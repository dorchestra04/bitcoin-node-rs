use hickory_resolver::{TokioAsyncResolver, config::{ResolverConfig, ResolverOpts}};
use std::{ io::Read, println, vec};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use std::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use serde::{ Serialize as SerdeSerialize, Deserialize as SerdeDeserialize};
use sha2::{Sha256, Digest};

pub struct Serialized {}

pub trait Serialize {
    fn serialize(&mut self) -> Vec<u8>;
}

pub trait Deserialize<T> {
    fn deserialize(payload: &mut &[u8]) -> Option<T>;
}

#[derive(Debug, Clone, Copy, PartialEq, SerdeSerialize, SerdeDeserialize, Default)]
enum Source {
    #[default]
    Seed,
    Requested,
    Announced,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
struct Peer {
    address: SocketAddr,
    attemts: u8,
    failed: u8,
    last_seen: u64,
    #[serde(default)]
    source: Source,
}

impl Peer {
    pub fn new(socket: SocketAddr) -> Peer {
        Peer {
            last_seen: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            attemts: 0,
            failed: 0,
            address: socket,
            source: Source::Seed,
        }
    }
    fn responded(&mut self) {
        self.attemts += 1;
        self.last_seen = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    }
    fn failed(&mut self) {
        self.attemts += 1;
        self.failed += 1;
        self.last_seen = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    }
}

#[derive(Debug, SerdeDeserialize, SerdeSerialize)]
struct Peers {
    pub peers: Vec<Peer>,
    pub len: usize
}

const PEERS_FILE: &str = "peers.json";
const ANCHORS_FILE: &str = "anchors.json";

impl Peers {
    pub fn new() -> Peers {
        let mut peers = match File::open(PEERS_FILE) {
            Ok(file) => {
                file
            },
            Err(_e) => {
                File::create(PEERS_FILE).expect("Error creating file")
            }
        };

        let mut buffer = String::new();
        if peers.read_to_string(&mut buffer).is_err() {
            println!("Creating a new file");
        }

        if !buffer.is_empty() {
            return match serde_json::from_str(&buffer) {
                Ok(peers) => peers,
                Err(e) => {
                    println!("Error parsing {}: {}", PEERS_FILE, e);
                    Peers { peers: vec![], len: 0 }
                }
            };
        }

        Peers {
            peers: vec![],
            len: 0
        }
    }

    pub fn load(&mut self) {
        let mut buffer = String::new();
        match File::open(PEERS_FILE) {
            Ok(mut file) => {
                if let Err(e) = file.read_to_string(&mut buffer) {
                    println!("Error reading file: {}", e);
                }
            }
            Err(e) => println!("Error opening file: {}", e),
        };

        if !buffer.is_empty() {
            match serde_json::from_str(&buffer) {
                Ok(peers) => *self = peers,
                Err(e) => println!("Error parsing {}: {}", PEERS_FILE, e),
            }
        }
    }

    pub fn save(&mut self) {
        self.len = self.peers.len();
        let json = serde_json::to_string(&self).unwrap();
        fs::write(PEERS_FILE, json).unwrap();
    }


    pub fn add_peer(&mut self, peer: Peer) {
        if let Some(known) = self.peers.iter_mut().find(|known| known.address == peer.address) {
            known.last_seen = peer.last_seen;
            return;
        }
        self.len += 1;
        self.peers.push(peer);
    }

    pub fn knows(&self, socket: &SocketAddr) -> bool {
        self.peers.iter().any(|known| known.address == *socket)
    }

    pub fn relay_addrs(&self) -> Vec<SocketAddr> {
        let limit = std::cmp::min(self.peers.len() * RELAY_PERCENT / 100, MAX_ADDR_ENTRIES);
        self.peers.iter()
            .filter(|peer| peer.attemts > 0)
            .take(limit)
            .map(|peer| peer.address)
            .collect()
    }
}

fn load_anchors() -> Vec<SocketAddr> {
    match File::open(ANCHORS_FILE) {
        Ok(mut file) => {
            let mut buffer = String::new();
            if file.read_to_string(&mut buffer).is_err() || buffer.is_empty() {
                return vec![];
            }
            serde_json::from_str(&buffer).unwrap_or_default()
        }
        Err(_e) => vec![],
    }
}

fn save_anchors(anchors: &Vec<SocketAddr>) {
    let json = serde_json::to_string(anchors).unwrap();
    fs::write(ANCHORS_FILE, json).unwrap();
}
// Network
const MAINNET: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

// Commands
const VERACK: [u8; 12] = [0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
const VERSION: [u8; 12] = [0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00];
const ADDOR: [u8; 12] = [0x61, 0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
const GETADDR: [u8; 12] = [0x67, 0x65, 0x74, 0x61, 0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00];
const PING: [u8; 12] = [0x70, 0x69, 0x6E, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
const PONG: [u8; 12] = [0x70, 0x6F, 0x6E, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

// Wire
const HEADER_SIZE: usize = 24;
const ADDR_ENTRY_SIZE: usize = 30;
const MAX_ADDR_ENTRIES: usize = 1000;
const MAX_PAYLOAD_SIZE: usize = MAX_ADDR_ENTRIES * ADDR_ENTRY_SIZE + 9;
const RELAY_PERCENT: usize = 23;
const NODE_NETWORK_LIMITED: u64 = 1024;

// Local node
const LISTEN_PORT: u16 = 8333;
const HANDSHAKE_TIMEOUT: u64 = 60;

struct HeaderMessage {
    magic: [u8; 4],
    command: [u8; 12],
    length: u32,
    checksum: [u8; 4]
}

impl HeaderMessage {
    pub fn compute_checksum(&mut self, payload: &[u8]) {
        let mut checksum: [u8; 4] = [0x00; 4];
        let hash1 = Sha256::digest(payload);
        let hash2 = Sha256::digest(hash1);
        
        checksum.copy_from_slice(&hash2[..4]);

        self.length = payload.len() as u32;
        self.checksum = checksum;
    }
}

impl Serialize for HeaderMessage {
    fn serialize(&mut self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.magic);
        buffer.extend_from_slice(&self.command);
        buffer.extend_from_slice(&self.length.to_le_bytes());
        buffer.extend_from_slice(&self.checksum);
        buffer
    }
}

impl Deserialize<HeaderMessage> for HeaderMessage {
    fn deserialize(payload: &mut &[u8]) -> Option<HeaderMessage> {
        let magic = read_bytes(payload, 4)?.try_into().ok()?;
        let command = read_bytes(payload, 12)?.try_into().ok()?;
        let length = read_u32(payload)?;
        let checksum = read_bytes(payload, 4)?.try_into().ok()?;

        Some(HeaderMessage {
            magic,
            command,
            length,
            checksum
        })
    }
}



struct VersionMessage {
    version: u32,
    services: u64,
    timestamp: u64,
    receiver_services: u64,
    receiver_address: [u8; 16],
    receiver_port: u16,
    sender_services: u64,
    sender_address: [u8; 16],
    sender_port: u16,
    nonce: u64,
    user_agent: String,
    start_height: u32,
    relay: bool
}

impl VersionMessage {
    pub fn new() -> VersionMessage {
        VersionMessage {
            version: 70016,
            services: NODE_NETWORK_LIMITED,
            timestamp: 0,
            receiver_services: 0,
            receiver_address: [0x00; 16],
            receiver_port: 0,
            sender_services: 0,
            sender_address: [0x00; 16],
            sender_port: 0,
            nonce: 0,
            user_agent: "JesusTech".to_string(),
            start_height: 0,
            relay: true
        }
    }
}

impl Serialize for VersionMessage {
    fn serialize(&mut self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.version.to_le_bytes());
        buffer.extend_from_slice(&self.services.to_le_bytes());
        buffer.extend_from_slice(&self.timestamp.to_le_bytes());
        buffer.extend_from_slice(&self.receiver_services.to_le_bytes());
        buffer.extend_from_slice(&self.receiver_address);
        buffer.extend_from_slice(&self.receiver_port.to_le_bytes());
        buffer.extend_from_slice(&self.sender_services.to_le_bytes());
        buffer.extend_from_slice(&self.sender_address);
        buffer.extend_from_slice(&self.sender_port.to_le_bytes());
        buffer.extend_from_slice(&self.nonce.to_le_bytes());
        buffer.extend_from_slice(&compact_size(self.user_agent.len() as u64));
        buffer.extend_from_slice(self.user_agent.as_bytes());
        buffer.extend_from_slice(&self.start_height.to_le_bytes());
        buffer.push(self.relay as u8);
        buffer
    }
}

pub fn decode_compact_size(bytes: &mut &[u8]) -> Option<usize> {
    let &first_byte = bytes.first()?;
    *bytes = &bytes[1..];

    match first_byte {
        0x00..=0xFC => Some(first_byte as usize),
        0xFD => {
            if bytes.len() < 2 {
                return None;
            }
            let value = u16::from_le_bytes(bytes[..2].try_into().ok()?);
            *bytes = &bytes[2..];
            Some(value as usize)
        }
        0xFE => {
            if bytes.len() < 4 {
                return None;
            }
            let value = u32::from_le_bytes(bytes[..4].try_into().ok()?);
            *bytes = &bytes[4..];
            Some(value as usize)
        }
        0xFF => {
            if bytes.len() < 8 {
                return None;
            }
            let value = u64::from_le_bytes(bytes[..8].try_into().ok()?);
            *bytes = &bytes[8..];
            Some(value as usize)
        }
    }
}

pub fn compact_size(size: u64) -> Vec<u8> {
    let mut buffer = Vec::new();

    if size < 0xfd {
        buffer.push(size as u8);
    } else if size <= 0xffff {
        buffer.push(0xfd);
        buffer.extend_from_slice(&(size as u16).to_le_bytes());
    } else if size <= 0xffffffff {
        buffer.push(0xfe);
        buffer.extend_from_slice(&(size as u32).to_le_bytes());
    } else {
        buffer.push(0xff);
        buffer.extend_from_slice(&size.to_le_bytes());
    }

    buffer
}

fn read_bytes<'a>(buf: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    if buf.len() < len {
        return None;
    }
    let (head, tail) = buf.split_at(len);
    *buf = tail;
    Some(head)
}

fn read_u16(buf: &mut &[u8]) -> Option<u16> {
    let bytes = read_bytes(buf, 2)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u16_be(buf: &mut &[u8]) -> Option<u16> {
    let bytes = read_bytes(buf, 2)?;
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

fn read_u32(buf: &mut &[u8]) -> Option<u32> {
    let bytes = read_bytes(buf, 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u64(buf: &mut &[u8]) -> Option<u64> {
    let bytes = read_bytes(buf, 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn read_bool(buf: &mut &[u8]) -> Option<bool> {
    let bytes = read_bytes(buf, 1)?;
    Some(bytes[0] != 0)
}

struct Addr {
    timestamp: u32,
    services: u64,
    address: [u8; 16],
    port: u16,
}

impl Addr {
    pub fn new(socket: SocketAddr, services: u64) -> Addr {
        let mut address = [0x00; 16];
        match socket.ip() {
            IpAddr::V4(ip) => {
                address[10] = 0xff;
                address[11] = 0xff;
                address[12..].copy_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => address.copy_from_slice(&ip.octets()),
        }

        Addr {
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as u32,
            services,
            address,
            port: socket.port(),
        }
    }

    pub fn socket(&self) -> Option<SocketAddr> {
        if self.port == 0 {
            return None;
        }

        let ip = Ipv6Addr::from(self.address);
        if let Some(ipv4) = ip.to_ipv4_mapped() {
            if ipv4.is_unspecified() {
                return None;
            }
            return Some(SocketAddr::new(IpAddr::V4(ipv4), self.port));
        }

        if ip.is_unspecified() {
            return None;
        }

        Some(SocketAddr::new(IpAddr::V6(ip), self.port))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.timestamp.to_le_bytes());
        buffer.extend_from_slice(&self.services.to_le_bytes());
        buffer.extend_from_slice(&self.address);
        buffer.extend_from_slice(&self.port.to_be_bytes());
        buffer
    }
}

fn serialize_addrs(addrs: &Vec<Addr>) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&compact_size(addrs.len() as u64));
    for addr in addrs {
        buffer.extend_from_slice(&addr.serialize());
    }
    buffer
}

fn deserialize_addrs(payload: &mut &[u8]) -> Option<Vec<Addr>> {
    let total = decode_compact_size(payload)?;

    if total > MAX_ADDR_ENTRIES || payload.len() < total * ADDR_ENTRY_SIZE {
        return None;
    }

    let mut addrs = Vec::new();
    for _ in 0..total {
        let timestamp = read_u32(payload)?;
        let services = read_u64(payload)?;
        let address = read_bytes(payload, 16)?.try_into().ok()?;
        let port = read_u16_be(payload)?;
        addrs.push(Addr { timestamp, services, address, port });
    }

    Some(addrs)
}

async fn send_message(stream: &mut tokio::net::TcpStream, command: [u8; 12], payload: &[u8]) -> std::io::Result<()> {
    let mut header = HeaderMessage {
        magic: MAINNET,
        command,
        length: payload.len() as u32,
        checksum: [0x00; 4]
    };
    header.compute_checksum(payload);

    stream.write_all(&header.serialize()).await?;
    stream.write_all(payload).await
}

async fn read_message(stream: &mut tokio::net::TcpStream) -> Option<(HeaderMessage, Vec<u8>)> {
    let mut buffer = [0; HEADER_SIZE];
    stream.read_exact(&mut buffer).await.ok()?;

    let header = HeaderMessage::deserialize(&mut &buffer[..])?;

    if header.length as usize > MAX_PAYLOAD_SIZE {
        return None;
    }

    let mut payload = vec![0; header.length as usize];
    if header.length > 0 {
        stream.read_exact(&mut payload).await.ok()?;
    }

    Some((header, payload))
}

impl Deserialize<VersionMessage> for VersionMessage {
    fn deserialize(payload: &mut &[u8]) -> Option<Self> {
        let version = read_u32(payload)?;
        let services = read_u64(payload)?;
        let timestamp = read_u64(payload)?;
        let receiver_services = read_u64(payload)?;
        let receiver_address = read_bytes(payload, 16)?.try_into().ok()?;
        let receiver_port = read_u16(payload)?;
        let sender_services = read_u64(payload)?;
        let sender_address = read_bytes(payload, 16)?.try_into().ok()?;
        let sender_port = read_u16(payload)?;
        let nonce = read_u64(payload)?;
        let ua_len = decode_compact_size(payload)?;
        let ua_bytes = read_bytes(payload, ua_len)?;
        let user_agent = String::from_utf8_lossy(ua_bytes).into_owned();
        let start_height = read_u32(payload)?;
        let relay = read_bool(payload).unwrap_or(true);

        Some(VersionMessage {
            version,
            services,
            timestamp,
            receiver_services,
            receiver_address,
            receiver_port,
            sender_services,
            sender_address,
            sender_port,
            nonce,
            user_agent,
            start_height,
            relay,
        })
    }
}

async fn send_version(stream: &mut tokio::net::TcpStream) -> std::io::Result<()> {
    let mut version = VersionMessage::new();
    let payload = version.serialize();
    send_message(stream, VERSION, &payload).await
}

fn our_addr(version: &VersionMessage, local: Option<SocketAddr>) -> Option<SocketAddr> {
    if version.receiver_port == LISTEN_PORT {
        let seen = Addr {
            timestamp: 0,
            services: NODE_NETWORK_LIMITED,
            address: version.receiver_address,
            port: version.receiver_port,
        };

        if let Some(socket) = seen.socket() {
            return Some(socket);
        }
    }

    local.filter(|socket| socket.port() == LISTEN_PORT && !socket.ip().is_unspecified())
}

async fn peer_connection(mut stream: tokio::net::TcpStream, remote: SocketAddr, store: Arc<Mutex<Peers>>, incoming: bool) {
    if incoming {
        println!("Incoming connection from {}", remote);
    } else if let Err(e) = send_version(&mut stream).await {
        println!("Error sending version message to {}: {}", remote, e);
        return;
    }

    let mut ours: Option<SocketAddr> = None;

    loop {
        let (header, payload) = match tokio::time::timeout(Duration::from_secs(HANDSHAKE_TIMEOUT), read_message(&mut stream)).await {
            Ok(Some(message)) => message,
            Ok(None) => {
                println!("Connection with {} closed", remote);
                break;
            }
            Err(_) => {
                println!("Handshake with {} timed out", remote);
                break;
            }
        };

        match header.command {
            VERSION => {
                let version = match VersionMessage::deserialize(&mut &payload[..]) {
                    Some(version) => version,
                    None => {
                        println!("Invalid version message from {}", remote);
                        break;
                    }
                };

                println!("User agent: {}", version.user_agent);
                println!("Start height: {}", version.start_height);

                ours = our_addr(&version, stream.local_addr().ok());

                if incoming && let Err(e) = send_version(&mut stream).await {
                    println!("Error sending version message to {}: {}", remote, e);
                    break;
                }

                if let Err(e) = send_message(&mut stream, VERACK, &[]).await {
                    println!("Error sending verack message to {}: {}", remote, e);
                    break;
                }

                println!("Sent verack message to {}", remote);
            }
            VERACK => {
                println!("Received verack message from {}", remote);
                break;
            }
            _ => println!("Received unknown message from {} during handshake", remote),
        }
    }

    if incoming {
        let mut peer = Peer::new(remote);
        peer.responded();
        peer.source = Source::Announced;
        store.lock().unwrap().add_peer(peer);
    }

    if let Err(e) = send_message(&mut stream, GETADDR, &[]).await {
        println!("Error sending getaddr message to {}: {}", remote, e);
    }

    if let Some(socket) = ours {
        let addrs = vec![Addr::new(socket, NODE_NETWORK_LIMITED)];
        if let Err(e) = send_message(&mut stream, ADDOR, &serialize_addrs(&addrs)).await {
            println!("Error sending addr message to {}: {}", remote, e);
        } else {
            println!("Announced {} to {}", socket, remote);
        }
    }

    let mut answered = false;
    let mut expecting_addrs = true;

    loop {
        let (header, payload) = match read_message(&mut stream).await {
            Some(message) => message,
            None => {
                println!("Connection with {} closed", remote);
                break;
            }
        };

        match header.command {
            GETADDR => {
                if !incoming {
                    println!("Ignored getaddr message from {}", remote);
                    continue;
                }

                if answered {
                    continue;
                }
                answered = true;

                let addrs: Vec<Addr> = store.lock().unwrap().relay_addrs()
                    .iter()
                    .map(|socket| Addr::new(*socket, NODE_NETWORK_LIMITED))
                    .collect();

                if let Err(e) = send_message(&mut stream, ADDOR, &serialize_addrs(&addrs)).await {
                    println!("Error sending addr message to {}: {}", remote, e);
                } else {
                    println!("Sent {} addresses to {}", addrs.len(), remote);
                }
            }
            ADDOR => {
                let addrs = match deserialize_addrs(&mut &payload[..]) {
                    Some(addrs) => addrs,
                    None => {
                        println!("Invalid addr message from {}", remote);
                        break;
                    }
                };

                let mut learned = 0;
                let mut peers = store.lock().unwrap();
                for addr in addrs {
                    if let Some(socket) = addr.socket() {
                        if Some(socket) == ours || peers.knows(&socket) {
                            continue;
                        }

                        let mut peer = Peer::new(socket);
                        if expecting_addrs {
                            expecting_addrs = false;
                            peer.source = Source::Requested;
                        } else {
                            peer.source = Source::Announced;
                        }

                        peers.add_peer(peer);
                        learned += 1;
                    }
                }

                println!("Learned {} addresses from {}", learned, remote);
            },
            PING => {
                println!("Received ping from {}, responding with pong", remote);
                if let Err(e) = send_message(&mut stream, PONG, &payload).await {
    			    println!("Error sending pong message to {}: {}", remote, e);
    			break;
                }
            }
            _ => println!("Received unknown message from {} ({} bytes)", String::from_utf8_lossy(&header.command), payload.len()),
        }
    }

    let mut peers = store.lock().unwrap();
    peers.save();
}

async fn listen_connections(store: Arc<Mutex<Peers>>) {
    let bind = SocketAddr::from(([0, 0, 0, 0], LISTEN_PORT));

    let listener = match TcpListener::bind(bind).await {
        Ok(listener) => listener,
        Err(e) => {
            println!("Error listening on {}: {}", bind, e);
            return;
        }
    };

    println!("Listening for incoming connections on {}", bind);

    loop {
        match listener.accept().await {
            Ok((stream, remote)) => {
                let store = store.clone();
                tokio::spawn(async move {
                    peer_connection(stream, remote, store, true).await;
                });
            }
            Err(e) => println!("Error accepting connection: {}", e),
        }
    }
}

#[tokio::main]
async fn main() {
    let dns_seeds: [&str; 8] = [
        "seed.bitcoin.sipa.be",
        "dnsseed.bluematt.me",
        "dnsseed.emzy.de",
        "seed.btc.petertodd.net",
        "seed.bitcoin.sprovoost.nl",
        "seed.bitcoin.jonasschnelli.ch",
        "seed.bitcoin.wiz.biz",
        "seed.mainnet.achownodes.xyz",
    ];

    let mut store: Peers = Peers::new();
    store.load();

    let mut anchors: Vec<SocketAddr> = load_anchors();

    if anchors.is_empty() {
        let mut ips_v4: Vec<Ipv4Addr> = vec![];
        let mut ips_v6: Vec<Ipv6Addr> = vec![];

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::cloudflare(),
            ResolverOpts::default(),
        );

        println!("Fetching DNS seeds...");

        for seed in dns_seeds {
            if let Ok(lookup) = resolver.ipv4_lookup(seed).await {
                for ip in lookup {
                    ips_v4.push(ip.0);
                }
            }

            if let Ok(lookup) = resolver.ipv6_lookup(seed).await {
                for ip in lookup {
                    ips_v6.push(ip.0);
                }
            }
        }

        println!("\n--- Result ---");
        println!("Total IPv4 found: {}", ips_v4.len());
        println!("Total IPv6 found: {}", ips_v6.len());

        println!("\n--- IPv4 ---");
        for ip in &ips_v4 {
            println!("{}", ip);
        }

        println!("\n--- IPv6 ---");
        for ip in &ips_v6 {
            println!("{}", ip);
        }
        for ip in ips_v4 {
            let socket_address = SocketAddr::new(IpAddr::V4(ip), 8333);
        
            let mut new_peer = Peer::new(socket_address);
            let limit_time = Duration::from_secs(3);

            match TcpStream::connect_timeout(&socket_address, limit_time) {
                Ok(_stream) => {
                    println!("Connected to {}", socket_address);
                    new_peer.responded();
                    store.add_peer(new_peer);
                    anchors.push(socket_address);
                }
                Err(_e) => {
                    println!("Failed to connect to {}", socket_address);
                    new_peer.failed();
                    store.add_peer(new_peer);
                }
            }
        }

        for ip in ips_v6 {
            let socket_address = SocketAddr::new(IpAddr::V6(ip), 8333);
        
            let mut new_peer = Peer::new(socket_address);
            let limit_time = Duration::from_secs(3);
            
            match TcpStream::connect_timeout(&socket_address, limit_time) {
                Ok(_stream) => {
                    println!("Connected to {}", socket_address);
                    new_peer.responded();
                    store.add_peer(new_peer);
                    anchors.push(socket_address);
                }
                Err(_e) => {
                    println!("Failed to connect to {}", socket_address);
                    new_peer.failed();
                    store.add_peer(new_peer);
                }
            }
        }
    } else {
        println!("Retrieving anchors...");
        let mut responding: Vec<SocketAddr> = vec![];
        for anchor in anchors.iter() {
            let socket_address = *anchor;
            let limit_time = Duration::from_secs(3);

            match TcpStream::connect_timeout(&socket_address, limit_time) {
                Ok(_stream) => {
                    println!("Connected to {}", socket_address);
                    responding.push(socket_address);
                }
                Err(_e) => {
                    println!("Failed to connect to {}", socket_address);
                }
            }
        }
        anchors = responding;
    };

    store.save();
    save_anchors(&anchors);
    println!("\n--------------------------------------------------------------------------");
    println!("--- Result ---");
    println!("--------------------------------------------------------------------------\n");
    println!("Total peers: {} {}\n", store.len, store.peers.len());
    println!("\n--------------------------- Peers statistics ---------------------------");

    for peer in &store.peers {
        println!("peer statistic: {}, Attemts: {}, Failed: {}, Seen: {}, Source: {:?}", peer.address, peer.attemts, peer.failed, peer.last_seen, peer.source);
    }
    println!("--------------------------------------------------------------------------");

    let store = Arc::new(Mutex::new(store));

    tokio::spawn(listen_connections(store.clone()));

    let peer_address = {
        let peers = store.lock().unwrap();
        peers.peers.get(1).map(|peer| peer.address)
    };

    match peer_address {
        Some(address) => {
            let store = store.clone();
            tokio::spawn(async move {
                match tokio::net::TcpStream::connect(address).await {
                    Ok(stream) => {
                        println!("Connected to {}", address);
                        peer_connection(stream, address, store, false).await;
                    }
                    Err(e) => println!("Error connecting to {}: {}", address, e),
                }
            });
        }
        None => println!("No peers available to connect"),
    }

    std::future::pending::<()>().await;
}

use hickory_resolver::{TokioAsyncResolver, config::{ResolverConfig, ResolverOpts}};
use std::{ io::{Read, Write}, println, vec};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, SystemTime};
use std::fs::{self, File};
use serde::{ Serialize as SerdeSerialize, Deserialize as SerdeDeserialize};
use sha2::{Sha256, Digest};

pub struct Serialized {}

pub trait Serialize {
    fn serialize(&mut self) -> Vec<u8>;
}

pub trait Deserialize<T> {
    fn deserialize(payload: &mut &[u8]) -> T;
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
struct Peer {
    address: SocketAddr,
    attemts: u8,
    failed: u8,
    last_seen: u64,
}

impl Peer {
    pub fn new(socket: SocketAddr) -> Peer {
        Peer {
            last_seen: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            attemts: 0,
            failed: 0,
            address: socket,
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
            return serde_json::from_str(&buffer).unwrap();
        }

        Peers {
            peers: vec![],
            len: 0
        }
    }

    pub fn load(&mut self) {
        let mut buffer = String::new();
        if let Err(e) = File::open(PEERS_FILE).unwrap().read_to_string(&mut buffer) {
            println!("Error reading file: {}", e);
        };

        if !buffer.is_empty() {
            *self = serde_json::from_str(&buffer).unwrap();
        }
    }

    pub fn save(&mut self) {
        self.len = self.peers.len();
        let json = serde_json::to_string(&self).unwrap();
        fs::write(PEERS_FILE, json).unwrap();
    }


    pub fn add_peer(&mut self, peer: Peer) {
        self.len += 1;
        self.peers.push(peer);
    }
    
    pub fn clean_peers(&mut self) {
        self.peers.retain(|p| p.failed < 3);
        self.len = self.peers.len()
    }
}
// Network
const MAINNET: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

// Commands
const VERACK: [u8; 12] = [0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
const VERSION: [u8; 12] = [0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00];

struct HeaderMessage {
    magic: [u8; 4],
    command: [u8; 12],
    length: u32,
    checksum: [u8; 4]
}

impl HeaderMessage {
    pub fn new(magic: [u8; 4], command: [u8; 12]) -> HeaderMessage {
        HeaderMessage {
            magic,
            command,
            length: 0,
            checksum: [0x00; 4]
        }
    }

    pub fn version() -> HeaderMessage {
        HeaderMessage {
            magic: MAINNET,
            command: VERSION,
            length: 0,
            checksum: [0x00; 4]
        }
    }

    pub fn verack() -> HeaderMessage {
        HeaderMessage {
            magic: MAINNET,
            command: VERACK,
            length: 0,
            checksum: [0x00; 4]
        }
    }

    pub fn compute_checksum(&mut self, payload: &Vec<u8>) {
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
    fn deserialize(payload: &mut &[u8]) -> HeaderMessage {
        let magic = read_bytes(payload, 4).unwrap().try_into().ok().unwrap();
        let command = read_bytes(payload, 12).unwrap().try_into().ok().unwrap();
        let length = read_u32(payload).unwrap();
        let checksum = read_bytes(payload, 4).unwrap().try_into().ok().unwrap();

        HeaderMessage {
            magic,
            command,
            length,
            checksum
        }
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
            services: 0,
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
    let &first_byte = bytes.get(0)?;
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

impl Deserialize<VersionMessage> for VersionMessage {
    fn deserialize(payload: &mut &[u8]) -> Self {
        let version = read_u32(payload).unwrap();
        let services = read_u64(payload).unwrap();
        let timestamp = read_u64(payload).unwrap();
        let receiver_services = read_u64(payload).unwrap();
        let receiver_address = read_bytes(payload, 16).unwrap().try_into().ok().unwrap();
        let receiver_port = read_u16(payload).unwrap();
        let sender_services = read_u64(payload).unwrap();
        let sender_address = read_bytes(payload, 16).unwrap().try_into().ok().unwrap();
        let sender_port = read_u16(payload).unwrap();
        let nonce = read_u64(payload).unwrap();
        let ua_len = decode_compact_size(payload).unwrap();
        let ua_bytes = read_bytes(payload, ua_len).unwrap();
        let user_agent = String::from_utf8_lossy(ua_bytes).into_owned();
        let start_height = read_u32(payload).unwrap();
        let relay = read_bool(payload).unwrap_or(true);

        VersionMessage {
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

    if store.len == 0 {
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
                }
                Err(_e) => {
                    println!("Failed to connect to {}", socket_address);
                    new_peer.failed();
                    store.add_peer(new_peer);
                }
            }
        }
    } else {
            println!("Retrieving peers...");
            for peer in &mut store.peers{
            let socket_address = peer.address;
            let limit_time = Duration::from_secs(3);
            
            match TcpStream::connect_timeout(&socket_address, limit_time) {
                Ok(_stream) => {
                    peer.responded();
                }
                Err(_e) => {
                    peer.failed();
                }
            }
        }
        store.clean_peers();
    };

    store.save();
    println!("\n--------------------------------------------------------------------------");
    println!("--- Result ---");
    println!("--------------------------------------------------------------------------\n");
    println!("Total peers: {} {}\n", store.len, store.peers.len());
    println!("\n--------------------------- Peers statistics ---------------------------");

    for peer in &store.peers {
        println!("peer statistic: {}, Attemts: {}, Failed: {}, Seen: {}", peer.address, peer.attemts, peer.failed, peer.last_seen);
    }
    println!("--------------------------------------------------------------------------");

    let mut header_version_message = HeaderMessage::version();
    let payload_version = VersionMessage::new().serialize();
    header_version_message.compute_checksum(&payload_version);

    let mut header_verack_message = HeaderMessage::verack();
    header_verack_message.compute_checksum(&"".as_bytes().to_vec());
}

use hickory_resolver::{TokioAsyncResolver, config::{ResolverConfig, ResolverOpts}};
use std::{io::Read, println};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, SystemTime};
use std::fs::{self, File};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Deserialize, Serialize)]
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
    println!("--------------------------------------------------------------------------")
}

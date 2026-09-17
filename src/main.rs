use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::println;

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
    for ip in ips_v4 {
        println!("{}", ip);
    }

    println!("\n--- IPv6 ---");
    for ip in ips_v6 {
        println!("{}", ip);
    }
}

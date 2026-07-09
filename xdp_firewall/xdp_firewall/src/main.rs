use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::time::{sleep, Duration};

// struct IpKey for map
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct IpKey {
    pub ip_type: u8,    // 4 for IPv4, 6 for IPv6
    pub addr: [u8; 16], // for IPv4 address we use the first 4 bytes from 16)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // if we use cargo-aya for build, loaded file is located in directory
    // target/bpfel-unknown-none/release/
    let mut bpf = Bpf::load_file("target/bpfel-unknown-none/release/xdp_firewall")?;
    
    // extract and load eBPF program
    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    
    // attach program to the interface "eth0" or "lo"
    program.attach("eth0", XdpFlags::default())?;
    println!("eBPF/XDP started. Suppored IPv4/IPv6 and CIDR ranges");

    let mut blocked_map: LpmTrie<_, IpKey, u8> = LpmTrie::try_from(bpf.map_mut("BLOCKED_IPS").unwrap())?;
    let file_path = "blocked_ips.txt";

    loop {
        if let Ok(mut file) = File::open(file_path).await {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).await.is_ok() {
                let mut current_networks = HashSet::new();

                for line in contents.lines() {
                    let entry = line.trim();
                    if entry.is_empty() || entry.starts_with('#') {
                        continue;
                    }

                    // Try to parse as a CIDR subnet (IPv4 or IPv6)
                    if let Ok(net) = IpNet::from_str(entry) {
                        current_networks.insert(net);
                    }

                    // If that fails, attempt to parse as a single IP address
                    else if let Ok(ip) = IpAddr::from_str(entry) {
                        match ip {
                            IpAddr::V4(v4) => current_networks.insert(IpNet::V4(Ipv4Net::new(v4, 32).unwrap())),
                            IpAddr::V6(v6) => current_networks.insert(IpNet::V6(Ipv6Net::new(v6, 128).unwrap())),
                        };
                    }
                }

                // write new rules to eBPF Map
                for net in current_networks {
                    match net {
                        IpNet::V4(v4net) => { // for IPv4
                            let mut addr = [0u8; 16];
                            addr[0..4].copy_from_slice(&v4net.network().octets());
                            
                            // important:
                            // prefix for Key::new in Aya is equal prefix_len + 
                            // size of extra fields in bits (ip_type = 8 bit).
                            let prefix_len = (v4net.prefix_len() + 8) as u32;
                            let key = Key::new(prefix_len, IpKey { ip_type: 4, addr });

                            let _ = blocked_map.insert(key, 1, 0);
                        }
                        IpNet::V6(v6net) => { // for IPv6
                            let key_data = IpKey {
                                ip_type: 6,
                                addr: v6net.network().octets(),
                            };
                            let prefix_len = (v6net.prefix_len() + 8) as u32;
                            let key = Key::new(prefix_len, key_data);

                            let _ = blocked_map.insert(key, 1, 0);
                        }
                    }
                }

                println!("eBPF map content updated");
            }
        }

        sleep(Duration::from_secs(5)).await;
    }
}


use aya::maps::HashMap;
use aya::programs::Xdp;
use aya::{Bpf, BpfLoader};
use futures::stream::StreamExt;
use network_interface::{NetworkInterface, NetworkInterfaceProvider};
use rtnetlink::constants::{RTMGRP_NEIGH, RTNLGRP_NEIGH};
use rtnetlink::new_connection;
use rtnetlink::sys::{SocketAddr, ImrIfindex};
use std::convert::TryInto;
use std::net::IpAddr;
use xdp_router_common::{RouteKey, RouteValue};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    env_logger::init();

    // load eBPF program
    let mut bpf = BpfLoader::new().load_file(
        "target/bpfel-unknown-none/release/xdp-router")?;
    let program: &mut Xdp = bpf.program_mut("xdp_router").unwrap().try_into()?;
    program.load()?;

    // attach to interface (eth0)
    program.attach("eth0", aya::programs::XdpFlags::default())?;

    let mut routes_map: HashMap<_, RouteKey, RouteValue> =
        HashMap::try_from(bpf.map_mut("ROUTES").unwrap())?;

    // get interfaces data
    let interfaces = NetworkInterface::show()?;
    for iface in interfaces {
        let if_index = iface.index;
        let src_mac = match iface.mac_addr {
            Some(mac_str) => parse_mac(&mac_str),
            None => continue,
        };

        for addr in iface.addr {
            let mut key = RouteKey {
                ip_type: 0,
                ip_v4: [0; 4],
                ip_v6: [0; 16],
                vlan_id: 0,
            };

            match addr.ip() {
                IpAddr::V4(v4) => {
                    key.ip_type = 4;
                    key.ip_v4 = v4.octets();
                }
                IpAddr::V6(v6) => {
                    key.ip_type = 6;
                    key.ip_v6 = v6.octets();
                }
            };

            let value = RouteValue {
                src_mac,
                // default broadcast; will be updated via ARP
                dst_mac: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],

                if_index,
                vlan_id: 0,
            };

            routes_map.insert(key, value, 0)?;
        }
    }

    // dynamic updating of ARP/Neighbor tables via Netlink
    tokio::spawn(async move {
        if let Err(e) = monitor_arp_updates(routes_map).await {
            log::error!("Netlink monitor failed: {:?}", e);
        }
    });

    // awaiting signal (Ctrl+C to stop !)
    tokio::signal::ctrl_c().await?;
    Ok(())
}

// monitoring changes ARP/NDP tables in Linux
async fn monitor_arp_updates(
    mut routes_map: HashMap<&mut aya::maps::MapData, RouteKey, RouteValue>) ->
        Result<(), Box<dyn std::error::Error>> {
    let (connection, mut handle, mut queue) = new_connection()?;
    
    // subscribe to the Neighbors group(ARP in IPv4,Neighbor Discovery in IPv6)
    let mut mut_connection = connection;
    let socket = mut_connection.socket_mut();
    let addr = SocketAddr::new(0, RTNLGRP_NEIGH | RTMGRP_NEIGH);
    socket.bind(&addr)?;

    tokio::spawn(queue);

    let mut stream = handle.neighbors().get().execute();

    // reading Netlink events stream regarding neighbor states
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(neigh_msg) => {
                let mut destination_ip: Option<IpAddr> = None;

                // neighbor's MAC address
                let mut ll_addr: Option<Vec<u8>> = ref_ll_addr(&neigh_msg);

                // parsing Netlink messages
                for nla in neigh_msg.nlas.iter() {
                    match nla {
                        rtnetlink::packet::neighbour::NeighbourAttribute::Destination(ip_bytes) => {
                            if ip_bytes.len() == 4 {
                                destination_ip = Some(IpAddr::V4(std::net::Ipv4Addr::new(
                                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3])));
                            } else if ip_bytes.len() == 16 {
                                let bytes: [u8; 16] = ip_bytes.as_slice().try_into().unwrap();
                                destination_ip = Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)));
                            }
                        }
                        rtnetlink::packet::neighbour::NeighbourAttribute::LinkLayerAddress(mac) => {
                            ll_addr = Some(mac.clone());
                        }
                        _ => {}
                    }
                }

                if let (Some(ip), Some(mac)) = (destination_ip, ll_addr) {
                    if mac.len() == 6 {
                        let mut key = RouteKey { ip_type: 0, ip_v4: [0; 4],
                            ip_v6: [0; 16], vlan_id: 0 };
                        match ip {
                            IpAddr::V4(v4) => { key.ip_type = 4;
                                key.ip_v4 = v4.octets(); }
                            IpAddr::V6(v6) => { key.ip_type = 6;
                                key.ip_v6 = v6.octets(); }
                        }

                        // if route was found ,update 'Target DST MAC'
                        if let Ok(mut current_route) = routes_map.get(&key, 0) {
                            current_route.dst_mac.copy_from_slice(&mac);
                            routes_map.insert(key, current_route, 0).unwrap();
                            log::info!("Updated ARP mapping: {} => {:02x?}",
                                ip, mac);
                        }
                    }
                }
            }
            Err(e) => log::error!("Netlink stream error: {}", e),
        }
    }
    Ok(())
}

fn parse_mac(mac_str: &str) -> [u8; 6] {
    let mut mac = [0u8; 6];
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() == 6 {
        for i in 0..6 {
            mac[i] = u8::from_str_radix(parts[i], 16).unwrap_or(0);
        }
    }
    mac
}

fn ref_ll_addr(msg: &rtnetlink::packet::NeighbourMessage) -> Option<Vec<u8>> {
    for nla in &msg.nlas {
        if let rtnetlink::packet::neighbour::NeighbourAttribute::LinkLayerAddress(mac) =
            nla {
            return Some(mac.clone());
        }
    }
    None
}


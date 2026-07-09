#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{ethhdr, iphdr, ipv6hdr, xdp_action},
    macros::{map, xdp},
    maps::LpmTrie,
    programs::XdpContext,
};

// unified fixed-size LPM Trie key structure for IPv4 and IPv6
#[repr(C, packed)]
pub struct IpKey {
    // the first field in the LPM Trie key must be u32 prefixlen.
    pub prefixlen: u32,
    pub ip_type: u8,    // type of packet: 4 for IPv4, 6 for IPv6
    pub addr: [u8; 16], // 16 bytes (IPv4 uses the first 4 bytes)
}

// LPM Trie MAP containing IP addresses and CIDR ranges whose packets
// should be blocked
#[map(name = "BLOCKED_IPS")]
static mut BLOCKED_IPS: LpmTrie<IpKey, u8> = LpmTrie::with_max_entries(4096, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    if start + core::mem::size_of::<ethhdr>() > end {
        return Err(());
    }

    let eth = start as *const ethhdr;
    let proto = unsafe { (*eth).h_proto };

    // protocol constants in network byte order (Big Endian)
    const ETH_P_IP: u16 = 0x0800;
    const ETH_P_IPV6: u16 = 0x86DD;

    if proto == u16::from_be(ETH_P_IP) {
        // process IPv4
        let ip_start = start + core::mem::size_of::<ethhdr>();
        if ip_start + core::mem::size_of::<iphdr>() > end {
            return Err(());
        }
        let ip = ip_start as *const iphdr;

        // we filter only TCP(6) in this prototype
        if unsafe { (*ip).protocol } != 6 {
            return Ok(xdp_action::XDP_PASS);
        }

        let mut addr_bytes = [0u8; 16];
        let src_ip = unsafe { (*ip).saddr };
        addr_bytes[0..4].copy_from_slice(&src_ip.to_ne_bytes());

        // prefixlen for IPv4: 
        // 32 bit (IPv4 mask) + 8 bit (len of ip_type) = 40 bit
        let key = IpKey {
            prefixlen: 40, 
            ip_type: 4,
            addr: addr_bytes,
        };

        if unsafe { BLOCKED_IPS.get(&key).is_some() } {
            return Ok(xdp_action::XDP_DROP);
        }

    } else if proto == u16::from_be(ETH_P_IPV6) {
        // process IPv6
        let ip6_start = start + core::mem::size_of::<ethhdr>();
        if ip6_start + core::mem::size_of::<ipv6hdr>() > end {
            return Err(());
        }
        let ip6 = ip6_start as *const ipv6hdr;

        // we filter here only TCP packets (6)
        if unsafe { (*ip6).nexthdr } != 6 {
            return Ok(xdp_action::XDP_PASS);
        }

        let src_ip6 = unsafe { (*ip6).saddr.in6_u.u6_addr8 };

        // prefixlen for IPv6: 128 bit(IPv6 mask) + 8 bit(len of ip_type) = 136
        let key = IpKey {
            prefixlen: 136,
            ip_type: 6,
            addr: src_ip6,
        };

        if unsafe { BLOCKED_IPS.get(&key).is_some() } {
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // pass packet to network stack
    Ok(xdp_action::XDP_PASS)
}

//

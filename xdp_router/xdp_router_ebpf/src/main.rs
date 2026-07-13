#![no_std]
#![no_main]

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use xdp_router_common::{RouteKey, RouteValue};

#[map(name = "ROUTES")]
static mut ROUTES: HashMap<RouteKey, RouteValue> =
    HashMap::with_max_entries(1024, 0);

#[repr(C)]
struct EthHdr {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: u16,
}

#[repr(C)]
struct VlanHdr {
    tci: u16,
    ether_type: u16,
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

#[xdp]
pub fn xdp_router(ctx: XdpContext) -> u32 {
    match try_xdp_router(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_router(ctx: &XdpContext) -> Result<u32, ()> {
    let eth: *mut EthHdr = ptr_at(ctx, 0)?;
    let mut ether_type = u16::from_be(unsafe { (*eth).ether_type });
    let mut offset = mem::size_of::<EthHdr>();
    let mut vlan_id = 0u16;

    // parsing VLAN(802.1Q)
    if ether_type == ETH_P_8021Q {
        let vlan: *mut VlanHdr = ptr_at(ctx, offset)?;
        vlan_id = u16::from_be(unsafe { (*vlan).tci }) & 0x0FFF;
        ether_type = u16::from_be(unsafe { (*vlan).ether_type });
        offset += mem::size_of::<VlanHdr>();
    }

    let mut lookup_key = RouteKey {
        ip_type: 0,
        ip_v4: [0; 4],
        ip_v6: [0; 16],
        vlan_id,
    };

    // extraction of the IP address
    if ether_type == ETH_P_IP {
        // offset 16 - position of dest IP in the IPv4 header
        let dst_ip_ptr: *mut [u8; 4] = ptr_at(ctx, offset + 16)?;

        lookup_key.ip_type = 4;
        lookup_key.ip_v4 = unsafe { *dst_ip_ptr };
    } else if ether_type == ETH_P_IPV6 {
        // offset 24 - position of dest. IPv6
        let dst_ip_ptr: *mut [u8; 16] = ptr_at(ctx, offset + 24)?;

        lookup_key.ip_type = 6;
        lookup_key.ip_v6 = unsafe { *dst_ip_ptr };
    } else {

        return Ok(xdp_action::XDP_PASS);
    }

    // search route in the eBPF map
    if let Some(route) = unsafe { ROUTES.get(&lookup_key) } {

        // changing MAC address values
        unsafe {
            (*eth).dst_mac = route.dst_mac;
            (*eth).src_mac = route.src_mac;
        }

        info!(ctx, "redirecting packet to ifindex: {}", route.if_index);
        return Ok(ctx.redirect(route.if_index, 0));
    }

    Ok(xdp_action::XDP_PASS)
}


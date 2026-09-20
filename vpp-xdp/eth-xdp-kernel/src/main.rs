#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};

// The XSKMAP map, to which VPP will bind the descriptors of its AF_XDP sockets
#[map(name = "VPP_XSK_MAP")]
static VPP_XSK_MAP: XskMap = XskMap::with_max_entries(64, 0);

#[xdp]
pub fn vpp_xdp_redirect(ctx: XdpContext) -> u32 {
    let queue_id = ctx.queue_id();

    // Attempting to redirect the packet to an AF_XDP socket bound to the current queue
    match VPP_XSK_MAP.redirect(queue_id, 0) {
        xdp_action::XDP_REDIRECT => xdp_action::XDP_REDIRECT,
        _ => xdp_action::XDP_PASS, // if there is no socket, pass the packet to the standard kernel stack
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

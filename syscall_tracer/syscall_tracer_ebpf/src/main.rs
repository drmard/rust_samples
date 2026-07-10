#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};

// structure for pass syscall data to userspace
#[repr(C)]
pub struct Event {
    pub pid: u32,
    pub syscall_id: u32,
    pub comm: [u8; 16],
}

#[map]
static mut EVENTS: PerfEventArray<Event> =
    PerfEventArray::with_max_entries(1024, 0);

#[tracepoint(category = "raw_syscalls", name = "sys_enter")]
pub fn sys_enter_syscall(ctx: TracePointContext) -> u32 {
    let mut event = Event {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,

        // get syscall ID from tracepoint context
        syscall_id: unsafe { ctx.read_at(0).unwrap_or(0) },
        comm: [0u8; 16],
    };

    // get process name (comm)
    unsafe {
        let _ = bpf_get_current_comm(&mut event.comm);
        EVENTS.output(&ctx, &event, 0);
    }
    0
}

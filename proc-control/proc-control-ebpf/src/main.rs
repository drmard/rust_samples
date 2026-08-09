#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{tracepoint, map},
    maps::RingBuf,
    programs::TracePointContext,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str},
};

use proc_control_common::{ProcessEvent, EVENT_EXEC, EVENT_OPEN, EVENT_MEMFD};

// RingBuf for pass events data to userspace
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 256, 0); // 256 KB

inline fn init_event(ctx: &TracePointContext, event_type: u32)
    -> Option<*mut ProcessEvent> {
    let entry = EVENTS.reserve::<ProcessEvent>(0)?;
    let entry_ptr = entry.as_mut_ptr();

    unsafe {
        (*entry_ptr).event_type = event_type;

        let pid_tgid = bpf_get_current_pid_tgid();
        (*entry_ptr).pid = (pid_tgid >> 32) as u32;
        (*entry_ptr).tgid = pid_tgid as u32;

        // get name of the current process
        let _ = bpf_get_current_comm(&mut (*entry_ptr).comm);
    }

    Some(entry_ptr)
}

// intercept process launch
#[tracepoint(name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    if let Some(entry_ptr) = init_event(&ctx, EVENT_EXEC) {
        unsafe {
            let filename_ptr: *const u8 = ctx.read_at(8).unwrap_or(core::ptr::null());
            if !filename_ptr.is_null() {
                let _ = bpf_probe_read_user_str(filename_ptr, &mut (*entry_ptr).filename);
            }
            EVENTS.submit(entry_ptr as *mut _, 0);
        }
    }
    0
}

// intercept file opening
#[tracepoint(name = "sys_enter_openat")]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    if let Some(entry_ptr) = init_event(&ctx, EVENT_OPEN) {
        unsafe {
            let filename_ptr: *const u8 = ctx.read_at(16).unwrap_or(core::ptr::null());
            if !filename_ptr.is_null() {
                let _ = bpf_probe_read_user_str(filename_ptr, &mut (*entry_ptr).filename);
            }
            EVENTS.submit(entry_ptr as *mut _, 0);
        }
    }
    0
}

#[tracepoint(name = "sys_enter_memfd_create")]
pub fn sys_enter_memfd_create(ctx: TracePointContext) -> u32 {
    if let Some(entry_ptr) = init_event(&ctx, EVENT_MEMFD) {
        unsafe {
            let name_ptr: *const u8 = ctx.read_at(8).unwrap_or(core::ptr::null());
            if !name_ptr.is_null() {
                let _ = bpf_probe_read_user_str(name_ptr, &mut (*entry_ptr).filename);
            }
            EVENTS.submit(entry_ptr as *mut _, 0);
        }
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::hint::unreachable_unchecked()
}

#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{lsm, map},
    maps::HashMap,
    programs::LsmContext,
    helpers::bpf_d_path,
};
use aya_log_ebpf::info;
use common::{FileRuleKey, FileRuleValue};
use common::{MAX_PATH_LEN, AUTH_OPEN, AUTH_READ, AUTH_WRITE, AUTH_EXEC};

use aya_ebpf::bindings::{file, path};

#[map]
static RULES: HashMap<FileRuleKey, FileRuleValue> =
    HashMap::with_max_entries(1024, 0);

// Helper for checking a bitmask
inline_fn! {
    fn is_flag_set(mask: u32, flag: u32) -> bool {
        (mask & flag) == flag
    }
}

// intercept the `file_open` hook. If the file is in the config,
// check the mask. If the flag is missing -> -EACCES
#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    unsafe {
        // Extract pointer to `struct file` from the hook arguments
        let f: *mut file = ctx.arg(0);
        if f.is_null() {
            return 0;
        }

        let f_path: path = (*f).f_path;
        let mut path_buf = [0u8; MAX_PATH_LEN];

        // Obtaining the absolute file path using eBPF
        let len = bpf_d_path(&f_path,
            path_buf.as_mut_ptr() as *mut i8, MAX_PATH_LEN as u32);

        if len <= 0 {
            return 0; // if the path not defined, ignore
        }

        // create key for search in the Map
        let key = FileRuleKey { path: path_buf };

        // searching ..
        if let Some(rule) = RULES.get(&key) {

            // obtaining flags
            let f_flags = (*f).f_flags;
            let mut requested_mask = 0u32;

            // determine which operations the process is requesting
            if (f_flags & 0x0003) == 0x0000 { requested_mask |= AUTH_READ; }
            if (f_flags & 0x0003) == 0x0001 { requested_mask |= AUTH_WRITE; }
            if (f_flags & 0x0003) ==
                0x0002 { requested_mask |= AUTH_READ | AUTH_WRITE; } // O_RDWR
            if (f_flags & 0x0020) != 0 { requested_mask |= AUTH_EXEC; }

            // we should add always the OPEN flag,
            // since this represents the actual call to open
            requested_mask |= AUTH_OPEN;

            if (rule.allowed_mask & requested_mask) != requested_mask {
                // operation prohibited, return -13(-EACCES: Permission Denied)
                return -13;
            }
        }
    }

    0 // access granted
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}


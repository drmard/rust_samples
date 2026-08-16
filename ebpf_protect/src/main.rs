use std::ffi::{CStr, CString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;
use log::{info, warn, error};
use syslog::{Facility, Formatter3164};

const BPF_FS_PATH: &str = "/sys/fs/bpf";
const WHITELIST_MAP_PIN_PATH: &str = "/sys/fs/bpf/fw_whitelist_map";
const BPF_OBJ_NAME_LEN: usize = 16;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct WhitelistKey {
    prog_type: u32,
    name: [u8; BPF_OBJ_NAME_LEN],
}

/// removing pin files
fn remove_bpf_pins_by_id(prog_id: u32, writer: &mut Box<dyn syslog::LogWriter>) {
    for entry in walkdir::WalkDir::new(BPF_FS_PATH)
        .into_iter()
        .filter_map(|e| e.ok()) 
    {
        let path = entry.path();
        if path.is_file() {
            if path.to_string_lossy() == WHITELIST_MAP_PIN_PATH {
                continue;
            }

            let c_path = match CString::new(path.as_os_str().as_bytes()) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let fd = unsafe { libbpf_sys::bpf_obj_get(c_path.as_ptr()) };
            if fd < 0 {
                continue;
            }

            let mut info: libbpf_sys::bpf_prog_info = unsafe { std::mem::zeroed() };
            let mut info_len = std::mem::size_of::<libbpf_sys::bpf_prog_info>() as u32;

            let info_res = unsafe {
                libbpf_sys::bpf_obj_get_info_by_fd(
                    fd,
                    &mut info as *mut _ as *mut std::ffi::c_void,
                    &mut info_len,
                )
            };

            if info_res == 0 && info.id == prog_id {
                warn!("pinned file: {:?}", path);
                if let Err(e) = fs::remove_file(path) {
                    error!("cannot remove pinned file {:?}: {}", path, e);
                    let _ = writer.err(format!("EBPF_FW_ERROR: Failed to delete pin {:?}", path));
                } else {
                    info!("pinned file removed: {:?}", path);
                    let _ = writer.notice(format!("EBPF_FW_CLEANUP: Unpinned path {:?}", path));
                }
            }

            unsafe { libc::close(fd) };
        }
    }
}

//
fn setup_whitelist_map() -> libc::c_int {
    let c_path = CString::new(WHITELIST_MAP_PIN_PATH).unwrap();

    if Path::new(WHITELIST_MAP_PIN_PATH).exists() {
        let fd = unsafe { libbpf_sys::bpf_obj_get(c_path.as_ptr()) };
        if fd >= 0 {
            info!("whitelist MAP loaded from {}", WHITELIST_MAP_PIN_PATH);
            return fd;
        }
    }

    let mut attr: libbpf_sys::bpf_attr = unsafe { std::mem::zeroed() };
    attr.__bindgen_anon_1.map_type = libbpf_sys::bpf_map_type_BPF_MAP_TYPE_HASH as u32;
    attr.__bindgen_anon_1.key_size = std::mem::size_of::<WhitelistKey>() as u32;
    attr.__bindgen_anon_1.value_size = 4;
    attr.__bindgen_anon_1.max_entries = 1024;

    let map_fd = unsafe {
        libbpf_sys::syscall(
            libc::SYS_bpf,
            libbpf_sys::bpf_cmd_BPF_MAP_CREATE,
            &attr as *const _ as *mut std::ffi::c_void,
            std::mem::size_of::<libbpf_sys::bpf_attr>(),
        ) as libc::c_int
    };

    if map_fd < 0 {
        panic!("error: cannot create ebpf map ..");
    }

    let pin_res = unsafe { libbpf_sys::bpf_obj_pin(map_fd, c_path.as_ptr()) };
    if pin_res != 0 {
        panic!("error: failed to pin the map in {}", WHITELIST_MAP_PIN_PATH);
    }

    info!("created whitelist map: {}", WHITELIST_MAP_PIN_PATH);
    map_fd
}

/// check the eBPF program in the whitelist
fn is_prog_allowed(map_fd: libc::c_int, name: &str, prog_type: u32) -> bool {
    let mut key = WhitelistKey {
        prog_type,
        name: [0; BPF_OBJ_NAME_LEN],
    };

    let name_bytes = name.as_bytes();
    let len = name_bytes.len().min(BPF_OBJ_NAME_LEN - 1);
    key.name[..len].copy_from_slice(&name_bytes[..len]);

    let mut value: u32 = 0;

    let mut attr: libbpf_sys::bpf_attr = unsafe { std::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = map_fd as u32;
    attr.__bindgen_anon_2.key = &key as *const _ as u64;
    attr.__bindgen_anon_2.value = &mut value as *mut _ as u64;

    let res = unsafe {
        libbpf_sys::syscall(
            libc::SYS_bpf,
            libbpf_sys::bpf_cmd_BPF_MAP_LOOKUP_ELEM,
            &attr as *const _ as *mut std::ffi::c_void,
            std::mem::size_of::<libbpf_sys::bpf_attr>(),
        )
    };

    res == 0
}

/// unloading the offender program
fn force_unload_bpf_program(fd: libc::c_int, id: u32, writer: &mut Box<dyn syslog::LogWriter>) {
    unsafe {
        let _ = libbpf_sys::bpf_prog_detach(fd, 0);
    }

    // remove pinned files and write results to syslog
    remove_bpf_pins_by_id(id, writer);

    unsafe {
        libc::close(fd);
    }
}

/// scanning the kernel for ebpf programs
fn check_and_enforce(map_fd: libc::c_int, syslog_writer: &mut Box<dyn syslog::LogWriter>) {
    let mut id: u32 = 0;

    loop {
        let mut next_id: u32 = 0;
        let res = unsafe { libbpf_sys::bpf_prog_get_next_id(id, &mut next_id) };
        if res != 0 {
            break;
        }

        id = next_id;

        let fd = unsafe { libbpf_sys::bpf_prog_get_fd_by_id(id) };
        if fd < 0 {
            continue;
        }

        let mut info: libbpf_sys::bpf_prog_info = unsafe { std::mem::zeroed() };
        let mut info_len = std::mem::size_of::<libbpf_sys::bpf_prog_info>() as u32;

        let info_res = unsafe {
            libbpf_sys::bpf_obj_get_info_by_fd(
                fd,
                &mut info as *mut _ as *mut std::ffi::c_void,
                &mut info_len,
            )
        };

        if info_res != 0 {
            unsafe { libc::close(fd) };
            continue;
        }

        let prog_name = unsafe {
            CStr::from_ptr(info.name.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        let prog_type = info.type_;

        if is_prog_allowed(map_fd, &prog_name, prog_type) {

            unsafe { libc::close(fd) };
        } else {

            // generation of the syslog alert
            let alert_msg = format!(
                "SECURITY_ALERT: Unauthorized eBPF program detected! ID={}, Name='{}', Type={}. Action: Force Unload.", 
                id,
                prog_name,
                prog_type
            );
            
            // sending alert to syslog with a severity level 'critical' (LOG_CRIT)
            if let Err(e) = syslog_writer.crit(alert_msg) {
                error!("cannot write alert to syslog: {}", e);
            }

            warn!("alert sent! Unauthorized program: ID={}, Name='{}'", id, prog_name);

            // unloading unauthorized module
            force_unload_bpf_program(fd, id, syslog_writer);
            
            let mitigate_msg = format!("eBPF program ID={} has been purged ..", id);
            let _ = syslog_writer.warning(mitigate_msg);
        }
    }
}

#[tokio::main]
async fn main() {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    info!("start of an advanced eBPF protect service ..");

    // initializing connection to the local syslog socket (/dev/log)
    let formatter = Formatter3164 {
        facility: Facility::LOG_AUTHPRIV,
        hostname: None,
        process: "ebpf_firewall".to_string(),
        pid: std::process::id(),
    };

    let mut syslog_writer =
        match syslog::unix(formatter) {
        Ok(w) => w,
        Err(e) => {
            panic!("cannot initialize syslog: {}", e);
        }
    };

    let _ = syslog_writer.info("eBPF protect daemon started and attached to syslog");

    let map_fd = setup_whitelist_map();

    loop {
        check_and_enforce(map_fd, &mut syslog_writer);
        sleep(Duration::from_secs(1)).await;
    }
}

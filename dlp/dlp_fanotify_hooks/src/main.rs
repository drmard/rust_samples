use std::sync::Arc;
use std::os::unix::io::RawFd;
use tokio::sync::mpsc;
use crate::config::DlpConfig;
use crate::engine::DlpEvent;

#[repr(C)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

#[repr(C)]
struct FanotifyResponse {
    fd: i32,
    response: u32,
}

const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;

pub async fn run_fanotify_monitor(tx: mpsc::Sender<DlpEvent>, config: Arc<DlpConfig>) -> anyhow::Result<()> {
    use libc::{fanotify_init, fanotify_mark, FAN_CLASS_CONTENT, FAN_PERM_OPEN, FAN_MARK_ADD, FAN_MARK_MOUNT};
    
    // Initializing fanotify in content monitoring mode (Permission-mode)
    let fd = unsafe { fanotify_init(FAN_CLASS_CONTENT | libc::O_RDONLY, libc::O_RDWR) };
    if fd < 0 {
        return Err(anyhow::anyhow!("Failed to initialize fanotify. Root privileges are required .."));
    }

    // Monitoring the root mount point "/"
    let path_ptr = std::ffi::CString::new("/").unwrap();
    let mark_res = unsafe {
        fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PERM_OPEN, libc::AT_FDCWD, path_ptr.as_ptr())
    };

    if mark_res < 0 {
        return Err(anyhow::anyhow!("Failed to set up the fanotify interception point"));
    }

    println!("[*] The fanotify module is active. File system monitoring is running in BLOCKING mode...");

    let mut buffer = [0u8; 4096];
    loop {
        let bytes_read = unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if bytes_read <= 0 { continue; }

        let mut offset = 0;
        while offset + std::mem::size_of::<FanotifyEventMetadata>() <= bytes_read as usize {
            let metadata = unsafe {
                &*(buffer.as_ptr().add(offset) as *const FanotifyEventMetadata)
            };

            if metadata.fd >= 0 {
                let path = get_path_from_fd(metadata.fd).unwrap_or_else(|_| "Unknown".to_string());
                
                // Synchronous analysis of file content prior to its opening by the calling process
                let decision = evaluate_file_safety(metadata.fd, &config);
                
                let response = FanotifyResponse {
                    fd: metadata.fd,
                    response: decision,
                };
                
                // Sending a response to the kernel: unblock or deny the open() operation
                unsafe {
                    libc::write(fd, &response as *const FanotifyResponse as *const libc::c_void, std::mem::size_of::<FanotifyResponse>());
                    libc::close(metadata.fd);
                }

                if decision == FAN_DENY {
                    println!("[BLOCK] File leak prevented: {} by process PID {}", path, metadata.pid);
                }

                let _ = tx.send(DlpEvent::FileAccess { pid: metadata.pid, path, fd: metadata.fd }).await;
            }

            offset += metadata.event_len as usize;
        }
    }
}

fn get_path_from_fd(fd: RawFd) -> std::io::Result<String> {
    let proc_path = format!("/proc/self/fd/{}", fd);
    std::fs::read_link(proc_path).map(|p| p.to_string_lossy().into_owned())
}

fn evaluate_file_safety(fd: RawFd, config: &DlpConfig) -> u32 {
    let mut file_buf = [0u8; 1024];

    // We use 'pread' to avoid shifting the kernel file descriptor's position pointer
    let res = unsafe { libc::pread(fd, file_buf.as_mut_ptr() as *mut libc::c_void, file_buf.len(), 0) };
    
    if res > 0 {
        if let Ok(content_str) = std::str::from_utf8(&file_buf[..res as usize]) {
            if config.matches_pattern(content_str) {
                return FAN_DENY; 
            }
        }
    }
    FAN_ALLOW
}

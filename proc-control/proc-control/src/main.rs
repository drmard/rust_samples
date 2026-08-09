use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::TracePoint,
    Bpf,
};

use aya_log::BpfLogger;
use log::{info, warn, debug};
use std::convert::TryFrom;
use tokio::signal;

use proc_control_common::{ProcessEvent, EVENT_EXEC, EVENT_OPEN, EVENT_MEMFD};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {

    // initialize console logging
    env_logger::init();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/proc-control"
    ))?;
    #[cfg(not::debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/proc-control"
    ))?;

    // activating logger
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program_exec: &mut TracePoint =
        bpf.program_mut("sys_enter_execve").unwrap().try_into()?;
    program_exec.load()?;
    program_exec.attach("sys_calls", "sys_enter_execve")?;

    let program_open: &mut TracePoint =
        bpf.program_mut("sys_enter_openat").unwrap().try_into()?;
    program_open.load()?;
    program_open.attach("sys_calls", "sys_enter_openat")?;

    let program_memfd: &mut TracePoint =
        bpf.program_mut("sys_enter_memfd_create").unwrap().try_into()?;
    program_memfd.load()?;
    program_memfd.attach("sys_calls", "sys_enter_memfd_create")?;

    // get RingBuffer to read events
    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    info!("eBPF service started...");

    tokio::spawn(async move {
        loop {
            if let Some(item) = ring_buf.next() {
                if item.len() >= std::mem::size_of::<ProcessEvent>() {
                    let event = unsafe { &*(item.as_ptr() as *const ProcessEvent) };

                    let comm = String::from_utf8_lossy(&event.comm).trim_matches('\0').to_string();
                    let filename =
                        String::from_utf8_lossy(&event.filename).trim_matches('\0').to_string();

                    match event.event_type {
                        EVENT_EXEC => {
                            println!(
                                "[EXEC] PID: {} | Process: {} launched a command: {}",
                                event.pid, comm, filename);
                        }

                        EVENT_OPEN => {
                            println!("[OPEN] PID: {} | Process: {} opened file: {}",
                            event.pid, comm, filename);
                        }

                        EVENT_MEMFD => {
                            println!(
                                "[MEMFD] PID: {} | Process: {} is attempting to create a RAM file: {}",
                                event.pid, comm, filename
                            );
                        }

                        _ => {}
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_micros(100)).await;
        }
    });

    // waiting for Ctrl + C
    signal::ctrl_c().await?;
    info!("exit...");

    Ok(())
}


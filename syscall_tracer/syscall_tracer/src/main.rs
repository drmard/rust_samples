use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Bpf};
use bytes::BytesMut;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {

    // load eBPF code compiled to my_ebpf_prog
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/my_ebpf_prog"))?;

    // initialize the eBPF logger (optional)
    aya_log::EbpfLogger::init(&mut bpf)?;

    // Try attach to entry point for all syscalls
    let program: &mut TracePoint = bpf.program_mut(
        "sys_enter_syscall").unwrap().try_into()?;
    program.load()?;
    program.attach("raw_syscalls", "sys_enter")?;

    // receiving events via PerfEventArray
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")
        .unwrap())?;

    println!("Tracing syscalls.. Ctrl + C to stop..");

    // read events from each CPU
    for cpu_id in aya::util::online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let event_ptr = buffers[i].as_ptr() as *const Event;
                    let event = unsafe { &*event_ptr };

                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("unknown")
                        .trim_matches(char::from(0));

                    println!("PID: {}, Process: {}, Syscall ID: {}",
                        event.pid, comm, event.syscall_id);
                }
            }
        });
    }

    signal::ctrl_c().await?;
    Ok(())
}

#[repr(C)]
struct Event {
    pid: u32,
    syscall_id: u32,
    comm: [u8; 16],
}

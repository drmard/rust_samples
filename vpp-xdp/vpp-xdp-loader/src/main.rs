use aya::maps::XskMap;
use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use clap::Parser;
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    iface: String, // Interface name (for example eth1)
    #[arg(short, long, default_value = "/sys/fs/bpf/vpp_xdp")]
    pin_path: String, // Path for card pinning
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // 1. Create a directory in bpffs if it does not exist
    if !Path::new(&args.pin_path).exists() {
        fs::create_dir_all(&args.pin_path)?;
    }

    // 2. get the eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes!("../../target/bpfel-unknown-none/debug/eth-xdp-kernel"))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes!("../../target/bpfel-unknown-none/release/eth-xdp-kernel"))?;

    // 3. Extract and pin the XSKMAP for VPP
    let mut xsk_map = XskMap::try_from(bpf.map_mut("VPP_XSK_MAP").unwrap())?;
    let map_pin_path = format!("{}/xsks_map", args.pin_path);
    
    // Remove the old pin file if it remains from previous runs
    let _ = fs::remove_file(&map_pin_path);

    xsk_map.pin(&map_pin_path)?;
    println!(" eBPF XSKMAP successfully pinned to: {}", map_pin_path);

    // 4. find then load and attach the XDP program to the interface
    let program: &mut Xdp = bpf.program_mut("vpp_xdp_redirect").unwrap().try_into()?;
    program.load()?;
    
    // We will use Native/Driver mode for maximum speed (or Skb for virtual machines)
    program.attach(&args.iface, XdpFlags::DRV_MODE)?;

    println!(" The eBPF program has been successfully started on the interface {}", args.iface);

    // We leave the program running until the user presses Ctrl+C
    tokio::signal::ctrl_c().add_now().await?;

    println!("Shut down, unlink ..");

    Ok(())
}

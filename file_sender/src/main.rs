use std::env;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> io::Result<()> {

    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Try: {} <IP:PORT> <FILE_PATH> <mode: client|server>", args[0]);
        std::process::exit(1);
    }

    let addr = &args[1];
    let file_path = &args[2];
    let mode = &args[3];

    match mode.as_str() {
        "server" => {
            println!("run in server mode on {}", addr);
            run_server(addr, file_path).await?;
        }
        "client" => {
            println!("client mode, connect to {}", addr);
            run_client(addr, file_path).await?;
        }
        _ => {
            eprintln!("error: mode must be either 'client' or 'server'");
            std::process::exit(1);
        }
    }

    Ok(())
}

// server mode
async fn run_server(addr: &str, output_path: &str) -> io::Result<()> {

    let listener = TcpListener::bind(addr).await?;
    println!("waiting ...");

    let (mut socket, client_addr) = listener.accept().await?;
    println!("client has connected: {}", client_addr);

    let mut file = File::create(output_path).await?;
    println!("receiving data into a file '{}'...", output_path);

    let bytes_copied = io::copy(&mut socket, &mut file).await?;

    file.flush().await?;
    println!("received {} bytes. file saved", bytes_copied);

    Ok(())
}

// client mode
async fn run_client(addr: &str, input_path: &str) -> io::Result<()> {

    // checking for the file's existence
    if !Path::new(input_path).exists() {

        return Err(io::Error::new(io::ErrorKind::NotFound, "specified file not found .."));
    }

    let mut file = File::open(input_path).await?;

    // connect asynchronously
    let mut socket = TcpStream::connect(addr).await?;
    println!("connected ..");

    println!("send file '{}'...", input_path);
    let bytes_copied = io::copy(&mut file, &mut socket).await?;

    socket.shutdown().await?;
    println!("successfully sent {} bytes", bytes_copied);

    Ok(())
}

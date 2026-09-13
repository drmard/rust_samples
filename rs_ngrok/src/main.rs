use std::env;
use std::error::Error;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    match args[1].as_str() {
        "server" => {
            // Awaiting the command: server <control_port> <public_port>
            let control_port = args.get(2).map(|s| s.as_str()).unwrap_or("8001");
            let public_port = args.get(3).map(|s| s.as_str()).unwrap_or("8080");
            run_server(control_port, public_port).await?;
        }
        "client" => {
            // Awaiting the command: client <server_control_addr> <local_service_addr>
            let server_addr = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:8001");
            let local_addr = args.get(3).map(|s| s.as_str()).unwrap_or("127.0.0.1:3000");
            run_client(server_addr, local_addr).await?;
        }
        _ => print_usage(),
    }

    Ok(())
}

fn print_usage() {
    println!("Usage:");
    println!("  server: rs_ngrok server [control_port] [public_port]");
    println!("  client: rs_ngrok client [server_control_addr] [local_service_addr]");
}

// ==================== Server side code ====================
async fn run_server(control_port: &str, public_port: &str) -> Result<(), Box<dyn Error>> {
    let control_listener = TcpListener::bind(format!("0.0.0.0:{}", control_port)).await?;
    let public_listener = TcpListener::bind(format!("0.0.0.0:{}", public_port)).await?;
    
    println!("Server started!");
    println!("Client waiting on the port :{}", control_port);
    println!("Public port (all traffic from here will go into the tunnel): :{}", public_port);

    // In the POC we accept exactly ONE connection from our client
    let (mut control_stream, _) = control_listener.accept().await?;

    println!("The client successfully connected to the control panel.");

    // Main public request processing loop
    loop {
        let (mut public_stream, _) = public_listener.accept().await?;
        println!("Public request received! Notifying the client...");

        // Notify the client that a new connection has arrived (send a 1-byte trigger)
        if control_stream.write_all(&[1]).await.is_err() {
            println!("Connection with the client has been lost.");
            break;
        }

        // We are waiting for the client to open a dedicated data connection to tunnel this user
        let (mut data_stream, _) = control_listener.accept().await?;
        
        // We directly link the incoming public stream and the tunnel stream from the client
        tokio::spawn(async move {
            if let Err(e) = copy_bidirectional(&mut public_stream, &mut data_stream).await {
                eprintln!("Data proxying error: {}", e);
            }
        });
    }

    Ok(())
}

// ==================== Client side code ====================
async fn run_client(server_addr: &str, local_addr: &str) -> Result<(), Box<dyn Error>> {
    println!("Connecting to the management server {}...", server_addr);
    let mut control_stream = TcpStream::connect(server_addr).await?;
    println!("Successfully connected to the server!");

    let mut buffer = [0u8; 1];
    
    // We continuously listen for commands from the server in a loop
    loop {

        // Read the control byte (signal indicating a new visitor)
        let n = control_stream.read(&mut buffer).await?;
        if n == 0 {
            println!("The server closed the connection.");
            break;
        }

        if buffer[0] == 1 {
            println!("The server is requesting a tunnel! Connecting the local service to the server...");
            
            let server_addr_clone = server_addr.to_string();
            let local_addr_clone = local_addr.to_string();

            // We redirect traffic asynchronously so as not to block the reading of subsequent commands
            tokio::spawn(async move {

                // Opening a parallel connection to the server (for data)
                let mut data_stream = match TcpStream::connect(&server_addr_clone).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };

                // Opening a connection to your local application (e.g., a website)
                let mut local_stream = match TcpStream::connect(&local_addr_clone).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };

                // A bridge between a local application and a remote server
                let _ = copy_bidirectional(&mut data_stream, &mut local_stream).await;
            });
        }
    }

    Ok(())
}

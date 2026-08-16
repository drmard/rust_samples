use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use dashmap::DashMap;

const TARGET_UPSTREAM: &str = "127.0.0.1:8080"; // Protected server
const PROXY_BIND_ADDR: &str = "0.0.0.0:8000";   // anti-DDoS proxy
const MAX_GLOBAL_CONNECTIONS: usize = 10000;    // SYN/Connection flood protection
const MAX_CONN_PER_IP: usize = 20;              // Connection limit per IP
const SLOW_ATTACK_TIMEOUT: Duration = Duration::from_secs(5); // read timeout (Slowloris)
const BURST_WINDOW: Duration = Duration::from_secs(1);        // RPS calculation window
const MAX_RPS_PER_IP: usize = 50;              // requests-per-second limit (L7 HTTP Flood)

// structure for tracking metrics for each IP (L4 and L7 metrics) 
struct IpStats {
    connection_count: usize,
    rps_count: usize,
    last_request_time: Instant,
}

struct AntiDDoSShield {
    ip_registry: DashMap<SocketAddr, IpStats>,
    global_connections: Arc<tokio::sync::Semaphore>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(PROXY_BIND_ADDR).await?;
    println!("[Anti-DDoS] The protection service is running on {}", PROXY_BIND_ADDR);

    let shield = Arc::new(AntiDDoSShield {
        ip_registry: DashMap::new(),
        global_connections: Arc::new(tokio::sync::Semaphore::new(MAX_GLOBAL_CONNECTIONS)),
    });

    let shield_clone = Arc::clone(&shield);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            shield_clone.ip_registry.retain(|_, stats| {
                stats.last_request_time.elapsed() < Duration::from_secs(60) || stats.connection_count > 0
            });
        }
    });

    // inbound traffic processing cycle
    loop {
        let (stream, client_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(_) => continue, // graceful handling of socket errors during heavy flooding
        };

        let shield_ref = Arc::clone(&shield);

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, client_addr, shield_ref).await {
                // Error logging in debug mode
                eprintln!("[DROP] client {}: {}", client_addr.ip(), e);
            }
        });
    }
}

async fn handle_client(
    mut client_stream: TcpStream,
    client_addr: SocketAddr,
    shield: Arc<AntiDDoSShield>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ip = client_addr;

    let _global_permit = shield.global_connections.try_acquire()
        .map_err(|_| "Global connection limit reached (SYN/Connection Flood Protection)")?;

    {
        let mut entry = shield.ip_registry.entry(ip).or_insert(IpStats {
            connection_count: 0,
            rps_count: 0,
            last_request_time: Instant::now(),
        });

        if entry.connection_count >= MAX_CONN_PER_IP {
            return Err("Too many connections from this IP (L4 Flood Mitigation)".into());
        }

        entry.connection_count += 1;
    }

    let shield_decrement = Arc::clone(&shield);
    let _cleanup = scopeguard::guard((), move |_| {
        if let Some(mut entry) = shield_decrement.ip_registry.get_mut(&ip) {
            if entry.connection_count > 0 {
                entry.connection_count -= 1;
            }
        }
    });

    let mut buffer = [0; 4096];
    
    // Slowloris Mitigation
    let bytes_read = timeout(SLOW_ATTACK_TIMEOUT, client_stream.read(&mut buffer))
        .await
        .map_err(|_| "Read timeout exceeded (Slowloris / Slow Read Attack Mitigation)")??;

    if bytes_read == 0 {
        return Ok(());
    }

    // RPS Rate Limiting
    {
        let mut entry = shield.ip_registry.entry(ip).or_insert(IpStats {
            connection_count: 1,
            rps_count: 0,
            last_request_time: Instant::now(),
        });

        let now = Instant::now();
        if now.duration_since(entry.last_request_time) > BURST_WINDOW {
            entry.rps_count = 1;
            entry.last_request_time = now;
        } else {
            entry.rps_count += 1;
            if entry.rps_count > MAX_RPS_PER_IP {
                return Err("RPS limit exceeded (L7 HTTP Flood Protection)".into());
            }
        }
    }

    // Proxying Cleaned Traffic to Upstream
    let mut upstream_stream = timeout(Duration::from_secs(3), TcpStream::connect(TARGET_UPSTREAM))
        .await
        .map_err(|_| "Upstream server unavailable")??;

    upstream_stream.write_all(&buffer[..bytes_read]).await?;

    let (mut client_reader, mut client_writer) = client_stream.into_split();
    let (mut upstream_reader, mut upstream_writer) = upstream_stream.into_split();

    let client_to_upstream = async {
        tokio::io::copy(&mut client_reader, &mut upstream_writer).await
    };
    
    let upstream_to_client = async {
        tokio::io::copy(&mut upstream_reader, &mut client_writer).await
    };

    // parallel data copying between client and server
    tokio::select! {
        res = client_to_upstream => res?,
        res = upstream_to_client => res?,
    };

    Ok(())
}

mod scopeguard {
    pub struct Guard<T, F: FnOnce(T)> {
        data: T,
        drop_fn: Option<F>,
    }
    pub fn guard<T, F: FnOnce(T)>(data: T, drop_fn: F) -> Guard<T, F> {
        Guard { data, drop_fn: Some(drop_fn) }
    }
    impl<T, F: FnOnce(T)> Drop for Guard<T, F> {
        fn drop(&mut self) {
            if let Some(f) = self.drop_fn.take() {
                (f)(std::ptr::replace(&mut self.data, unsafe { std::mem::zeroed() }));
            }
        }
    }
}

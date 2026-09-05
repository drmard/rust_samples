use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use pcap::Capture;
use regex::Regex;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task;

// --- DLP Analysis Module ---
#[derive(Clone)]
struct DlpEngine {
    // Regular expression for finding credit cards (an example of sensitive data)
    card_pattern: Regex,
}

impl DlpEngine {
    fn new() -> Self {
        Self {
            card_pattern: Regex::new(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b").unwrap(),
        }
    }

    // Checking text data for leaks
    fn inspect_data(&self, context: &str, data: &str) {

        if self.card_pattern.is_match(data) {
            println!("[DLP ALERT] A live card data leak has been detected: {}!", context);
            for mat in self.card_pattern.find_iter(data) {
                println!("   Compromised fragment: {}", mat.as_str());
            }
        }
    }
}

// --- HTTP Proxy (Active Interception) ---
async fn proxy_handler(
    dlp: Arc<DlpEngine>,
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {

    let (parts, body) = req.into_parts();
    
    // read the request body for analysis
    let body_bytes = match hyper::body::to_bytes(body).await {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Error reading request body"))
            .unwrap()),
    };

    if let Ok(text) = std::str::from_utf8(&body_bytes) {
        dlp.inspect_data(&format!("HTTP Proxy Request to {}", parts.uri), text);
    }

    // reconstructing the request to be sent to the target server (returning a stub as part of the mock).
    // in a full-fledged proxy, we should call `hyper::Client` here to proxy the request
    // to the target URI
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("data successfully processed by the DLP proxy"))
        .unwrap();

    Ok(response)
}

async fn run_proxy(dlp: Arc<DlpEngine>) {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    
    let make_svc = make_service_fn(move |_conn| {
        let dlp_clone = dlp.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                proxy_handler(dlp_clone.clone(), req)
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);
    println!("[PROXY] HTTP Proxy running on http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("Proxy server error: {}", e);
    }
}

// --- NETWORK SNIFFER (PASSIVE ANALYSIS) ---
fn run_sniffer(dlp: Arc<DlpEngine>) {

    // Select of the default packet capture device(interface)
    let device = Capture::from_device("any")
        .unwrap_or_else(|_| {
            // if "any" is not supported , we take the first available device
            pcap::Device::lookup().unwrap().expect("no network interfaces available")
        });

    println!("[SNIFFER] The sniffer is running on the device: {}", device.name);

    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true) // Enable promiscuous mode to intercept other people's traffic
        .snaplen(65535)
        .timeout(1000)
        .open()
        .unwrap();

    // Filter: capture only IP packets containing data (exclude pure TCP handshakes)
    // For demonstration purposes, we do not apply a strict port constraint; we search everywhere
    cap.filter("ip", true).unwrap();

    while let Ok(packet) = cap.next_packet() {

        // Basic parsing of raw bytes (skipping Ethernet/IP/TCP headers)
        let data = packet.data;
        
        // We are trying to find here text strings in the raw packet payload
        if let Ok(payload_text) = std::str::from_utf8(data) {

            dlp.inspect_data("Passive Network Sniffer", payload_text);
        } else {

            // If the entire packet is not UTF-8, we search for text substrings within the binary data
            let lossy_text = String::from_utf8_lossy(data);

            if lossy_text.len() > 40 { // We will analyze only packets with a payload
                dlp.inspect_data("Passive Network Sniffer (Lossy)", &lossy_text);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    println!("=== Initializing the DLP Component ===");
    let dlp_engine = Arc::new(DlpEngine::new());

    // Launching the sniffer in a separate OS thread, since pcap blocks the thread in an infinite loop
    let dlp_for_sniffer = dlp_engine.clone();
    task::spawn_blocking(move || {
        run_sniffer(dlp_for_sniffer);
    });

    // Launching a proxy server in the asynchronous Tokio environment
    run_proxy(dlp_engine).clone().await;
}

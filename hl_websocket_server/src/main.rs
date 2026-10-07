use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use dashmap::DashMap;
use futures-util::{SinkExt, StreamExt};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;

// Internal Redis channel for inter-node communication (horizontal scaling)
const REDIS_BROADCAST_CHANNEL: &str = "ws_global_broadcast";

// Heartbeat intervals
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Serialize, Deserialize, Debug, Clone)]
enum ClientMessage {
    Ping,
    Auth { user_id: u64, token: String },
    Broadcast { text: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum ServerMessage {
    Pong,
    Welcome { session_id: u64 },
    Notification { from_user: u64, text: String },
    Error { code: u16, msg: String },
}

type ClientSender = mpsc::UnboundedSender<ServerMessage>;
type RedisPool = Pool<RedisConnectionManager>;

struct ServerState {
    connections: DashMap<u64, ClientSender>,
    redis_pool: RedisPool,
}

// Tuning the Tokio Thread Pool (Custom Entry Point)
fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Configuring the multi-threaded runtime for a high-load profile
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_cpus::get()) // One worker thread per CPU core
        .max_blocking_threads(512)       // Headroom for heavy synchronous tasks / file I/O
        .thread_name("hl-ws-worker")
        .thread_stack_size(3 * 1024 * 1024) // 3 Mb per thread stack
        .build()?;

    runtime.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:8080";
    let listener = TcpListener::bind(addr).await?;

    println!("High-Load Cluster Node launched on {}", addr);

    // INITIALIZING REDIS INTEGRATION
    let redis_url = "redis://127.0.0.1:6379";
    let manager = RedisConnectionManager::new(redis_url)?;

    // Creating a connection pool: max. 50 connections to Redis
    let redis_pool = Pool::builder().max_size(50).build(manager).await?;

    let state = Arc::new(ServerState {
        connections: DashMap::new(),
        redis_pool: redis_pool.clone(),
    });

    // We are launching a background task to listen to Redis Pub/Sub for horizontal scaling
    tokio::spawn(listen_global_broadcast(Arc::clone(&state), redis_url.to_string()));

    let mut session_counter: u64 = 0;

    while let Ok((stream, client_addr)) = listener.accept().await {
        session_counter += 1;
        let current_session = session_counter;
        let state_clone = Arc::clone(&state);

        if let Err(e) = stream.set_nodelay(true) {
            eprintln!("TCP_NODELAY configuration error: {}", e);
        }

        tokio::spawn(async move {
            if let Err(e) = handle_connection(state_clone, stream, client_addr, current_session).await {
                eprintln!("Session {} has ended: {:?}", current_session, e);
            }
        });
    }

    Ok(())
}

// Network Heartbeat/Ping-Pong and Incoming Data Processing
async fn handle_connection(
    state: Arc<ServerState>,
    stream: TcpStream,
    addr: SocketAddr,
    session_id: u64,
) -> Result<(), Box<dyn std::error::Error>> {

    let ws_stream = tokio_tungstenite::accept_async(stream).await?;
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
    state.connections.insert(session_id, tx);

    // Welcome message
    let welcome_bytes = postcard::to_allocvec(&ServerMessage::Welcome { session_id })?;
    ws_tx.send(WsMessage::Binary(welcome_bytes)).await?;

    // TASK 1: Data transmission + Network Heartbeat (Ping frames every 20 seconds)
    let state_write_clone = Arc::clone(&state);
    let mut write_task = tokio::spawn(async move {
        let mut heartbeat_ticker = tokio::time::interval(HEARTBEAT_INTERVAL);

        // The first iteration of the ticker fires immediately; we should skip it
        heartbeat_ticker.tick().await; 

        loop {
            tokio::select! {
                // extract messages from the server's internal channel to the client
                Some(message) = rx.recv() => {
                    if let Ok(bytes) = postcard::to_allocvec(&message) {
                        if ws_tx.send(WsMessage::Binary(bytes)).await.is_err() { break; }
                    }
                }
                // Heartbeat Timer: Generating a Native WebSocket Ping Frame
                _ = heartbeat_ticker.tick() => {
                    // send an empty Ping at the network frame level (RFC 6455)
                    if ws_tx.send(WsMessage::Ping(vec![])).await.is_err() {
                        break; 
                    }
                }
            }
        }

        let _ = ws_tx.close().await;
        state_write_clone.connections.remove(&session_id);
    });

    // TASK 2: Read loop (current context) with protection against "stalled" connections via timeout
    loop {
        // If no frames are received from the client (including an automatic Pong in response to our Ping) within
        // 45 seconds, we drop the connection
        let incoming = timeout(CLIENT_TIMEOUT, ws_rx.next()).await;

        match incoming {
            Ok(Some(Ok(msg))) => {
                if msg.is_binary() {
                    let bytes = msg.into_data();
                    if let Ok(client_msg) = postcard::from_bytes::<ClientMessage>(&bytes) {
                        process_message(&state, session_id, client_msg).await;
                    }
                } else if msg.is_pong() {
                    // The native Pong frame is automatically intercepted by the library. Our timeout
                    // was reset thanks to the successful reading of the frame - the connection is "alive"
                } else if msg.is_close() {
                    break;
                }
            }
            Ok(Some(Err(_))) | Ok(None) => break, // network error or closure
            Err(_) => {
                println!("Session {} timed out (Heartbeat Timeout)", session_id);
                break;
            }
        }
    }

    // Cleanup
    state.connections.remove(&session_id);
    write_task.abort();

    Ok(())
}

// Business Logic and Horizontal Scaling via Redis Pub/Sub
async fn process_message(state: &Arc<ServerState>, sender_id: u64, msg: ClientMessage) {
    match msg {
        ClientMessage::Ping => {
            if let Some(sender) = state.connections.get(&sender_id) {
                let _ = sender.send(ServerMessage::Pong);
            }
        }
        ClientMessage::Auth { user_id, token } => {
            println!("Auth request on session {}: user={}", sender_id, user_id);
        }
        ClientMessage::Broadcast { text } => {
            // Drafting 'Notification' message
            let notification = ServerMessage::Notification {
                from_user: sender_id,
                text,
            };

            // serialize it for sending to Redis
            if let Ok(payload) = postcard::to_allocvec(&notification) {

                // We take an available connection from the pool and publish it to Redis for all cluster nodes
                if let Ok(mut redis_conn) = state.redis_pool.get().await {
                    let _: Result<(), _> = redis_conn.publish(REDIS_BROADCAST_CHANNEL, payload).await;
                }
            }
        }
    }
}

// Background TASK: Listening to Redis Pub/Sub and broadcasting to local clients
async fn listen_global_broadcast(state: Arc<ServerState>, redis_url: String) {

    let client = redis::Client::open(redis_url).expect("Invalid Redis URL for PubSub");
    
    loop {
        if let Ok(conn) = client.get_async_connection().await {
            let mut pubsub = conn.into_pubsub();
            if pubsub.subscribe(REDIS_BROADCAST_CHANNEL).await.is_ok() {
                let mut stream = pubsub.on_message();
                
                // intercepting messages from the global Redis bus
                while let Some(msg) = stream.next().await {
                    let payload: Vec<u8> = msg.get_payload().unwrap_or_default();
                    
                    // deserialize the message
                    if let Ok(server_msg) = postcard::from_bytes::<ServerMessage>(&payload) {

                        // extract the sender (to avoid broadcasting back to them if they are on this node)
                        let origin_sender = match &server_msg {
                            ServerMessage::Notification { from_user, .. } => *from_user,
                            _ => 0,
                        };

                        // we quickly broadcast to all local clients connected to the CURRENT node
                        for target in state.connections.iter() {
                            if *target.key() != origin_sender {
                                let _ = target.value().send(server_msg.clone());
                            }
                        }
                    }
                }
            }
        }

        // Redis failover protection: pause before reconnecting
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

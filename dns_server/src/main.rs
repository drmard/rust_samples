use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::get,
    Router,
};
use chrono::{DateTime, Utc};
use hickory_proto::op::{Header, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

// Разделяемое состояние для Axum и DNS-сервера
type SharedDb = Arc<Mutex<Connection>>;

struct DnsServerHandler {
    db: SharedDb,
    forwarder: TokioAsyncResolver,
}

impl DnsServerHandler {
    fn new(db: SharedDb) -> Self {
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfigGroup::from_ips_clear(
            &[IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            53,
            true,
        ));
        let mut opts = ResolverOpts::default();
        opts.cache_size = 0; // Локальный кэш в SQLite

        Self {
            db,
            forwarder: TokioAsyncResolver::tokio(config, opts),
        }
    }

    fn lookup_local_a_record(&self, domain: &str) -> Option<Ipv4Addr> {
        let db = self.db.lock().unwrap();
        let mut stmt = db
            .prepare("SELECT ip_address FROM dns_records WHERE domain = ? AND record_type = 'A' LIMIT 1")
            .ok()?;
        
        let clean_domain = domain.trim_end_matches('.');
        let mut rows = stmt.query(params![clean_domain]).ok()?;
        if let Some(row) = rows.next().ok()? {
            let ip_str: String = row.get(0).ok()?;
            Ipv4Addr::from_str(&ip_str).ok()
        } else {
            None
        }
    }

    fn lookup_cache_a_record(&self, domain: &str) -> Option<Ipv4Addr> {
        let db = self.db.lock().unwrap();
        let mut stmt = db
            .prepare("SELECT ip_address, expires_at FROM dns_cache WHERE domain = ? AND record_type = 'A' LIMIT 1")
            .ok()?;
        
        let clean_domain = domain.trim_end_matches('.');
        let mut rows = stmt.query(params![clean_domain]).ok()?;
        if let Some(row) = rows.next().ok()? {
            let ip_str: String = row.get(0).ok()?;
            let expires_str: String = row.get(1).ok()?;
            if let Ok(expires_at) = DateTime::parse_from_rfc3339(&expires_str) {
                if Utc::now() < expires_at.with_timezone(&Utc) {
                    return Ipv4Addr::from_str(&ip_str).ok();
                }
            }
        }
        None
    }

    fn save_to_cache(&self, domain: &str, ip: &str, ttl: u32) {
        let db = self.db.lock().unwrap();
        let clean_domain = domain.trim_end_matches('.');
        let expires_str = (Utc::now() + chrono::Duration::seconds(ttl as i64)).to_rfc3339();
        let _ = db.execute(
            "INSERT OR REPLACE INTO dns_cache (domain, record_type, ip_address, expires_at) VALUES (?, 'A', ?, ?)",
            params![clean_domain, ip, expires_str],
        );
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsServerHandler {
    async fn handle_request<R: ResponseHandler>(&self, request: &Request, mut response_handler: R) -> ResponseInfo {
        let query = request.query();
        let name = query.name().to_string();
        let record_type = query.query_type();

        if record_type == RecordType::A {
            if let Some(local_ip) = self.lookup_local_a_record(&name) {
                info!("[DDNS HIT] {} -> {}", name, local_ip);
                return respond_with_a(request, response_handler, local_ip, 60, true).await;
            }
            if let Some(cached_ip) = self.lookup_cache_a_record(&name) {
                info!("[CACHE HIT] {} -> {}", name, cached_ip);
                return respond_with_a(request, response_handler, cached_ip, 300, false).await;
            }
        }

        info!("[MISS] forwarding: {}", name);
        match self.forwarder.lookup(query.name(), record_type).await {
            Ok(lookup_result) => {
                let mut header = Header::response_from_request(request.header());
                header.set_authoritative(false);
                let records: Vec<Record> = lookup_result
                    .records()
                    .iter()
                    .map(|r| Record::from_rdata(r.name().clone(), r.ttl(), r.data().clone()))
                    .collect();

                if record_type == RecordType::A {
                    for record in lookup_result.records() {
                        if let Some(RData::A(ip)) = record.data().as_a() {
                            self.save_to_cache(&name, &ip.to_string(), record.ttl());
                            break;
                        }
                    }
                }
                let builder = MessageResponseBuilder::from_message_request(request);
                response_handler.send_response(builder.build(header, &records, &[], &[], &[])).await.unwrap_or_else(|_| ResponseInfo::from(header))
            }
            Err(_) => {
                let mut header = Header::response_from_request(request.header());
                header.set_rcode(ResponseCode::NXDomain);
                let builder = MessageResponseBuilder::from_message_request(request);
                response_handler.send_response(builder.build_no_records(header)).await.unwrap_or_else(|_| ResponseInfo::from(header))
            }
        }
    }
}

async fn respond_with_a<R: ResponseHandler>(request: &Request, mut handler: R, ip: Ipv4Addr, ttl: u32, auth: bool) -> ResponseInfo {
    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(auth);
    let record = Record::from_rdata(request.query().name().into(), ttl, RData::A(ip));
    let builder = MessageResponseBuilder::from_message_request(request);
    handler.send_response(builder.build(header, &[record], &[], &[], &[])).await.unwrap_or_else(|_| ResponseInfo::from(header))
}

// REST API components

// structure for GET request parameters validation /update?domain=...&ip=...
#[derive(Deserialize)]
struct UpdateParams {
    domain: String,
    ip: String,
}

// http handler for updating Dynamic DNS records
async fn handle_ddns_update(
    State(db): State<SharedDb>,
    Query(params): Query<UpdateParams>,
) -> (StatusCode, String) {

    // validation of the IP address format
    if Ipv4Addr::from_str(&params.ip).is_err() {
        return (StatusCode::BAD_REQUEST, "Error: invalid IPv4 address format\n".to_string());
    }

    let clean_domain = params.domain.trim_end_matches('.').to_string();
    
    // lock the mutex for writing to the DB  
    let db_lock = db.lock().unwrap();
    let result = db_lock.execute(
        "INSERT OR REPLACE INTO dns_records (domain, record_type, ip_address) VALUES (?, 'A', ?)",
        params![clean_domain, params.ip],
    );

    match result {
        Ok(_) => {
            info!("[HTTP API] successfully updated domain '{}' -> {}", clean_domain, params.ip);
            (StatusCode::OK, format!("successfully updated: {} points to {}\n", clean_domain, params.ip))
        }
        Err(e) => {
            error!("[HTTP API] SQLite error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "internal database error\n".to_string())
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    info!("launch of the DNS and DDNS REST API service...");

    // initializing SQLite
    let db_conn = Connection::open("dns_records.db")?;
    db_conn.execute("CREATE TABLE IF NOT EXISTS dns_records (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE, record_type TEXT NOT NULL, ip_address TEXT NOT NULL)", [])?;
    db_conn.execute("CREATE TABLE IF NOT EXISTS dns_cache (domain TEXT NOT NULL UNIQUE, record_type TEXT NOT NULL, ip_address TEXT NOT NULL, expires_at TEXT NOT NULL)", [])?;
    db_conn.execute("CREATE INDEX IF NOT EXISTS idx_ddns ON dns_records(domain)", [])?;
    db_conn.execute("CREATE INDEX IF NOT EXISTS idx_cache ON dns_cache(domain)", [])?;
    
    let db_shared = Arc::new(Mutex::new(db_conn));

    // Launching a REST API (Axum) in a background thread
    let db_for_axum = Arc::clone(&db_shared);
    tokio::spawn(async move {

        // create the router and pass the database state (State).
        let app = Router::new()
            .route("/update", get(handle_ddns_update))
            .with_state(db_for_axum);

        let http_addr = SocketAddr::from(([0, 0, 0, 0], 8080));
        let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
        info!("REST API server running at http://{}", http_addr);
        
        axum::serve(listener, app).await.unwrap();

    });

    // cache clearing
    let db_for_cleanup = Arc::clone(&db_shared);
    tokio::spawn(async move {
        loop {

            tokio::time::sleep(Duration::from_secs(60)).await;
            let db = db_for_cleanup.lock().unwrap();
            let now_str = Utc::now().to_rfc3339();
            if let Ok(deleted) = db.execute("DELETE FROM dns_cache WHERE expires_at < ?", params![now_str]) {
                if deleted > 0 { info!("[CLEANUP] removed obsolete cache entries: {}", deleted); }
            }
        }
    });

    // DNS server started: main thread
    let dns_addr: SocketAddr = "0.0.0.0:5353".parse()?;
    let udp_socket = UdpSocket::bind(dns_addr).await?;
    info!("DNS server listens UDP on {}", dns_addr);

    let handler = DnsServerHandler::new(Arc::clone(&db_shared));

    let mut server = hickory_server::ServerFuture::new(handler);
    server.register_socket(udp_socket);
    server.block_until_done().await?;

    Ok(())
}

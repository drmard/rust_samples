use clickhouse::{Client, Row};
use etherparse::SlicedPacket;
use hickory_proto::op::{Message, MessageType};
use pcap::{Capture, Device};
use serde::Serialize;
use std::error::Error;
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::instant;

// record for add to ClickHouse  
#[derive(Debug, Serialize, Row, Clone)]
struct DnsRecord {
    #[serde(with = "clickhouse::serde::time::datetime64::ms")]
    timestamp: chrono::DateTime<chrono::Utc>,
    tx_id: u16,
    msg_type: String,
    query_type: String,
    domain: String,
    answers: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // initializing ClickHouse client
    let ch_client = Client::default()
        .with_url("http://127.0.0.1:8123")
        .with_database("default");

    // communication channels
    let (tx_packet, mut rx_packet) = mpsc::channel::<Vec<u8>>(10_000);
    let (tx_log, mut rx_log) = mpsc::channel::<DnsRecord>(50_000);

    // packet capture stream (pcap)
    thread::spawn(move || {
        if let Err(e) = run_pcap_sniffer(tx_packet) {
            eprintln!("[pcap error]: {:?}", e);
        }
    });

    let ch_worker = ch_client.clone();
    tokio::spawn(async move {
        let mut batch = Vec::with_capacity(1000);
        let mut last_flush = instant::Instant::now();
        let flush_interval = Duration::from_secs(3);

        loop {
            tokio::select! {
                // new log record has arrived from the parser
                Some(record) = rx_log.recv() => {
                    batch.push(record);
                    if batch.len() >= 1000 {
                        flush_to_clickhouse(&ch_worker, &mut batch).await;
                        last_flush = instant::Instant::now();
                    }
                }

                _ = tokio::time::sleep_until(last_flush + flush_interval) => {
                    if !batch.is_empty() {
                        flush_to_clickhouse(&ch_worker, &mut batch).await;
                    }
                    last_flush = instant::Instant::now();
                }
            }
        }
    });

    println!("service has been started. Telemetry is being collected in ClickHouse ..");

    // packet parsing loop
    while let Some(packet_data) = rx_packet.recv().await {
        if let Ok(sliced) = SlicedPacket::from_ethernet(&packet_data) {
            if let Some(etherparse::TransportSlice::Udp(_)) = sliced.transport {
                if !sliced.payload.is_empty() {
                    if let Ok(dns_msg) = Message::from_bytes(sliced.payload) {

                        // parse and send to the write queue
                        if let Some(record) = parse_dns_to_record(&dns_msg) {
                            let _ = tx_log.try_send(record);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// packets capture in the OS native stream
fn run_pcap_sniffer(tx: mpsc::Sender<Vec<u8>>) -> Result<(), Box<dyn Error>> {
    let device = Device::lookup()?.ok_or("no interface")?;
    let mut cap = Capture::from_device(device)?.promisc(true).snaplen(65535).timeout(100).open()?;
    cap.filter("udp port 53", true)?;

    while let Ok(packet) = cap.next_packet() {
        let _ = tx.try_send(packet.data.to_vec());
    }

    Ok(())
}

// mapping DNS data to record for database
fn parse_dns_to_record(msg: &Message) -> Option<DnsRecord> {
    let query = msg.queries().first()?;
    let tx_id = msg.id();
    let domain = query.name().to_string();
    let query_type = format!("{:?}", query.query_type());
    let timestamp = chrono::Utc::now();

    let (msg_type, answers) = match msg.message_type() {
        MessageType::Query => ("Query".to_string(), vec![]),
        MessageType::Response => {
            let ans_list = msg.answers().iter()
                .filter_map(|ans| ans.data().map(|d| format!("{}", d)))
                .collect();
            ("Response".to_string(), ans_list)
        }
    };

    Some(DnsRecord { timestamp, tx_id, msg_type, query_type, domain, answers })
}

// asynchronous insertion of a bunch of the rows to ClickHouse
async fn flush_to_clickhouse(client: &Client, batch: &mut Vec<DnsRecord>) {
    println!("[ClickHouse] writing a batch of {} logs...", batch.len());

    // create an insert session via the driver interface
    if let Ok(mut inserter) = client.insert("dns_telemetry") {
        for record in batch.iter() {
            if let Err(e) = inserter.write(record).await {
                eprintln!("[ClickHouse] record preparation error: {:?}", e);
                return;
            }
        }
        if let Err(e) = inserter.end().await {
            eprintln!("[ClickHouse] batch commit error: {:?}", e);
        }
    }

    batch.clear();
}


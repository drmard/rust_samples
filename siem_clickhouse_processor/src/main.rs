use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clickhouse::Row;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::instant::Instant;
use tracing::{error, info, warn};
use uuid::Uuid;

// --- SIEM event data model ---
#[derive(Debug, Clone, Serialize, Deserialize, Row)]
pub struct SiemEvent {
    #[serde(with = "clickhouse::serde::uuid")]
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub severity: String,
    pub message: String,
}

// --- Processing architecture configuration ---
struct Config {
    max_batch_size: usize,
    batch_timeout: Duration,
    wal_path: String,
}

// --- Data recording layer (ClickHouse Writer) ---
struct ClickHouseWriter {
    client: clickhouse::Client,
    wal_path: String,
}

impl ClickHouseWriter {
    pub fn new(client: clickhouse::Client, wal_path: String) -> Self {
        Self { client, wal_path }
    }

    // Method for reliable batch recording
    pub async fn write_batch(&self, batch: Vec<SiemEvent>) {
        if batch.is_empty() {
            return;
        }

        info!("Attempt to write {} events to ClickHouse ..", batch.len());

        let mut insert = match self.client.insert("siem_events") {
            Ok(ins) => ins,
            Err(e) => {
                error!("ClickHouse insert initialization error: {:?}", e);
                let _ = self.dump_to_wal(&batch).await;
                return;
            }
        };

        let mut failed = false;
        for event in &batch {
            if let Err(e) = insert.write(event).await {
                error!("String validation error for ClickHouse: {:?}", e);

                failed = true;
                break;
            }
        }

        if !failed {
            if let Err(e) = insert.end().await {
                error!("Batch commit error in ClickHouse: {:?}", e);
                failed = true;
            } else {
                info!("A batch of {} events has been successfully written", batch.len());
            }
        }

        // If the write fails due to a network or DBMS crash -> save the data to the WAL
        if failed {
            warn!("ClickHouse failure. Redirecting batch to local WAL ..");

            if let Err(err) = self.dump_to_wal(&batch).await {
                error!("CRITICAL ERROR: Failed to save WAL to disk! Data lost: {:?}", err);
            }
        }
    }

    // saving data to disk in the event of a crash
    async fn dump_to_wal(&self, batch: &[SiemEvent]) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.wal_path)
            .await
            .context("Could not open file WAL")?;

        for event in batch {
            let serialized = serde_json::to_string(event)?;
            file.write_all(serialized.as_bytes()).await?;
            file.write_all(b"\n").await?;
        }
        file.flush().await?;
        warn!("The batch has been successfully saved to a local file {}", self.wal_path);

        Ok(())
    }
}

struct BatchManager {
    config: Config,
    rx: mpsc::Receiver<SiemEvent>,
    writer: Arc<ClickHouseWriter>,
}

impl BatchManager {
    pub fn new(config: Config, rx: mpsc::Receiver<SiemEvent>, writer: Arc<ClickHouseWriter>) -> Self {
        Self { config, rx, writer }
    }

    pub async fn run(mut self) {
        let mut buffer = Vec::with_capacity(self.config.max_batch_size);
        let sleep = tokio::time::sleep(self.config.batch_timeout);
        tokio::pin!(sleep);

        loop {
            tokio::select! {
                // Receiving a new event from the channel
                maybe_event = self.rx.recv() => {
                    match maybe_event {
                        Some(event) => {
                            buffer.push(event);

                            // If the buffer is full, flush it immediately
                            if buffer.len() >= self.config.max_batch_size {
                                let batch_to_send = std::mem::replace(&mut buffer, Vec::with_capacity(self.config.max_batch_size));
                                let writer_clone = self.writer.clone();
                               
                                // starting the recording asynchronously so as not to block reading logs from the channel
                                tokio::spawn(async move {
                                    writer_clone.write_batch(batch_to_send).await;
                                });
                               
                                // Resetting the batch wait timer
                                sleep.as_mut().reset(Instant::now() + self.config.batch_timeout);
                            }
                        }

                        None => {
                            // Channel closed (server shutting down) — flushing remaining data
                            if !buffer.is_empty() {
                                info!("The channel is closed; we are flushing the final batch of size {} ..", buffer.len());
                                self.writer.write_batch(buffer).await;
                            }
                            break;
                        }
                    }
                }

                // Batch accumulation timeout expiration
                _ = &mut sleep => {
                    if !buffer.is_empty() {
                        let batch_to_send = std::mem::replace(&mut buffer, Vec::with_capacity(self.config.max_batch_size));
                        let writer_clone = self.writer.clone();
                       
                        tokio::spawn(async move {
                            writer_clone.write_batch(batch_to_send).await;
                        });
                    }

                    // restarting the timer in any case
                    sleep.as_mut().reset(Instant::now() + self.config.batch_timeout);
                }
            }
        }

        info!("The batching actor has successfully completed its work");
    }
}

// --- Load Generator (SIEM Data Source Simulation) ---
async fn simulate_siem_traffic(tx: mpsc::Sender<SiemEvent>) {
    let severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    let types = ["Auth_Failure", "Malware_Detected", "Port_Scan", "Data_Exfiltration"];
    let mut counter = 0;

    loop {
        counter += 1;
        let event = SiemEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: types[counter % types.len()].to_string(),
            source_ip: format!("192.168.1.{}", counter % 254),
            destination_ip: "10.0.0.1".to_string(),
            severity: severities[counter % severities.len()].to_string(),
            message: format!("SIEM alert log sequence id: {}", counter),
        };

        if tx.send(event).await.is_err() {

            // If the channel is full or closed, we exit(The backpressure pattern)
            warn!("The channel receiver is overloaded or closed. Stopping generation");
            break;
        }

        // We pause every 15 events, triggering the batch via a timeout
        if counter % 15 == 0 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        } else {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        if counter >= 50 {
            info!("Traffic simulation complete. 50 events generated");
            break;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {

    // Logging initialization
    tracing_subscriber::fmt::init();

    info!("Launching an asynchronous SIEM log processor ..");

    let clickhouse_client = clickhouse::Client::default().with_url("http://localhost:8123");
   
    let config = Config {
        max_batch_size: 20,                       // Reset every 20 lines
        batch_timeout: Duration::from_secs(1),    // Or once a second
        wal_path: "siem_corrupted_events.wal".to_string(),
    };

    // Buffered channel with a capacity of 100 elements (Backpressure anchor)
    let (tx, rx) = mpsc::channel::<SiemEvent>(100);

    let writer = Arc::new(ClickHouseWriter::new(clickhouse_client, config.wal_path.clone()));
    let batch_manager = BatchManager::new(config, rx, writer);

    // Batch manager launch point
    let manager_handle = tokio::spawn(async move {
        batch_manager.run().await;
    });

    // Log generator launch point
    let traffic_handle = tokio::spawn(async move {
        simulate_siem_traffic(tx).await;
    });

    // waiting the completion of the processes
    let _ = tokio::join!(traffic_handle, manager_handle);

    info!("SIEM service has been successfully stopped");

    Ok(())
}

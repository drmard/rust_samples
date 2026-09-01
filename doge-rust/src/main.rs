use sha2::{Sha256, Digest};
use std::time::SystemTime;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;

const DIFFICULTY: usize = 4;
const MINING_REWARD: f64 = 50.0;

#[derive(Serialize, Deserialize, Debug, Clone)]
enum Message {
    NewTransaction(Transaction),
    NewBlock(Block),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub sender: String,                 // sender's hexadecimal public key
    pub receiver: String,               // recipient's hexadecimal public key
    pub signature: Option<Vec<u8>>,     // digital signature of transaction data
}

impl Transaction {
    pub fn new(sender: String, receiver: String, amount: f64) -> Self {
        Transaction { sender, receiver, amount, signature: None }
    }

    // Hashing transaction data for signing/verification
    pub fn calculate_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        let input = format!("{}{}{}", self.sender, self.receiver, self.amount);
        hasher.update(input.as_bytes());
        hasher.finalize().to_vec()
    }

    // Signing a transaction with a private key
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let msg = self.calculate_hash();
        let signature: Signature = signing_key.sign(&msg);
        self.signature = Some(signature.to_bytes().to_vec());
    }

    // signature verification using the sender's public key
    pub fn verify_signature(&self) -> bool {

        // system transactions (miner reward) do not require a signature
        if self.sender == "SYSTEM" {
            return true;
        }

        let sig_bytes = match &self.signature {
            Some(bytes) => bytes,
            None => return false,
        };

        // recovering the public key from the address hex string
        let public_key_bytes = match hex::decode(&self.sender) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes.try_into().unwrap_or([0; 32])) {
            Ok(key) => key,
            Err(_) => return false,
        };

        let signature = match Signature::from_bytes(&sig_bytes.clone().try_into().unwrap_or([0; 64])) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        let msg = self.calculate_hash();
        verifying_key.verify(&msg, &signature).is_ok()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub index: u32,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub hash: String,
    pub nonce: u64,
}

impl Block {
    pub fn new(index: u32, transactions: Vec<Transaction>, previous_hash: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut block = Block {
            index,
            timestamp,
            transactions,
            previous_hash,
            hash: String::new(),
            nonce: 0,
        };

        block.hash = block.calculate_hash();
        block
    }

    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        let tx_data = serde_json::to_string(&self.transactions).unwrap();
        let input = format!("{}{}{}{}{}", self.index, self.timestamp, tx_data, self.previous_hash, self.nonce);
        hasher.update(input.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn mine(&mut self, difficulty: usize) {
        let target = "0".repeat(difficulty);
        while !self.hash.starts_with(&target) {
            self.nonce += 1;
            self.hash = self.calculate_hash();
        }

        println!("Block mined! Nonce: {}, Hash: {}", self.nonce, self.hash);
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    pub pending_transactions: Vec<Transaction>,
}

impl Blockchain {
    pub fn new() -> Self {
        let mut blockchain = Blockchain {
            chain: Vec::new(),
            pending_transactions: Vec::new(),
        };
        blockchain.create_genesis_block();
        blockchain
    }

    fn create_genesis_block(&mut self) {
        let genesis_tx = vec![Transaction::new("SYSTEM".to_string(), "Genesis_Receiver".to_string(), 1000000.0)];
        let mut genesis_block = Block::new(0, genesis_tx, "0".to_string());
        genesis_block.mine(DIFFICULTY);
        self.chain.push(genesis_block);
    }

    pub fn get_latest_block(&self) -> &Block {
        self.chain.last().unwrap()
    }

    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<(), &'static str> {
        if transaction.amount <= 0.0 {
            return Err("The transaction amount must be greater than 0");
        }

        if !transaction.verify_signature() {
            return Err("Critical error: Transaction digital signature is invalid!");
        }

        self.pending_transactions.push(transaction);

        Ok(())
    }

    pub fn mine_pending_transactions(&mut self, miner_address: String) -> Block {
        let reward_tx = Transaction::new("SYSTEM".to_string(), miner_address, MINING_REWARD);
        let mut block_txs = vec![reward_tx];
        block_txs.extend(self.pending_transactions.clone());

        let last_block = self.get_latest_block();
        let mut new_block = Block::new(last_block.index + 1, block_txs, last_block.hash.clone());

        println!("Mining a new block {}...", new_block.index);

        new_block.mine(DIFFICULTY);

        self.chain.push(new_block.clone());
        self.pending_transactions.clear();

        new_block
    }

    pub fn add_block_from_network(&mut self, block: Block) -> Result<(), &'static str> {
        let last_block = self.get_latest_block();
        if block.previous_hash != last_block.hash {
            return Err("The previous hash does not match ..");
        }

        if block.hash != block.calculate_hash() {
            return Err("Block hash is corrupted ..");
        }

        self.chain.push(block);
        self.pending_transactions.clear();

        Ok(())
    }
}

// simple module for working with hex strings
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
    pub fn decode(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }
}

type SharedBlockchain = Arc<Mutex<Blockchain>>;
type PeerList = Arc<Mutex<Vec<SocketAddr>>>;

async fn handle_connection(mut stream: TcpStream, bc: SharedBlockchain) {
    let mut buffer = vec![0; 4096];
    if let Ok(n) = stream.read(&mut buffer).await {
        if n == 0 { return; }
        if let Ok(msg) = serde_json::from_slice::<Message>(&buffer[..n]) {
            let mut blockchain = bc.lock().await;
            match msg {

                Message::NewTransaction(tx) => {
                    println!("received a transaction from the network for the amount of {} DOGE", tx.amount);
                    if let Err(e) = blockchain.add_transaction(tx) {
                        println!("network transaction rejected: {}", e);
                    }
                }

                Message::NewBlock(block) => {
                    println!("new block {} received from the network", block.index);
                    if let Err(e) = blockchain.add_block_from_network(block) {
                        println!("network block rejected: {}", e);
                    }
                }
            }
        }
    }
}

async fn broadcast_message(peers: PeerList, msg: Message) {
    let payload = serde_json::to_vec(&msg).unwrap();
    let peer_addresses = peers.lock().await;
    for peer in peer_addresses.iter() {
        if let Ok(mut stream) = TcpStream::connect(peer).await {
            let _ = stream.write_all(&payload).await;
        }
    }
}

#[tokio::main]
async fn main() {

    // Key generation for users
    let mut csprng = OsRng;

    let user1_signing_key = SigningKey::generate(&mut csprng);
    let user1_public_key = user1_signing_key.verifying_key();
    let user1_addr = hex::encode(user1_public_key.as_bytes());

    let user2_signing_key = SigningKey::generate(&mut csprng);
    let user2_addr = hex::encode(user2_signing_key.verifying_key().as_bytes());

    println!("keys generated ..");
    println!("address user1 (ED25519 Pub): {}", user1_addr);
    println!("address user2 (ED25519 Pub): {}", user2_addr);

    // node initialization
    let blockchain = Arc::new(Mutex::new(Blockchain::new()));
    let peers: PeerList = Arc::new(Mutex::new(vec![]));

    let server_addr = "127.0.0.1:8080";
    let peer_addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
    peers.lock().await.push(peer_addr);

    // starting the node's TCP server on port 8080 in the background via a tokio thread
    let bc_clone = Arc::clone(&blockchain);
    tokio::spawn(async move {
        let listener = TcpListener::bind(server_addr).await.unwrap();
        println!("network node is running on {}", server_addr);
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let bc_local = Arc::clone(&bc_clone);
                tokio::spawn(handle_connection(stream, bc_local));
            }
        }
    });

    // allow the server time to initialize
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // WORKING WITH TRANSACTION
    println!("\ncreating and signing a transaction...");
    let mut tx = Transaction::new(user1_addr.clone(), user2_addr.clone(), 100.0);

    // user1 signs the transaction with their private key
    tx.sign(&user1_signing_key);

    // adding transaction locally
    {
        let mut bc = blockchain.lock().await;
        bc.add_transaction(tx.clone()).unwrap();
    }

    // broadcasting the transaction to the network
    broadcast_message(Arc::clone(&peers), Message::NewTransaction(tx)).await;

    // Mining and Block Broadcasting
    let mined_block = {
        let mut bc = blockchain.lock().await;
        bc.mine_pending_transactions(user1_addr.clone())
    };

    // send mined block over the network
    broadcast_message(Arc::clone(&peers), Message::NewBlock(mined_block)).await;
    println!("\nThe demonstration is complete. Network streams and cryptography functioned as expected");
}

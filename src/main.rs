mod crypto;
mod discovery;
mod network;
mod protocol;

use anyhow::Result;
use clap::Parser;
use crypto::KeyStore;
use discovery::DiscoveryManager;
use network::Node;
use protocol::EncryptedMessage;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 0)]
    port: u16,

    /// Optional specific peer to connect to on startup (IP:PORT)
    #[arg(short, long)]
    connect: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;

    // 1. Initialize Crypto Identity
    let keystore = KeyStore::new()?;
    let identity = keystore.load_or_generate()?;
    println!("My Identity (Ed25519 PubKey): {:?}", identity.public_key());

    // 2. Initialize the P2P Node
    // Channel for the UI to receive messages from the network layer
    let (message_tx, mut message_rx) = mpsc::channel(100);

    let node = Node::new(identity.clone(), bind_addr, message_tx)?;
    let node = Arc::new(node);

    // 3. Start the Node Listener
    tokio::spawn(Arc::clone(&node).start_listening());

    // 4. Initialize Local Peer Discovery (mDNS)
    // Extract actual bound port if 0 was passed
    let actual_port = args.port; // Needs refining to grab OS assigned port if 0, hardcoded for now or use specific ports.

    let discovery = DiscoveryManager::new(hex::encode(identity.public_key().0))?;

    if actual_port > 0 {
        if let Err(e) = discovery.start_broadcasting(actual_port) {
            error!("Failed to start mDNS broadcast: {}", e);
        }
    }

    let (peer_tx, mut peer_rx) = mpsc::channel(50);
    if let Err(e) = discovery.start_listening(peer_tx) {
        error!("Failed to start mDNS browsing: {}", e);
    }

    // Attempt initial manual connection if requested
    if let Some(peer_addr) = args.connect {
        let node_clone = Arc::clone(&node);
        tokio::spawn(async move {
            info!("Attempting manual connection to {}", peer_addr);
            if let Err(e) = node_clone.connect_to_peer(peer_addr).await {
                error!("Failed to connect to {}: {}", peer_addr, e);
            }
        });
    }

    // 5. Event Loop (Terminal UI + Network Events)
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin).lines();

    println!("========================================");
    println!("P2P Encrypted Chat Started");
    println!("Type a message and press Enter to broadcast.");
    println!("========================================");

    loop {
        tokio::select! {
            // Handle Keyboard Input
            line_result = reader.next_line() => {
                match line_result {
                    Ok(Some(line)) if !line.trim().is_empty() => {
                        // Broadcast message to all connected peers
                        node.broadcast_message(line.as_bytes()).await;
                        println!("You: {}", line);
                    }
                    Ok(None) => break, // EOF (Ctrl+D)
                    Err(e) => {
                        error!("Stdin err: {}", e);
                        break;
                    }
                    _ => {}
                }
            }

            // Handle Incoming Network Messages
            Some((sender_pubkey, msg_bytes)) = message_rx.recv() => {
                if let Ok(msg_str) = String::from_utf8(msg_bytes) {
                    println!("\n[{}] says: {}", hex::encode(&sender_pubkey.0[..4]), msg_str);
                }
            }

            // Handle newly discovered peers via mDNS
            Some(discovered_addr) = peer_rx.recv() => {
                info!("Discovered peer on local network at {}", discovered_addr);
                let node_clone = Arc::clone(&node);
                tokio::spawn(async move {
                    if let Err(e) = node_clone.connect_to_peer(discovered_addr).await {
                        error!("Failed auto-connect to mDNS peer {}: {}", discovered_addr, e);
                    }
                });
            }
        }
    }

    discovery.shutdown();
    Ok(())
}

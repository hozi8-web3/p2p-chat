use crate::crypto::{derive_session_keys, generate_ephemeral_keypair, Identity, PublicKey};
use crate::network::config::NetworkConfig;
use crate::protocol::{EncryptedMessage, HandshakePayload};
use anyhow::{anyhow, Result};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Represents an established and cryptographically verified peer connection.
pub struct PeerConnection {
    pub _identity: PublicKey,
    pub tx_key: [u8; 32],
    pub _rx_key: [u8; 32],
    pub connection: Connection,
    /// We keep an incremental nonce count to prevent replay attacks.
    pub last_tx_nonce: u64,
}

pub struct Node {
    pub identity: Identity,
    endpoint: Endpoint,
    /// Thread-safe map of active peer connections, keyed by their Ed25519 Public Key.
    peers: Arc<Mutex<HashMap<[u8; 32], Arc<Mutex<PeerConnection>>>>>,
    message_tx: mpsc::Sender<(PublicKey, Vec<u8>)>,
}

impl Node {
    pub fn new(
        identity: Identity,
        bind_addr: SocketAddr,
        message_tx: mpsc::Sender<(PublicKey, Vec<u8>)>,
    ) -> Result<Self> {
        let config = NetworkConfig::bind(bind_addr)?;

        Ok(Self {
            identity,
            endpoint: config.endpoint,
            peers: Arc::new(Mutex::new(HashMap::new())),
            message_tx,
        })
    }

    /// Spawns the main network event loop to listen for incoming connections.
    pub async fn start_listening(self: Arc<Self>) {
        let local_addr = self.endpoint.local_addr().unwrap();
        println!("Node listening on {}", local_addr);

        while let Some(incoming) = self.endpoint.accept().await {
            let node_clone = Arc::clone(&self);

            tokio::spawn(async move {
                if let Ok(connection) = incoming.await {
                    if let Err(e) = node_clone.handle_incoming_connection(connection).await {
                        eprintln!("Incoming connection failed: {}", e);
                    }
                }
            });
        }
    }

    /// Connects to a remote peer via SocketAddr and performs the cryptographic handshake.
    pub async fn connect_to_peer(self: Arc<Self>, addr: SocketAddr) -> Result<()> {
        // "localhost" is a dummy server_name because our server verifier blindly accepts it.
        // The real authentication happens via our Application-Layer Handshake.
        let connection = self.endpoint.connect(addr, "localhost")?.await?;

        // Open a bi-directional stream for the handshake
        let (send, recv) = connection.open_bi().await?;

        self.perform_handshake_as_initiator(connection, send, recv)
            .await?;
        Ok(())
    }

    async fn handle_incoming_connection(self: Arc<Self>, connection: Connection) -> Result<()> {
        // Accept the first bi-directional stream for the handshake
        let (send, recv) = connection.accept_bi().await?;
        
        self.perform_handshake_as_responder(connection, send, recv).await?;
        Ok(())
    }

    async fn perform_handshake_as_initiator(
        self: Arc<Self>,
        connection: Connection,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        // 1. Generate our ephemeral DH parameters
        let (my_secret, my_public) = generate_ephemeral_keypair();

        // 2. Create the signed payload guaranteeing this identity owns the ephemeral key
        let payload = HandshakePayload::new(&self.identity, &my_public);
        let serialized_payload = bincode::serialize(&payload)?;

        // 3. Send our payload (Length-prefixed for basic framing)
        let len = serialized_payload.len() as u32;
        send.write_all(&len.to_be_bytes()).await?;
        send.write_all(&serialized_payload).await?;

        // 4. Receive Bob's payload
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let their_len = u32::from_be_bytes(len_buf) as usize;

        let mut their_payload_buf = vec![0u8; their_len];
        recv.read_exact(&mut their_payload_buf).await?;

        let their_payload: HandshakePayload = bincode::deserialize(&their_payload_buf)?;

        // 5. Verify Bob's signature
        if !their_payload.verify() {
            return Err(anyhow!("Invalid peer signature during handshake"));
        }

        let their_public_dh = their_payload.get_ephemeral_key();

        // 6. Compute HKDF derived keys
        let (tx_key, rx_key) = derive_session_keys(my_secret, &their_public_dh, true);

        // 7. Register Peer
        self.register_peer(
            their_payload.identity_pub_key,
            tx_key,
            rx_key,
            connection,
        )
        .await;

        Ok(())
    }

    async fn perform_handshake_as_responder(
        self: Arc<Self>,
        connection: Connection,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        // Responder does the opposite sequence: read first, then write.

        // 1. Read Alice's payload
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let their_len = u32::from_be_bytes(len_buf) as usize;

        let mut their_payload_buf = vec![0u8; their_len];
        recv.read_exact(&mut their_payload_buf).await?;

        let their_payload: HandshakePayload = bincode::deserialize(&their_payload_buf)?;

        if !their_payload.verify() {
            return Err(anyhow!("Invalid peer signature during handshake"));
        }

        let their_public_dh = their_payload.get_ephemeral_key();

        // 2. Generate our DH
        let (my_secret, my_public) = generate_ephemeral_keypair();

        let payload = HandshakePayload::new(&self.identity, &my_public);
        let serialized_payload = bincode::serialize(&payload)?;

        // 3. Send Bob's payload back
        let len = serialized_payload.len() as u32;
        send.write_all(&len.to_be_bytes()).await?;
        send.write_all(&serialized_payload).await?;

        // 4. Compute HKDF keys
        let (tx_key, rx_key) = derive_session_keys(my_secret, &their_public_dh, false);

        // 5. Register Peer
        self.register_peer(
            their_payload.identity_pub_key,
            tx_key,
            rx_key,
            connection,
        )
        .await;

        Ok(())
    }

    async fn register_peer(
        self: Arc<Self>,
        peer_identity: PublicKey,
        tx_key: [u8; 32],
        rx_key: [u8; 32],
        connection: Connection,
    ) {
        println!(
            "Successfully established secure session with peer {:?}",
            peer_identity
        );

        let peer_conn = Arc::new(Mutex::new(PeerConnection {
            _identity: peer_identity.clone(),
            tx_key,
            _rx_key: rx_key,
            connection: connection.clone(),
            last_tx_nonce: 0,
        }));

        self.peers
            .lock()
            .await
            .insert(peer_identity.0, Arc::clone(&peer_conn));

        // Spawn a dedicated message listener for this established connection
        let node_clone = Arc::clone(&self);
        tokio::spawn(async move {
            node_clone
                .listen_for_messages(peer_identity, rx_key, connection)
                .await;
        });
    }

    async fn listen_for_messages(
        self: Arc<Self>,
        peer_identity: PublicKey,
        rx_key: [u8; 32],
        connection: Connection,
    ) {
        // Continuously accept new unidirectional streams meant for text messages
        while let Ok(mut recv) = connection.accept_uni().await {
            let node_clone = Arc::clone(&self);
            let peer_id_clone = peer_identity.clone();
            
            tokio::spawn(async move {
                // Read 4-byte length prefix
                let mut len_buf = [0u8; 4];
                if recv.read_exact(&mut len_buf).await.is_err() {
                    return;
                }

                let len = u32::from_be_bytes(len_buf) as usize;

                // Limit message size to something sane (e.g. 10MB) to prevent OOM DoS
                if len > 10 * 1024 * 1024 {
                    eprintln!("Message too large from {:?}", peer_id_clone);
                    return;
                }

                let mut msg_buf = vec![0u8; len];
                if recv.read_exact(&mut msg_buf).await.is_err() {
                    return;
                }

                // Deserialize EncryptedMessage format
                match bincode::deserialize::<EncryptedMessage>(&msg_buf) {
                    Ok(encrypted_msg) => {
                        // Authenticate and Decrypt
                        match encrypted_msg.decrypt(&rx_key, &peer_id_clone.0) {
                            Ok(plaintext) => {
                                // Forward the decrypted message to the app's UI/Event-loop
                                let _ = node_clone
                                    .message_tx
                                    .send((peer_id_clone.clone(), plaintext))
                                    .await;
                            }
                            Err(e) => {
                                eprintln!(
                                    "AEAD Decryption failed for message from {:?}: {}",
                                    peer_id_clone, e
                                );
                            }
                        }
                    }
                    Err(e) => eprintln!("Malformed message packet from {:?}: {}", peer_id_clone, e),
                }
            });
        }
        
        println!("Connection with {:?} closed.", peer_identity);
        self.peers.lock().await.remove(&peer_identity.0);
    }

    /// Broadcasts a message to all connected and verified peers.
    pub async fn broadcast_message(&self, message: &[u8]) {
        let peers_map = self.peers.lock().await;

        for (pubkey_bytes, peer_mtx) in peers_map.iter() {
            let mut peer = peer_mtx.lock().await;

            peer.last_tx_nonce += 1;

            // Construct a unique 12-byte nonce (8 bytes counter + 4 bytes random helps prevent collision if state is lost)
            let mut nonce = [0u8; 12];
            nonce[0..8].copy_from_slice(&peer.last_tx_nonce.to_le_bytes());
            rand::thread_rng().fill_bytes(&mut nonce[8..12]);

            // Encrypt using our identity as AAD.
            // The receiver expects the AAD to be the sender's (our) public key.
            match EncryptedMessage::encrypt(
                &peer.tx_key,
                &nonce,
                message,
                &self.identity.public_key().0,
            ) {
                Ok(encrypted_msg) => {
                    if let Ok(serialized) = bincode::serialize(&encrypted_msg) {
                        // Open a new quick unidirectional stream for sending this message
                        if let Ok(mut send) = peer.connection.open_uni().await {
                            let len = serialized.len() as u32;
                            let _ = send.write_all(&len.to_be_bytes()).await;
                            let _ = send.write_all(&serialized).await;
                        }
                    }
                }
                Err(e) => eprintln!("Failed to encrypt message for {:?}: {}", pubkey_bytes, e),
            }
        }
    }
}

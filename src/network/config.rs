use anyhow::Result;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;

/// In a pure P2P network without a PKI, we rely on our cryptographic handshake
/// (Ed25519 identity + X25519 DH) for authentication. Therefore, the TLS layer
/// provided by QUIC is mostly to establish the initial secure transport.
/// We use ephemeral, self-signed certificates for this layer to bootstrap QUIC.

pub struct NetworkConfig {
    pub endpoint: Endpoint,
}

impl NetworkConfig {
    /// Binds a QUIC endpoint to the given address.
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let (server_config, client_config) = Self::generate_configs()?;

        let mut endpoint = Endpoint::server(server_config, addr)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    fn generate_configs() -> Result<(ServerConfig, ClientConfig)> {
        // Generate a self-signed cert just for the QUIC/TLS layer.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;

        let cert_der = rustls::Certificate(cert.cert.der().to_vec());
        let private_key = rustls::PrivateKey(cert.key_pair.serialize_der());

        let cert_chain = vec![cert_der];

        // Ensure we bypass standard certificate validation since this is P2P.
        // We will authenticate peers using our own Ed25519 signatures inside the QUIC stream.
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        // We need to support ALPN
        client_crypto.alpn_protocols = vec![b"p2p-chat-v1".to_vec()];

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        server_crypto.alpn_protocols = vec![b"p2p-chat-v1".to_vec()];

        let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_concurrent_bidi_streams(1024u32.into());

        let mut client_config = ClientConfig::new(Arc::new(client_crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        client_config.transport_config(Arc::new(transport));

        Ok((server_config, client_config))
    }
}

/// A dummy verifier that accepts any server certificate.
/// WARNING: This is only secure because our custom P2P handshake
/// runs INSIDE the established QUIC connection to verify Ed25519 identities.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

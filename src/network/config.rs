use anyhow::Result;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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
        
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let private_key_der = PrivateKeyDer::from(private_key);

        let cert_chain = vec![cert_der];

        // Ensure we bypass standard certificate validation since this is P2P.
        // We will authenticate peers using our own Ed25519 signatures inside the QUIC stream.
        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
            
        // We need to support ALPN
        client_crypto.alpn_protocols = vec![b"p2p-chat-v1".to_vec()];

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key_der)?;
            
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

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

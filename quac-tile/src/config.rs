use std::sync::Arc;

pub use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Configuration for a QUIC server endpoint.
#[derive(Clone)]
pub struct ServerConfig(pub(crate) Arc<quinn_proto::ServerConfig>);

/// Configuration for a QUIC client endpoint.
pub struct ClientConfig(pub(crate) Arc<quinn_proto::ClientConfig>);

/// Per-endpoint configuration (MTU, connection IDs, etc.)
#[derive(Clone)]
pub struct EndpointConfig(pub(crate) Arc<quinn_proto::EndpointConfig>);

impl ServerConfig {
    pub fn new(inner: Arc<quinn_proto::ServerConfig>) -> Self {
        Self(inner)
    }

    pub fn into_inner(self) -> Arc<quinn_proto::ServerConfig> {
        self.0
    }

    pub fn with_transport_config(self, tc: quinn_proto::TransportConfig) -> Self {
        let mut inner = (*self.0).clone();
        inner.transport = Arc::new(tc);
        Self(Arc::new(inner))
    }

    /// Build a server config from a certificate chain and private key.
    ///
    /// Uses ring-backed TLS (rustls with ring provider). Sets ALPN to `alpn`.
    pub fn with_single_cert(
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        alpn: &[&[u8]],
    ) -> Result<Self, rustls::Error> {
        use quinn_proto::crypto::rustls::QuicServerConfig;
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;
        tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let quic = QuicServerConfig::try_from(tls)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        let sc = quinn_proto::ServerConfig::with_crypto(Arc::new(quic));
        Ok(Self::new(Arc::new(sc)))
    }
}

impl ClientConfig {
    pub fn new(inner: quinn_proto::ClientConfig) -> Self {
        Self(Arc::new(inner))
    }

    pub(crate) fn inner(&self) -> quinn_proto::ClientConfig {
        (*self.0).clone()
    }
}

impl EndpointConfig {
    pub fn new(inner: quinn_proto::EndpointConfig) -> Self {
        Self(Arc::new(inner))
    }
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self(Arc::new(quinn_proto::EndpointConfig::default()))
    }
}

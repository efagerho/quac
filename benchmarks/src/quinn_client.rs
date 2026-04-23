//! Shared Quinn **insecure** client endpoint for local `quic_pong` / `quic_pong_quinn` servers
//! (self-signed `localhost`). **MITM unsafe** — bench / smoke tools only.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

/// Quinn client bound to an ephemeral UDP port, with TLS verification disabled (local dev only).
pub fn make_insecure_client_endpoint() -> io::Result<Endpoint> {
    make_endpoint(false)
}

/// Like [`make_insecure_client_endpoint`] but with session resumption disabled so every
/// connection performs a full TLS 1.3 handshake (useful for benchmarking handshake throughput).
pub fn make_insecure_client_endpoint_no_resumption() -> io::Result<Endpoint> {
    make_endpoint(true)
}

fn make_endpoint(disable_resumption: bool) -> io::Result<Endpoint> {
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    if disable_resumption {
        tls.resumption = rustls::client::Resumption::disabled();
    }
    let crypto = Arc::new(
        QuicClientConfig::try_from(tls).map_err(|e| io::Error::other(e.to_string()))?,
    );
    endpoint.set_default_client_config(ClientConfig::new(crypto));
    Ok(endpoint)
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

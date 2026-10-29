//! dpop-vs-mtls-bench: measured cost of sender-constrained access tokens.
//! DPoP (RFC 9449, ES256 or EdDSA proofs) vs mTLS certificate-bound tokens
//! (RFC 8705) vs plain bearer tokens, served by axum over rustls on
//! loopback, with keep-alive and new-connection-per-request patterns.

pub mod certs;
pub mod client;
pub mod counting;
pub mod server;
pub mod token;

/// Install the ring crypto provider once.
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

//! Test PKI: one CA, one server certificate for `localhost`, two client
//! certificates (the second one is used for the wrong-certificate control).

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// DER material for one end entity.
pub struct Leaf {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

/// The whole PKI.
pub struct Pki {
    pub ca: Vec<u8>,
    pub server: Leaf,
    pub client: Leaf,
    pub other_client: Leaf,
}

fn leaf(name: &str, issuer: &Issuer<'_, KeyPair>) -> Leaf {
    let kp = KeyPair::generate().expect("keygen");
    let p = CertificateParams::new(vec![name.to_string()]).expect("params");
    let c = p.signed_by(&kp, issuer).expect("sign");
    Leaf {
        cert: c.der().to_vec(),
        key: kp.serialize_der(),
    }
}

/// Generate a fresh PKI (ECDSA P-256 keys).
pub fn generate() -> Pki {
    let ca_kp = KeyPair::generate().expect("keygen");
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = p.self_signed(&ca_kp).expect("ca");
    let ca_der = ca.der().to_vec();
    let issuer = Issuer::new(p, ca_kp);
    Pki {
        ca: ca_der,
        server: leaf("localhost", &issuer),
        client: leaf("client-a", &issuer),
        other_client: leaf("client-b", &issuer),
    }
}

/// rustls types for a leaf.
pub fn chain_and_key(l: &Leaf) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    (
        vec![CertificateDer::from(l.cert.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(l.key.clone())),
    )
}

/// base64url SHA-256 of a DER certificate (`x5t#S256`, RFC 8705 3.1).
pub fn x5t_s256(der: &[u8]) -> String {
    use base64::Engine;
    use sha2::Digest;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(der))
}

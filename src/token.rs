//! Access tokens (HS256 JWT with a `cnf` claim) and DPoP proofs.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Key shared by the token issuer and the resource server.
pub const AS_KEY: &[u8; 32] = b"dpop-vs-mtls bench as hmac key 1";

/// Confirmation method carried by an access token.
#[derive(Clone, Debug, PartialEq)]
pub enum Cnf {
    None,
    Jkt(String),
    X5t(String),
}

fn hs256(input: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(AS_KEY).expect("key");
    m.update(input);
    m.finalize().into_bytes().to_vec()
}

/// Issue an access token.
pub fn issue(sub: &str, cnf: &Cnf, exp: u64) -> String {
    let mut c =
        json!({"iss": "https://as.example", "sub": sub, "aud": "https://localhost", "exp": exp});
    match cnf {
        Cnf::None => {}
        Cnf::Jkt(t) => c["cnf"] = json!({"jkt": t}),
        Cnf::X5t(t) => c["cnf"] = json!({"x5t#S256": t}),
    }
    let si = format!(
        "{}.{}",
        B64.encode(r#"{"alg":"HS256","typ":"at+jwt"}"#),
        B64.encode(c.to_string())
    );
    format!("{si}.{}", B64.encode(hs256(si.as_bytes())))
}

/// Verify an access token; returns its confirmation method.
pub fn verify_access(tok: &str, now: u64) -> Result<Cnf, &'static str> {
    let (si, sig) = tok.rsplit_once('.').ok_or("format")?;
    let sig = B64.decode(sig).map_err(|_| "b64")?;
    let mut m = Hmac::<Sha256>::new_from_slice(AS_KEY).expect("key");
    m.update(si.as_bytes());
    m.verify_slice(&sig).map_err(|_| "at-sig")?;
    let p = si.split_once('.').ok_or("format")?.1;
    let c: Value =
        serde_json::from_slice(&B64.decode(p).map_err(|_| "b64")?).map_err(|_| "json")?;
    if c["exp"].as_u64().ok_or("exp")? <= now {
        return Err("expired");
    }
    Ok(if let Some(j) = c["cnf"]["jkt"].as_str() {
        Cnf::Jkt(j.into())
    } else if let Some(x) = c["cnf"]["x5t#S256"].as_str() {
        Cnf::X5t(x.into())
    } else {
        Cnf::None
    })
}

/// DPoP signing key.
pub enum DpopKey {
    Es256(p256::ecdsa::SigningKey),
    EdDsa(ed25519_dalek::SigningKey),
}

impl DpopKey {
    /// Public JWK as a JSON value.
    pub fn jwk(&self) -> Value {
        match self {
            DpopKey::Es256(k) => {
                let ep = p256::ecdsa::VerifyingKey::from(k).to_encoded_point(false);
                json!({"kty":"EC","crv":"P-256","x":B64.encode(ep.x().unwrap()),"y":B64.encode(ep.y().unwrap())})
            }
            DpopKey::EdDsa(k) => {
                json!({"kty":"OKP","crv":"Ed25519","x":B64.encode(k.verifying_key().as_bytes())})
            }
        }
    }
    fn alg(&self) -> &'static str {
        match self {
            DpopKey::Es256(_) => "ES256",
            DpopKey::EdDsa(_) => "EdDSA",
        }
    }
    fn sign(&self, m: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        match self {
            DpopKey::Es256(k) => {
                let s: p256::ecdsa::Signature = k.sign(m);
                s.to_bytes().to_vec()
            }
            DpopKey::EdDsa(k) => k.sign(m).to_bytes().to_vec(),
        }
    }
}

/// JWK thumbprint (RFC 7638), base64url SHA-256.
pub fn jkt(jwk: &Value) -> Result<String, &'static str> {
    let canon = match jwk["kty"].as_str() {
        Some("EC") => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk["crv"].as_str().ok_or("jwk")?,
            jwk["x"].as_str().ok_or("jwk")?,
            jwk["y"].as_str().ok_or("jwk")?
        ),
        Some("OKP") => format!(
            r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
            jwk["crv"].as_str().ok_or("jwk")?,
            jwk["x"].as_str().ok_or("jwk")?
        ),
        _ => return Err("kty"),
    };
    Ok(B64.encode(Sha256::digest(canon.as_bytes())))
}

/// Create a DPoP proof for `htm htu` bound to `access_token` (`ath`).
pub fn proof(
    key: &DpopKey,
    jti: &str,
    htm: &str,
    htu: &str,
    iat: u64,
    access_token: &str,
) -> String {
    let h = json!({"typ":"dpop+jwt","alg":key.alg(),"jwk":key.jwk()});
    let ath = B64.encode(Sha256::digest(access_token.as_bytes()));
    let c = json!({"jti":jti,"htm":htm,"htu":htu,"iat":iat,"ath":ath});
    let si = format!(
        "{}.{}",
        B64.encode(h.to_string()),
        B64.encode(c.to_string())
    );
    format!("{si}.{}", B64.encode(key.sign(si.as_bytes())))
}

/// Verified proof data.
pub struct ProofClaims {
    pub jti: String,
    pub jkt: String,
}

/// Verify a DPoP proof (RFC 9449 4.3 checks except jti uniqueness, which
/// the caller does).
pub fn verify_proof(
    p: &str,
    htm: &str,
    htu: &str,
    now: u64,
    window: u64,
    access_token: &str,
) -> Result<ProofClaims, &'static str> {
    let mut it = p.split('.');
    let (h, c, s) = match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(c), Some(s), None) => (h, c, s),
        _ => return Err("format"),
    };
    let hv: Value =
        serde_json::from_slice(&B64.decode(h).map_err(|_| "b64")?).map_err(|_| "json")?;
    if hv["typ"] != "dpop+jwt" {
        return Err("typ");
    }
    let jwk = &hv["jwk"];
    let sig = B64.decode(s).map_err(|_| "b64")?;
    let si = format!("{h}.{c}");
    match hv["alg"].as_str() {
        Some("ES256") => {
            use p256::ecdsa::signature::Verifier;
            let x: [u8; 32] = B64
                .decode(jwk["x"].as_str().ok_or("jwk")?)
                .map_err(|_| "jwk")?
                .try_into()
                .map_err(|_| "jwk")?;
            let y: [u8; 32] = B64
                .decode(jwk["y"].as_str().ok_or("jwk")?)
                .map_err(|_| "jwk")?
                .try_into()
                .map_err(|_| "jwk")?;
            let ep = p256::EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
            let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&ep).map_err(|_| "jwk")?;
            let sg = p256::ecdsa::Signature::from_slice(&sig).map_err(|_| "sig")?;
            vk.verify(si.as_bytes(), &sg).map_err(|_| "sig")?;
        }
        Some("EdDSA") => {
            let x: [u8; 32] = B64
                .decode(jwk["x"].as_str().ok_or("jwk")?)
                .map_err(|_| "jwk")?
                .try_into()
                .map_err(|_| "jwk")?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&x).map_err(|_| "jwk")?;
            let sg = ed25519_dalek::Signature::from_slice(&sig).map_err(|_| "sig")?;
            vk.verify_strict(si.as_bytes(), &sg).map_err(|_| "sig")?;
        }
        _ => return Err("alg"),
    }
    let cv: Value =
        serde_json::from_slice(&B64.decode(c).map_err(|_| "b64")?).map_err(|_| "json")?;
    if cv["htm"] != htm || cv["htu"] != htu {
        return Err("binding");
    }
    let iat = cv["iat"].as_u64().ok_or("iat")?;
    if iat + window < now || iat > now + window {
        return Err("iat");
    }
    let ath = B64.encode(Sha256::digest(access_token.as_bytes()));
    if cv["ath"] != ath.as_str() {
        return Err("ath");
    }
    Ok(ProofClaims {
        jti: cv["jti"].as_str().ok_or("jti")?.to_string(),
        jkt: jkt(jwk)?,
    })
}

/// Unix seconds.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

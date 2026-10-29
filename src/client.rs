//! Scenario runner: builds client TLS configs, opens connections (keep-alive
//! or one per request, with or without TLS session resumption) and measures
//! latency and bytes on the wire.

use crate::certs::{chain_and_key, x5t_s256, Pki};
use crate::counting::{Counters, Counting};
use crate::server::HTU_DPOP;
use crate::token::{self, Cnf, DpopKey};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, HandshakeKind, RootCertStore};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// What authenticates the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    Bearer,
    DpopEs256,
    DpopEdDsa,
    Mtls,
}

/// Connection pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnMode {
    /// One connection for all requests.
    KeepAlive,
    /// New TCP+TLS connection per request, TLS resumption enabled.
    NewResume,
    /// New TCP+TLS connection per request, resumption disabled.
    NewFull,
}

/// One scenario.
#[derive(Clone, Copy, Debug)]
pub struct Scenario {
    pub auth: Auth,
    pub conn: ConnMode,
    pub n: usize,
}

impl Scenario {
    pub fn name(&self) -> String {
        let a = match self.auth {
            Auth::Bearer => "bearer",
            Auth::DpopEs256 => "dpop_es256",
            Auth::DpopEdDsa => "dpop_eddsa",
            Auth::Mtls => "mtls",
        };
        let c = match self.conn {
            ConnMode::KeepAlive => "keepalive",
            ConnMode::NewResume => "newconn_resume",
            ConnMode::NewFull => "newconn_full",
        };
        format!("{a}_{c}")
    }
}

/// Measured outcome.
#[derive(Debug, Default)]
pub struct Outcome {
    pub ok: usize,
    pub failed: usize,
    pub latencies_us: Vec<f64>,
    pub elapsed_s: f64,
    pub bytes: u64,
    pub handshakes: usize,
    pub resumed: usize,
}

impl Outcome {
    pub fn pct(&self, p: f64) -> f64 {
        let mut v = self.latencies_us.clone();
        if v.is_empty() {
            return f64::NAN;
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[((p / 100.0) * (v.len() as f64 - 1.0)).round() as usize]
    }
}

/// Client-side material for the scenarios.
pub struct ClientKit {
    pub roots: Arc<RootCertStore>,
    pub pki_client: (Vec<u8>, Vec<u8>),
    pub bearer_token: String,
    pub mtls_token: String,
    pub es_key: DpopKey,
    pub es_token: String,
    pub ed_key: DpopKey,
    pub ed_token: String,
}

impl ClientKit {
    pub fn new(pki: &Pki, seed: u64) -> Self {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let mut roots = RootCertStore::empty();
        roots.add(pki.ca.clone().into()).expect("ca");
        let exp = token::now() + 3600;
        let es_key = DpopKey::Es256(p256::ecdsa::SigningKey::random(&mut rng));
        let ed_key = DpopKey::EdDsa(ed25519_dalek::SigningKey::generate(&mut rng));
        let es_token = token::issue("alice", &Cnf::Jkt(token::jkt(&es_key.jwk()).unwrap()), exp);
        let ed_token = token::issue("alice", &Cnf::Jkt(token::jkt(&ed_key.jwk()).unwrap()), exp);
        ClientKit {
            roots: Arc::new(roots),
            pki_client: (pki.client.cert.clone(), pki.client.key.clone()),
            bearer_token: token::issue("alice", &Cnf::None, exp),
            mtls_token: token::issue("alice", &Cnf::X5t(x5t_s256(&pki.client.cert)), exp),
            es_key,
            es_token,
            ed_key,
            ed_token,
        }
    }

    /// TLS client config for a scenario.
    pub fn tls(&self, mtls: bool, resume: bool) -> Arc<ClientConfig> {
        crate::init_crypto();
        let b = ClientConfig::builder().with_root_certificates(self.roots.clone());
        let mut c = if mtls {
            let leaf = crate::certs::Leaf {
                cert: self.pki_client.0.clone(),
                key: self.pki_client.1.clone(),
            };
            let (chain, key) = chain_and_key(&leaf);
            b.with_client_auth_cert(chain, key).expect("client cert")
        } else {
            b.with_no_client_auth()
        };
        if !resume {
            c.resumption = Resumption::disabled();
        }
        Arc::new(c)
    }
}

type Sender = hyper::client::conn::http1::SendRequest<Empty<Bytes>>;

/// Open one connection; returns the sender and whether TLS resumed.
pub async fn connect(
    addr: SocketAddr,
    cfg: Arc<ClientConfig>,
    ctr: Arc<Counters>,
) -> std::io::Result<(Sender, bool)> {
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let tls = TlsConnector::from(cfg)
        .connect(
            ServerName::try_from("localhost").unwrap(),
            Counting { inner: tcp, c: ctr },
        )
        .await?;
    let resumed = tls.get_ref().1.handshake_kind() == Some(HandshakeKind::Resumed);
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(std::io::Error::other)?;
    tokio::spawn(conn);
    Ok((sender, resumed))
}

/// Build the request for `auth`. `seq` makes the DPoP `jti` unique.
pub fn request(kit: &ClientKit, auth: Auth, seq: u64) -> hyper::Request<Empty<Bytes>> {
    let b = hyper::Request::get(match auth {
        Auth::Bearer => "/bearer",
        Auth::DpopEs256 | Auth::DpopEdDsa => "/dpop",
        Auth::Mtls => "/mtls",
    })
    .header("host", "localhost");
    let b = match auth {
        Auth::Bearer => b.header("authorization", format!("Bearer {}", kit.bearer_token)),
        Auth::Mtls => b.header("authorization", format!("Bearer {}", kit.mtls_token)),
        Auth::DpopEs256 | Auth::DpopEdDsa => {
            let (k, t) = if auth == Auth::DpopEs256 {
                (&kit.es_key, &kit.es_token)
            } else {
                (&kit.ed_key, &kit.ed_token)
            };
            let p = token::proof(k, &format!("j-{seq}"), "GET", HTU_DPOP, token::now(), t);
            b.header("authorization", format!("DPoP {t}"))
                .header("dpop", p)
        }
    };
    b.body(Empty::new()).unwrap()
}

/// Send one request; true if HTTP 200.
pub async fn send(s: &mut Sender, req: hyper::Request<Empty<Bytes>>) -> bool {
    match s.send_request(req).await {
        Ok(r) => {
            let ok = r.status() == 200;
            let _ = r.into_body().collect().await;
            ok
        }
        Err(_) => false,
    }
}

/// Run a scenario against the (plain, mtls) addresses.
pub async fn run(
    kit: &ClientKit,
    sc: Scenario,
    plain: SocketAddr,
    mtls: SocketAddr,
    seq0: u64,
) -> Outcome {
    let is_mtls = sc.auth == Auth::Mtls;
    let addr = if is_mtls { mtls } else { plain };
    let cfg = kit.tls(is_mtls, sc.conn != ConnMode::NewFull);
    let ctr = Arc::new(Counters::default());
    let mut o = Outcome::default();
    let t0 = Instant::now();
    let mut ka: Option<Sender> = None;
    for i in 0..sc.n {
        let start = Instant::now();
        let ok = match sc.conn {
            ConnMode::KeepAlive => {
                if ka.is_none() {
                    let (s, r) = connect(addr, cfg.clone(), ctr.clone())
                        .await
                        .expect("connect");
                    o.handshakes += 1;
                    o.resumed += r as usize;
                    ka = Some(s);
                }
                let req = request(kit, sc.auth, seq0 + i as u64);
                send(ka.as_mut().unwrap(), req).await
            }
            ConnMode::NewResume | ConnMode::NewFull => {
                let (mut s, r) = connect(addr, cfg.clone(), ctr.clone())
                    .await
                    .expect("connect");
                o.handshakes += 1;
                o.resumed += r as usize;
                let req = request(kit, sc.auth, seq0 + i as u64);
                send(&mut s, req).await
            }
        };
        let el = start.elapsed().as_secs_f64() * 1e6;
        if ok {
            o.ok += 1;
            o.latencies_us.push(el);
        } else {
            o.failed += 1;
        }
    }
    o.elapsed_s = t0.elapsed().as_secs_f64();
    drop(ka);
    o.bytes = ctr.total();
    o
}

/// Functional controls: each must be rejected (401) or accepted as stated.
/// Returns (name, passed).
pub async fn controls(
    kit: &ClientKit,
    pki: &Pki,
    plain: SocketAddr,
    mtls: SocketAddr,
) -> Vec<(&'static str, bool)> {
    let mut out = Vec::new();
    let ctr = Arc::new(Counters::default());
    let plain_cfg = kit.tls(false, true);
    let (mut s, _) = connect(plain, plain_cfg.clone(), ctr.clone())
        .await
        .expect("connect");
    // Positive: each method accepted once.
    out.push((
        "bearer accepted",
        send(&mut s, request(kit, Auth::Bearer, 1)).await,
    ));
    out.push((
        "dpop es256 accepted",
        send(&mut s, request(kit, Auth::DpopEs256, 2)).await,
    ));
    out.push((
        "dpop eddsa accepted",
        send(&mut s, request(kit, Auth::DpopEdDsa, 3)).await,
    ));
    // Replay of the exact same DPoP request (same jti) must be rejected.
    let r1 = request(kit, Auth::DpopEs256, 4);
    let (parts, _) = r1.into_parts();
    let mk = || {
        let mut b = hyper::Request::get("/dpop");
        for (k, v) in parts.headers.iter() {
            b = b.header(k, v);
        }
        b.body(Empty::<Bytes>::new()).unwrap()
    };
    let first = send(&mut s, mk()).await;
    let second = send(&mut s, mk()).await;
    out.push(("dpop replay rejected", first && !second));
    // DPoP-bound token presented as bearer must be rejected.
    let req = hyper::Request::get("/bearer")
        .header("host", "localhost")
        .header("authorization", format!("Bearer {}", kit.es_token))
        .body(Empty::<Bytes>::new())
        .unwrap();
    out.push(("dpop token as bearer rejected", !send(&mut s, req).await));
    // Proof signed by a different key than the token's jkt.
    let req = {
        let p = token::proof(
            &kit.ed_key,
            "j-wrongkey",
            "GET",
            HTU_DPOP,
            token::now(),
            &kit.es_token,
        );
        hyper::Request::get("/dpop")
            .header("host", "localhost")
            .header("authorization", format!("DPoP {}", kit.es_token))
            .header("dpop", p)
            .body(Empty::<Bytes>::new())
            .unwrap()
    };
    out.push(("dpop wrong key rejected", !send(&mut s, req).await));
    // mTLS with the right certificate accepted.
    let (mut m, _) = connect(mtls, kit.tls(true, true), ctr.clone())
        .await
        .expect("connect");
    out.push((
        "mtls accepted",
        send(&mut m, request(kit, Auth::Mtls, 5)).await,
    ));
    // mTLS token over a connection authenticated with another client cert.
    let other = {
        crate::init_crypto();
        let (chain, key) = chain_and_key(&pki.other_client);
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(kit.roots.clone())
                .with_client_auth_cert(chain, key)
                .expect("cert"),
        )
    };
    let (mut o, _) = connect(mtls, other, ctr.clone()).await.expect("connect");
    out.push((
        "mtls other cert rejected",
        !send(&mut o, request(kit, Auth::Mtls, 6)).await,
    ));
    // mTLS listener without a client certificate: the handshake must fail.
    let no_cert = connect(mtls, plain_cfg, ctr).await;
    let refused = match no_cert {
        Err(_) => true,
        Ok((mut s, _)) => !send(&mut s, request(kit, Auth::Mtls, 7)).await,
    };
    out.push(("mtls without client cert refused", refused));
    out
}

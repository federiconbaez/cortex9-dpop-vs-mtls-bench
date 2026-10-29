//! axum resource server over rustls. Two listeners: one without client
//! authentication (bearer and DPoP) and one that requires a client
//! certificate from the test CA (mTLS).

use crate::certs::{chain_and_key, x5t_s256, Pki};
use crate::token::{self, Cnf};
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::Router;
use hyper_util::rt::TokioIo;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// `htu` the server expects in DPoP proofs.
pub const HTU_DPOP: &str = "https://localhost/dpop";
/// Freshness window for DPoP `iat`, seconds.
pub const WINDOW: u64 = 60;

#[derive(Default)]
struct AppState {
    jtis: Mutex<HashSet<String>>,
}

#[derive(Clone)]
struct PeerX5t(Option<String>);

fn auth(h: &HeaderMap, scheme: &str) -> Result<String, (StatusCode, &'static str)> {
    let v = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "no authorization"))?;
    v.strip_prefix(scheme)
        .and_then(|r| r.strip_prefix(' '))
        .map(str::to_string)
        .ok_or((StatusCode::UNAUTHORIZED, "scheme"))
}

type Res = Result<&'static str, (StatusCode, &'static str)>;
const DENY: StatusCode = StatusCode::UNAUTHORIZED;

async fn bearer(h: HeaderMap) -> Res {
    let tok = auth(&h, "Bearer")?;
    match token::verify_access(&tok, token::now()) {
        Ok(Cnf::None) => Ok("ok"),
        Ok(_) => Err((DENY, "sender-constrained token sent as bearer")),
        Err(e) => Err((DENY, e)),
    }
}

async fn dpop(State(st): State<Arc<AppState>>, h: HeaderMap) -> Res {
    let tok = auth(&h, "DPoP")?;
    let now = token::now();
    let Cnf::Jkt(want) = token::verify_access(&tok, now).map_err(|e| (DENY, e))? else {
        return Err((DENY, "token not DPoP-bound"));
    };
    let p = h
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .ok_or((DENY, "no dpop header"))?;
    let c = token::verify_proof(p, "GET", HTU_DPOP, now, WINDOW, &tok).map_err(|e| (DENY, e))?;
    if c.jkt != want {
        return Err((DENY, "jkt mismatch"));
    }
    if !st.jtis.lock().unwrap().insert(c.jti) {
        return Err((DENY, "jti replay"));
    }
    Ok("ok")
}

async fn mtls(Extension(peer): Extension<PeerX5t>, h: HeaderMap) -> Res {
    let tok = auth(&h, "Bearer")?;
    let Cnf::X5t(want) = token::verify_access(&tok, token::now()).map_err(|e| (DENY, e))? else {
        return Err((DENY, "token not certificate-bound"));
    };
    match peer.0 {
        Some(got) if got == want => Ok("ok"),
        Some(_) => Err((DENY, "x5t mismatch")),
        None => Err((DENY, "no client certificate")),
    }
}

fn router() -> Router {
    Router::new()
        .route("/bearer", get(bearer))
        .route("/dpop", get(dpop))
        .route("/mtls", get(mtls))
        .with_state(Arc::new(AppState::default()))
}

async fn accept_loop(l: TcpListener, acc: TlsAcceptor, app: Router) {
    loop {
        let Ok((tcp, _)) = l.accept().await else {
            return;
        };
        let _ = tcp.set_nodelay(true);
        let acc = acc.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let Ok(tls) = acc.accept(tcp).await else {
                return;
            };
            let x5t = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| x5t_s256(c));
            let svc = app.layer(Extension(PeerX5t(x5t)));
            let svc = hyper_util::service::TowerToHyperService::new(svc);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}

/// Bind both listeners on loopback and spawn the accept loops on the
/// current runtime. Returns (plain, mtls) addresses.
pub async fn spawn(pki: &Pki) -> (SocketAddr, SocketAddr) {
    crate::init_crypto();
    let (chain, key) = chain_and_key(&pki.server);
    let plain = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain.clone(), key.clone_key())
        .expect("server cert");
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone().into()).expect("ca");
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("verifier");
    let mtls_cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .expect("server cert");
    let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (a1, a2) = (l1.local_addr().unwrap(), l2.local_addr().unwrap());
    let app = router();
    tokio::spawn(accept_loop(
        l1,
        TlsAcceptor::from(Arc::new(plain)),
        app.clone(),
    ));
    tokio::spawn(accept_loop(l2, TlsAcceptor::from(Arc::new(mtls_cfg)), app));
    (a1, a2)
}

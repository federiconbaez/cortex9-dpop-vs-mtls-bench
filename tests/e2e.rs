use dpop_vs_mtls_bench::client::{self, Auth, ClientKit, ConnMode, Scenario};
use dpop_vs_mtls_bench::token::{self, Cnf, DpopKey};
use dpop_vs_mtls_bench::{certs, server};
use rand::SeedableRng;

#[test]
fn access_token_roundtrip_and_tamper() {
    let t = token::issue("a", &Cnf::Jkt("abc".into()), token::now() + 60);
    assert_eq!(
        token::verify_access(&t, token::now()),
        Ok(Cnf::Jkt("abc".into()))
    );
    let mut b = t.into_bytes();
    let i = b.len() - 3;
    b[i] = if b[i] == b'A' { b'B' } else { b'A' };
    assert!(token::verify_access(&String::from_utf8(b).unwrap(), token::now()).is_err());
    let old = token::issue("a", &Cnf::None, 10);
    assert_eq!(token::verify_access(&old, token::now()), Err("expired"));
}

#[test]
fn proof_roundtrip_both_algs_and_ath() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
    for k in [
        DpopKey::Es256(p256::ecdsa::SigningKey::random(&mut rng)),
        DpopKey::EdDsa(ed25519_dalek::SigningKey::generate(&mut rng)),
    ] {
        let now = token::now();
        let p = token::proof(&k, "j", "GET", "https://x/y", now, "AT");
        let c = token::verify_proof(&p, "GET", "https://x/y", now, 60, "AT").unwrap();
        assert_eq!(c.jkt, token::jkt(&k.jwk()).unwrap());
        assert_eq!(
            token::verify_proof(&p, "GET", "https://x/y", now, 60, "OTHER").err(),
            Some("ath")
        );
        assert_eq!(
            token::verify_proof(&p, "POST", "https://x/y", now, 60, "AT").err(),
            Some("binding")
        );
        assert_eq!(
            token::verify_proof(&p, "GET", "https://x/y", now + 3600, 60, "AT").err(),
            Some("iat")
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn functional_controls_and_tiny_scenarios() {
    let pki = certs::generate();
    let (plain, mtls) = server::spawn(&pki).await;
    let kit = ClientKit::new(&pki, 7);
    for (name, ok) in client::controls(&kit, &pki, plain, mtls).await {
        assert!(ok, "control failed: {name}");
    }
    let mut seq = 100;
    for auth in [Auth::Bearer, Auth::DpopEs256, Auth::DpopEdDsa, Auth::Mtls] {
        for conn in [ConnMode::KeepAlive, ConnMode::NewResume, ConnMode::NewFull] {
            let o = client::run(&kit, Scenario { auth, conn, n: 5 }, plain, mtls, seq).await;
            seq += 5;
            assert_eq!(o.ok, 5, "{auth:?} {conn:?}");
            let resumed = match conn {
                ConnMode::NewResume => 4,
                _ => 0,
            };
            assert_eq!(o.resumed, resumed, "{auth:?} {conn:?}");
            assert!(o.bytes > 0);
        }
    }
}

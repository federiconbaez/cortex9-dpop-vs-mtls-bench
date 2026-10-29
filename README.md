# dpop-vs-mtls-bench

Costo medido de restringir tokens al emisor con DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) frente a mTLS con tokens ligados al certificado ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)), y frente a un bearer sin restricción. Servidor axum sobre rustls, por TCP loopback. Compara conexiones keep-alive con conexiones nuevas por request, con y sin reanudación TLS.

Measured cost of DPoP vs mTLS certificate-bound tokens vs plain bearer, on axum + rustls over loopback, with keep-alive and new-connection patterns, with and without TLS resumption.

> **ES** primero · **EN** abajo. Nivel de verificación: **B** (ver abajo).

---

## ES

### Qué hay

| Pieza | Qué hace |
|---|---|
| `src/token.rs` | Tokens de acceso HS256 con `cnf` (`jkt` o `x5t#S256`). Pruebas DPoP ES256 (`p256`) y EdDSA (`ed25519-dalek`) con `ath`. Thumbprint RFC 7638. |
| `src/server.rs` | axum + rustls (ring). `/bearer` y `/dpop` en un listener sin auth de cliente, `/mtls` en otro que exige certificado. DPoP chequea token, firma, `jkt`, `ath`, `htm`/`htu`, `iat` ±60 s y `jti` único. mTLS compara `x5t#S256` con el certificado del handshake. |
| `src/client.rs` | Escenarios y 9 controles funcionales. |
| `src/bin/dvm-bench.rs` | Levanta el servidor como proceso hijo (su CPU sale de `/proc`), corre controles y escenarios, y escribe CSV. |
| `tests/e2e.rs` | Tokens, pruebas, controles y los 12 pares método × conexión con 5 requests. |

### Medición

Prerregistrada en [`PREREGISTRO.md`](PREREGISTRO.md). `--check` salió con 0: los 9 controles pasan, no falló ningún request y las reanudaciones son exactas (599 de 600 con reanudación, 0 sin ella).

```sh
cargo run --release --bin dvm-bench -- run --keepalive 3000 --newconn 600 --rounds 2 --seed 42 --csv results/bench.csv --check
```

Resultados de las rondas 1 y 2 (`results/bench.csv`). Un cliente secuencial. La latencia es del lado del cliente e incluye crear la prueba DPoP; la CPU va en µs por request.

| Escenario | req/s | p50 µs | p99 µs | CPU cliente | CPU servidor | bytes/req |
|---|---|---|---|---|---|---|
| `bearer_keepalive` | 34017 / 33676 | 28.3 / 28.9 | 37.8 / 36.3 | 13.0 / 13.0 | 13.3 / 13.3 | 426 |
| `dpop_es256_keepalive` | 2145 / 2184 | 432.2 / 430.5 | 744.9 / 747.4 | 176.2 / 175.0 | 260.0 / 266.7 | 993 |
| `dpop_eddsa_keepalive` | 9565 / 10174 | 96.5 / 93.8 | 185.2 / 173.9 | 39.7 / 34.4 | 63.3 / 60.0 | 931 |
| `mtls_keepalive` | 30860 / 31156 | 29.7 / 29.6 | 73.5 / 53.9 | 13.9 / 14.3 | 16.7 / 16.7 | 511 |
| `bearer_newconn_resume` | 3504 / 3562 | 270.3 / 270.8 | 692.4 / 604.5 | 157.0 / 159.1 | 166.7 / 150.0 | 1261 |
| `dpop_es256_newconn_resume` | 1332 / 1423 | 684.4 / 671.7 | 1136.2 / 1188.7 | 366.5 / 319.9 | 433.3 / 416.7 | 1828 |
| `mtls_newconn_resume` | 3454 / 3531 | 277.6 / 273.5 | 476.3 / 577.3 | 164.0 / 160.5 | 166.7 / 183.3 | 1345 |
| `bearer_newconn_full` | 2368 / 2343 | 396.9 / 400.2 | 916.6 / 801.6 | 274.1 / 282.7 | 166.7 / 183.3 | 1608 |
| `dpop_es256_newconn_full` | 1181 / 1082 | 814.1 / 896.4 | 1412.4 / 1446.1 | 438.7 / 447.7 | 450.0 / 533.3 | 2175 |
| `mtls_newconn_full` | 1651 / 1674 | 560.5 / 559.8 | 1050.2 / 1159.9 | 302.8 / 300.7 | 350.0 / 333.3 | 2212 |

Una tercera ronda en un clon limpio (`results/clean-clone.csv`) da los mismos órdenes de magnitud: bearer 35576 req/s, mTLS 35864, DPoP EdDSA 11350 y DPoP ES256 2387 en keep-alive.

Lectura, contra las hipótesis prerregistradas:
- **H1 (se cumple):** con keep-alive, mTLS cuesta casi lo mismo que bearer: p50 29,6–29,7 µs contra 28,3–28,9, y CPU de servidor 16,7 contra 13,3 µs (con la resolución de 1 tick, ver límites). Suma 85 bytes por request por el `cnf` del token.
- **H2 (se cumple):** DPoP suma una firma y una verificación por request. Con ES256 (`p256`, Rust puro) el throughput cae entre 15 y 16 veces respecto de bearer; con EdDSA, entre 3,3 y 3,6 veces. El header `DPoP` suma 505 bytes (EdDSA) a 567 (ES256) por request.
- **H3 (se cumple):** con una conexión nueva sin reanudación, mTLS suma 604 bytes (certificado del cliente y CertificateVerify) y ≈ 160 µs de p50 sobre bearer, y la CPU de servidor sube de 167–183 a 333–350 µs. Con reanudación, mTLS queda a 1–3 % de bearer en p50 y suma 84 bytes.
- **H4:** entre las rondas, req/s varía hasta 9 % (`dpop_es256_newconn_full`: 1082 contra 1181) y p99 hasta 36 % (`mtls_keepalive`: 53,9 contra 73,5 µs).

### Tests

`cargo test`: 3/3 (el de punta a punta recorre los 9 controles y 12 escenarios). Ningún test se saltea.

### Qué prueba y qué no el 9/9 controles y los 0 requests fallidos

- **Prueba**:
  - Los chequeos de ligadura del servidor están conectados. Acepta bearer, DPoP ES256, DPoP EdDSA y mTLS válidos.
  - Rechaza una vez cada uno de los 5 casos negativos: la misma prueba DPoP repetida, un token DPoP presentado como bearer, una prueba firmada con otra clave, mTLS con otro certificado y mTLS sin certificado.
  - Los números de rendimiento salen de un camino que funciona, porque no falló ningún request.
- **No prueba**:
  - No es una evaluación de seguridad: cada control corre una sola vez y solo cubre esos 9 casos.
  - Nada sobre el compromiso de la clave DPoP del cliente o de la clave de su certificado: con la clave, el atacante pasa los chequeos.
  - Nada sobre el replay entre servidores distintos; para eso está `dpop-replay-mesh`.
  - Nada sobre variaciones de `iat`, `htu` o `ath` más allá de las que prueba el servidor, ni sobre el robo del token sin la clave en otros escenarios.
- **Los controles los diseñamos nosotros.**

### Nivel de verificación

**B**: el mecanismo está medido, con controles funcionales y dos rondas más una en un clon limpio. No es B+ porque no compara contra una implementación de referencia externa. No es C porque no hubo concurrencia ni red real.

### Límites

- Un cliente secuencial. Sin concurrencia, req/s es la inversa de la latencia, no la capacidad del servidor.
- TCP loopback en una VM compartida. No se usó netem, que necesita root; con RTT real, el handshake de conexión nueva pesaría más.
- La CPU del servidor se lee en ticks de 10 ms: la resolución es ≈ 3 µs/request con 3000 requests y ≈ 17 µs/request con 600.
- Los números dependen de las implementaciones elegidas: ES256 con `p256` en Rust puro, y TLS con ring. Otra pila de ES256 cambiaría H2.
- No hay caché de `jti` compartida ni nonce del servidor (ver `dpop-replay-mesh`); el token de acceso es HS256 local, sin introspección.

### Fuentes leídas

- RFC 9449, secciones 4.3 y 11.1: `https://www.rfc-editor.org/rfc/rfc9449.txt`.
- RFC 8705, sección 3.1 (`x5t#S256`): `https://www.rfc-editor.org/rfc/rfc8705.txt`.
- Código de `rustls` 0.23.46 (`handshake_kind`, `peer_certificates`, `Resumption::disabled`) y `rcgen` 0.14.10 (`Issuer`, `signed_by`).
- API de crates.io para las versiones: `https://crates.io/api/v1/crates/<nombre>`.

---

## EN

### What is here

HS256 access tokens with `cnf`; DPoP proofs (ES256 via `p256`, EdDSA via `ed25519-dalek`) with `ath`; an axum + rustls server with `/bearer`, `/dpop` (full RFC 9449 §4.3 checks plus `jti` uniqueness) and `/mtls` (token `x5t#S256` vs handshake certificate); a scenario client with 9 functional controls; a bench binary that runs the server as a child process to read its CPU from `/proc`.

### Measurement

Pre-registered. `--check` passed (9/9 controls, 0 failed requests, exact resumption counts). Two rounds, plus one in a clean clone (table above). H1 holds: with keep-alive, mTLS costs about the same as bearer, plus 85 bytes. H2 holds: DPoP costs one sign and one verify per request; throughput falls 15–16× with ES256 (pure-Rust `p256`) and 3.3–3.6× with EdDSA, plus 505–567 bytes. H3 holds: on a new connection without resumption, mTLS adds 604 bytes, about 160 µs p50 and 150–183 µs of server CPU over bearer; with resumption it is within 1–3 % of bearer. H4: round-to-round variation is up to 9 % in req/s and 36 % in p99.

### What 9/9 controls and 0 failed requests prove and what they don't

- **They prove** that the server's binding checks are wired: valid bearer, DPoP ES256, DPoP EdDSA and mTLS requests are accepted, and each of 5 negatives is rejected once (replayed DPoP proof, DPoP token sent as bearer, proof signed with another key, mTLS with another certificate, mTLS without a certificate). The performance numbers come from a working path.
- **They are not a security evaluation**: each control runs once and only covers those 9 cases.
- **They don't cover**:
  - compromise of the client's DPoP or certificate key;
  - cross-server replay (see `dpop-replay-mesh`);
  - wider `iat`, `htu` or `ath` variations.
- **The controls are ours.**

### Verification level

**B**: mechanism measured with functional controls, two rounds plus a clean-clone round. Not B+ (no external reference), not C (no concurrency, no real network).

### Limits

Single sequential client; loopback on a shared VM, no netem (needs root); server CPU in 10 ms ticks; results depend on the chosen ES256 and TLS implementations; no shared jti cache, no server nonce, no token introspection.

## License

Apache-2.0.

# Prerregistro de la medición / Measurement pre-registration

Escrito y commiteado antes de correr el banco. / Written and committed before running the bench.

**Divulgación / disclosure:** antes de este commit sólo corrieron los tests (`cargo test`: controles y 5 requests por par método × conexión, sin mirar tiempos). / Only the tests ran before this commit.

Comando / command:

```sh
cargo run --release --bin dvm-bench -- run --keepalive 3000 --newconn 600 --rounds 2 --seed 42 --csv results/bench.csv --check
```

Cliente y servidor en procesos separados en la misma máquina, cada uno con un runtime tokio de un hilo, TCP loopback, TLS de rustls (ring). Un cliente secuencial: no hay concurrencia. Dos rondas de los 10 escenarios, intercaladas.

Escenarios: `{bearer, dpop_es256, dpop_eddsa, mtls}_keepalive` (3000 requests), `{bearer, dpop_es256, mtls}_newconn_resume` y `{bearer, dpop_es256, mtls}_newconn_full` (600 requests, una conexión TCP+TLS por request).

Métricas: req/s, latencia p50/p99 del lado del cliente, CPU del cliente y del servidor por request (getrusage y /proc), bytes en el cable por request (contados en el socket del cliente), handshakes y reanudaciones.

Controles (con `--check`, fallan visible): los 9 controles funcionales pasan (DPoP repetido, token DPoP como bearer, prueba con otra clave, mTLS con otro certificado y sin certificado: todos rechazados); 0 requests fallidos; en `newconn_resume` reanudan todos menos el primero; en `newconn_full`, ninguno.

Hipótesis (sin umbral; se reporta lo que salga):
- H1 keep-alive: mTLS cuesta ≈ lo mismo que bearer por request (la prueba de posesión ya se hizo en el handshake).
- H2 keep-alive: DPoP suma una firma en el cliente y una verificación en el servidor por request; ES256 (crate `p256`, Rust puro) más caro que EdDSA (`ed25519-dalek`). Suma ≈ 600–800 bytes por request por el header `DPoP`.
- H3 conexión nueva sin reanudación: mTLS suma el certificado del cliente y su CertificateVerify al handshake (bytes y CPU de servidor). Con reanudación, esa diferencia baja.
- H4 la diferencia entre las dos rondas da la escala del ruido.

Límites conocidos / known limits: loopback en una VM compartida, sin red ni netem (necesita root); CPU por ticks de 10 ms; un solo cliente; claves P-256 de rcgen; las cifras dependen de las implementaciones elegidas (`p256` en Rust puro y ring en TLS), no son del protocolo en abstracto.

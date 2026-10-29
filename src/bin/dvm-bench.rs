//! `dvm-bench run`: spawns the server as a child process (so its CPU time
//! can be read from /proc), runs the functional controls and every scenario
//! for a number of rounds, and writes a CSV.
//! `dvm-bench serve <pki.json>`: the child.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use dpop_vs_mtls_bench::certs::{self, Leaf, Pki};
use dpop_vs_mtls_bench::client::{self, Auth, ClientKit, ConnMode, Scenario};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};

fn arg(name: &str, def: &str) -> String {
    let a: Vec<String> = std::env::args().collect();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1).cloned())
        .unwrap_or_else(|| def.to_string())
}

fn pki_to_json(p: &Pki) -> String {
    serde_json::json!({
        "ca": B64.encode(&p.ca),
        "server_cert": B64.encode(&p.server.cert),
        "server_key": B64.encode(&p.server.key),
    })
    .to_string()
}

fn pki_from_json(s: &str) -> Pki {
    let v: serde_json::Value = serde_json::from_str(s).unwrap();
    let d = |k: &str| B64.decode(v[k].as_str().unwrap()).unwrap();
    let empty = || Leaf {
        cert: vec![],
        key: vec![],
    };
    Pki {
        ca: d("ca"),
        server: Leaf {
            cert: d("server_cert"),
            key: d("server_key"),
        },
        client: empty(),
        other_client: empty(),
    }
}

fn serve(path: &str) {
    let pki = pki_from_json(&std::fs::read_to_string(path).unwrap());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (a, b) = dpop_vs_mtls_bench::server::spawn(&pki).await;
        println!("PORTS {} {}", a.port(), b.port());
        // Exit when the parent closes stdin.
        tokio::task::spawn_blocking(|| {
            let mut s = String::new();
            let _ = std::io::stdin().read_to_string(&mut s);
        })
        .await
        .unwrap();
    });
}

fn proc_cpu_s(pid: u32) -> f64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let after = &s[s.rfind(')').unwrap() + 2..];
    let f: Vec<&str> = after.split(' ').collect();
    // fields 14 and 15 (utime, stime) are at index 11 and 12 after the comm.
    let ticks: u64 = f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap();
    ticks as f64 / unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64
}

fn self_cpu_s() -> f64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let t = |tv: libc::timeval| tv.tv_sec as f64 + tv.tv_usec as f64 / 1e6;
    t(ru.ru_utime) + t(ru.ru_stime)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.get(1).map(String::as_str) == Some("serve") {
        serve(&a[2]);
        return;
    }
    let keepalive: usize = arg("--keepalive", "3000").parse().unwrap();
    let newconn: usize = arg("--newconn", "600").parse().unwrap();
    let rounds: usize = arg("--rounds", "2").parse().unwrap();
    let seed: u64 = arg("--seed", "42").parse().unwrap();
    let csv_path = arg("--csv", "results/bench.csv");
    let check = a.iter().any(|x| x == "--check");

    let pki = certs::generate();
    let dir = std::path::Path::new("target/dvm-bench");
    std::fs::create_dir_all(dir).unwrap();
    let pki_path = dir.join("pki.json");
    std::fs::write(&pki_path, pki_to_json(&pki)).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("serve")
        .arg(&pki_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let ports: Vec<u16> = line
        .split_whitespace()
        .skip(1)
        .map(|p| p.parse().unwrap())
        .collect();
    let plain = std::net::SocketAddr::from(([127, 0, 0, 1], ports[0]));
    let mtls = std::net::SocketAddr::from(([127, 0, 0, 1], ports[1]));
    let pid = child.id();

    let kit = ClientKit::new(&pki, seed);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut fails = Vec::new();
    for (name, ok) in rt.block_on(client::controls(&kit, &pki, plain, mtls)) {
        println!("control {name}: {}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            fails.push(format!("control {name}"));
        }
    }
    let scenarios: Vec<Scenario> = {
        use Auth::*;
        use ConnMode::*;
        let k = |auth| Scenario {
            auth,
            conn: KeepAlive,
            n: keepalive,
        };
        let r = |auth| Scenario {
            auth,
            conn: NewResume,
            n: newconn,
        };
        let f = |auth| Scenario {
            auth,
            conn: NewFull,
            n: newconn,
        };
        vec![
            k(Bearer),
            k(DpopEs256),
            k(DpopEdDsa),
            k(Mtls),
            r(Bearer),
            r(DpopEs256),
            r(Mtls),
            f(Bearer),
            f(DpopEs256),
            f(Mtls),
        ]
    };
    let mut csv = String::from("round,scenario,requests,ok,failed,req_per_s,p50_us,p99_us,client_cpu_us_per_req,server_cpu_us_per_req,bytes_per_req,handshakes,resumed\n");
    let mut seq = 1_000_000u64;
    for round in 1..=rounds {
        for sc in &scenarios {
            let (c0, s0) = (self_cpu_s(), proc_cpu_s(pid));
            let o = rt.block_on(client::run(&kit, *sc, plain, mtls, seq));
            let (c1, s1) = (self_cpu_s(), proc_cpu_s(pid));
            seq += sc.n as u64;
            let n = sc.n as f64;
            let l = format!(
                "{round},{},{},{},{},{:.0},{:.1},{:.1},{:.1},{:.1},{:.0},{},{}",
                sc.name(),
                sc.n,
                o.ok,
                o.failed,
                n / o.elapsed_s,
                o.pct(50.0),
                o.pct(99.0),
                (c1 - c0) * 1e6 / n,
                (s1 - s0) * 1e6 / n,
                o.bytes as f64 / n,
                o.handshakes,
                o.resumed
            );
            println!("{l}");
            let _ = writeln!(csv, "{l}");
            if o.failed != 0 {
                fails.push(format!("{}: {} failed requests", sc.name(), o.failed));
            }
            let want_resumed = match sc.conn {
                ConnMode::KeepAlive => 0,
                ConnMode::NewResume => o.handshakes - 1,
                ConnMode::NewFull => 0,
            };
            if o.resumed != want_resumed {
                fails.push(format!(
                    "{}: resumed {} expected {}",
                    sc.name(),
                    o.resumed,
                    want_resumed
                ));
            }
        }
    }
    drop(child.stdin.take());
    let _ = child.wait();
    if let Some(d) = std::path::Path::new(&csv_path).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    std::fs::write(&csv_path, csv).unwrap();
    for f in &fails {
        eprintln!("CHECK FAIL: {f}");
    }
    if check && !fails.is_empty() {
        std::process::exit(1);
    }
}

//! Transport probe: does an mshr endpoint actually work from a phone?
//!
//! Written for the yah-mobile feasibility spike (R726-S1, W122). It is a
//! plain `main()` rather than a test because the interesting questions are
//! about a *device* — NAT class, relay fallback, cold-dial latency, whether
//! the OS reaps the socket while the screen is off — and none of those are
//! answerable from a host-side `cargo test`.
//!
//! Build for a phone (from `oss/mshr`):
//!
//! ```text
//! source ../../scripts/android-env.sh
//! cargo build --release --target aarch64-linux-android --example android_probe
//! adb push target/aarch64-linux-android/release/examples/android_probe /data/local/tmp/
//! adb shell chmod 755 /data/local/tmp/android_probe
//! ```
//!
//! Then, laptop side:
//!
//! ```text
//! cargo run --example android_probe -- serve
//! # -> prints "node_id=<64 hex>"
//! ```
//!
//! and phone side:
//!
//! ```text
//! adb shell /data/local/tmp/android_probe env
//! adb shell /data/local/tmp/android_probe dial <node_id> --rounds 10 --sleep 30
//! ```
//!
//! Output is one `key=value` line per round so it can be pasted into a
//! ticket or piped through `awk` without a parser.
//!
//! # What this probe can and cannot tell you
//!
//! Run under `adb shell` the binary is a plain shell process in
//! `/data/local/tmp`, NOT an app in an App Standby bucket. So it measures
//! the **transport**: dial latency, whether the path came up direct or via
//! a relay, and whether an idle connection survives. It does **not**
//! reproduce Doze-mode process freezing or app-standby socket reaping —
//! that needs the real Tauri host (R726-T2) plus an unplugged device or
//! `adb shell dumpsys deviceidle force-idle`. Don't report a `--hold` run
//! from `adb shell` as a Doze result.
//!
//! **Only `round=1` is a cold dial.** The endpoint caches a peer's
//! transport addresses after the first success, so `--rounds 5` measures
//! one cold dial and four warm re-dials — locally that was 617 ms then
//! 4-5 ms. W122's sub-second budget is about the *cold* number, because
//! FCM wakes a process that has no cache. To sample it properly, invoke
//! the binary once per measurement:
//!
//! ```text
//! for i in $(seq 1 10); do
//!   adb shell /data/local/tmp/android_probe dial <node_id> --ephemeral
//!   sleep 60
//! done
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use mshr::{Endpoint, Keypair, NodeId, Seeds};

/// Probe-only ALPN. Deliberately not one of yah's real control ALPNs —
/// pointing this at a live camp should fail the ALPN negotiation rather
/// than half-speak a protocol it does not implement.
const DEFAULT_ALPN: &[u8] = b"yah/mobile-probe/1";

const PING: &[u8] = b"ping";
const PONG: &[u8] = b"pong";

fn usage() -> ! {
    eprintln!(
        "\
android_probe — mshr/iroh transport probe (R726-S1)

  android_probe env
      Print platform + identity-storage diagnostics and exit. Run this
      FIRST on a new device: it says whether mshr can find anywhere to
      persist a NodeId.

  android_probe serve [OPTIONS]
      Bind an endpoint, print its node_id, and echo `ping` -> `pong` on
      the probe ALPN until killed. Run this on the desktop camp side.

  android_probe dial <NODE_ID> [OPTIONS]
      Dial NODE_ID, ping it, report latency and whether the path is
      direct or relayed. Run this on the phone.

OPTIONS
  --dir <PATH>     Where to load-or-create the identity. Default: mshr's
                   platform data dir, which does NOT resolve on Android
                   (see `env`) — pass an app-private path there.
  --ephemeral      Generate a throwaway identity; touches no disk.
  --alpn <STR>     ALPN to use. Default: yah/mobile-probe/1
  --rounds <N>     dial: how many probes. Default 1.
  --sleep <SECS>   dial: seconds between probes. Default 5.
  --hold           dial: keep ONE connection open across rounds instead of
                   redialing. This is the connection-survival measurement;
                   without it you are measuring cold dials (the FCM-wake
                   design in W122).
  --timeout <SECS> Per-round deadline. Default 30.
  --verbose        Turn on iroh's debug logging.
"
    );
    std::process::exit(2);
}

struct Args {
    cmd: String,
    node_id: Option<String>,
    dir: Option<PathBuf>,
    ephemeral: bool,
    alpn: Vec<u8>,
    rounds: u32,
    sleep: Duration,
    hold: bool,
    timeout: Duration,
    verbose: bool,
}

fn parse_args() -> Result<Args> {
    let mut it = std::env::args().skip(1);
    let cmd = match it.next() {
        Some(c) => c,
        None => usage(),
    };
    let mut a = Args {
        cmd,
        node_id: None,
        dir: None,
        ephemeral: false,
        alpn: DEFAULT_ALPN.to_vec(),
        rounds: 1,
        sleep: Duration::from_secs(5),
        hold: false,
        timeout: Duration::from_secs(30),
        verbose: false,
    };
    while let Some(arg) = it.next() {
        let mut want = |name: &str| -> Result<String> {
            it.next()
                .ok_or_else(|| anyhow!("{name} needs a value"))
        };
        match arg.as_str() {
            "--dir" => a.dir = Some(PathBuf::from(want("--dir")?)),
            "--ephemeral" => a.ephemeral = true,
            "--alpn" => a.alpn = want("--alpn")?.into_bytes(),
            "--rounds" => a.rounds = want("--rounds")?.parse().context("--rounds")?,
            "--sleep" => {
                a.sleep = Duration::from_secs(want("--sleep")?.parse().context("--sleep")?)
            }
            "--hold" => a.hold = true,
            "--timeout" => {
                a.timeout = Duration::from_secs(want("--timeout")?.parse().context("--timeout")?)
            }
            "--verbose" | "-v" => a.verbose = true,
            "-h" | "--help" => usage(),
            other if other.starts_with('-') => bail!("unknown flag {other}"),
            positional => {
                if a.node_id.is_some() {
                    bail!("unexpected extra argument {positional}");
                }
                a.node_id = Some(positional.to_string());
            }
        }
    }
    Ok(a)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

    tracing_subscriber::fmt()
        .with_max_level(if args.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::WARN
        })
        .with_writer(std::io::stderr)
        .init();

    match args.cmd.as_str() {
        "env" => cmd_env(),
        "serve" => cmd_serve(&args).await,
        "dial" => cmd_dial(&args).await,
        other => {
            eprintln!("unknown subcommand {other}");
            usage()
        }
    }
}

// ---------------------------------------------------------------- env

/// Platform + identity-storage diagnostics.
///
/// The load-bearing line is `identity_dir=`. `mshr::keypair::identity_dir`
/// goes through `directories::ProjectDirs`, which on Android takes the
/// Linux/XDG branch and needs `$HOME` — a variable Android does not set
/// for app processes. If that line says `ERR`, then
/// `Keypair::load_or_create()` cannot be the mobile host's identity path
/// and `load_or_create_at(<app files dir>)` has to be, which is exactly
/// the question R726-S1 exists to settle.
fn cmd_env() -> Result<()> {
    println!("os={}", std::env::consts::OS);
    println!("arch={}", std::env::consts::ARCH);
    println!("family={}", std::env::consts::FAMILY);
    for var in ["HOME", "TMPDIR", "XDG_DATA_HOME", "EXTERNAL_STORAGE", "USER"] {
        match std::env::var(var) {
            Ok(v) => println!("env.{var}={v}"),
            Err(_) => println!("env.{var}=<unset>"),
        }
    }
    match std::env::current_dir() {
        Ok(d) => println!("cwd={}", d.display()),
        Err(e) => println!("cwd=ERR({e})"),
    }
    match mshr::keypair::identity_dir() {
        Ok(d) => {
            println!("identity_dir={}", d.display());
            println!("identity_dir_writable={}", probe_writable(&d));
        }
        Err(e) => println!("identity_dir=ERR({e})"),
    }
    // The two paths an Android host actually has: the adb-shell scratch
    // dir, and (for the real app) whatever `Context.getFilesDir()` hands
    // the Rust side. Probing the first tells us the *mechanism* works.
    for candidate in ["/data/local/tmp/mshr-probe", "./mshr-probe"] {
        println!(
            "candidate.{candidate}_writable={}",
            probe_writable(std::path::Path::new(candidate))
        );
    }
    Ok(())
}

/// Can we create the directory and an O_EXCL file inside it? This is the
/// exact operation `Keypair::load_or_create_at` performs, so a `true`
/// here means identity persistence will work at that path.
fn probe_writable(dir: &std::path::Path) -> String {
    if let Err(e) = std::fs::create_dir_all(dir) {
        return format!("no({e})");
    }
    let probe = dir.join(".write-probe");
    let _ = std::fs::remove_file(&probe);
    match std::fs::write(&probe, b"x") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            "yes".to_string()
        }
        Err(e) => format!("no({e})"),
    }
}

// -------------------------------------------------------------- shared

async fn bind(args: &Args) -> Result<Endpoint> {
    let keypair = if args.ephemeral {
        Keypair::generate()
    } else if let Some(dir) = &args.dir {
        Keypair::load_or_create_at(dir).with_context(|| format!("identity at {}", dir.display()))?
    } else {
        Keypair::load_or_create()
            .context("no --dir given and the platform data dir did not resolve; run `env`")?
    };

    let builder = Endpoint::builder()
        .keypair(keypair)
        .alpns([args.alpn.clone()]);
    // Full default posture: n0 relays + pkarr resolution + LAN mDNS. That
    // is what makes a bare-NodeId dial resolvable, and it is the posture
    // the mobile host will ship with.
    let ep = Seeds::defaults()
        .apply(builder)
        .bind()
        .await
        .context("endpoint bind")?;
    Ok(ep)
}

/// Which transport addresses is this connection *actively* using, and are
/// they direct IP paths or relayed?
///
/// `remote_info` is the only honest source for this — the fact that
/// `connect` returned says nothing about whether the bytes are going
/// through n0's relay. On a phone that distinction is the whole point of
/// the spike, so it is reported per round rather than summarised.
///
/// NOTE for R726-T2: this reaches through `Endpoint::inner()` into
/// `iroh` because mshr re-exports neither `remote_info` nor
/// `TransportAddr`/`TransportAddrUsage`. That is fine here (this example
/// lives inside the mshr package, where `iroh` is already a dependency)
/// but the mobile host wants to *show* direct-vs-relay in the UI, and it
/// would have to take a direct `iroh` dependency to do so — exactly what
/// mshr exists to avoid. Closing that is a small additive re-export on
/// mshr; see the R726-T2 `next` bullets.
async fn path_report(ep: &Endpoint, peer: NodeId) -> (String, String) {
    use iroh::endpoint::TransportAddrUsage;
    use iroh::TransportAddr;

    let Some(info) = ep.inner().remote_info(peer).await else {
        return ("unknown".into(), String::new());
    };
    let mut direct = Vec::new();
    let mut relay = Vec::new();
    for a in info.addrs() {
        // `matches!` rather than `!=`: iroh 1.0.0-rc.0's
        // `TransportAddrUsage` derives neither `PartialEq` nor `Eq`.
        if !matches!(a.usage(), TransportAddrUsage::Active) {
            continue;
        }
        match a.addr() {
            TransportAddr::Ip(sa) => direct.push(sa.to_string()),
            TransportAddr::Relay(url) => relay.push(url.to_string()),
            other => relay.push(format!("{other:?}")),
        }
    }
    let class = match (direct.is_empty(), relay.is_empty()) {
        (false, true) => "direct",
        (false, false) => "mixed",
        (true, false) => "relay",
        (true, true) => "none",
    };
    let mut addrs = direct;
    addrs.extend(relay);
    (class.to_string(), addrs.join(","))
}

// -------------------------------------------------------------- serve

async fn cmd_serve(args: &Args) -> Result<()> {
    let ep = bind(args).await?;
    println!("node_id={}", ep.node_id());
    println!("endpoint_addr={:?}", ep.endpoint_addr());
    println!("alpn={}", String::from_utf8_lossy(&args.alpn));
    println!("ready — ctrl-c to stop");

    let mut handlers: HashMap<Vec<u8>, mshr::endpoint::AlpnHandler> = HashMap::new();
    handlers.insert(
        args.alpn.clone(),
        Arc::new(|conn: mshr::Connection| {
            Box::pin(async move {
                let peer = conn.remote_id();
                loop {
                    let (mut send, mut recv) = match conn.accept_bi().await {
                        Ok(pair) => pair,
                        // The dialer closing is the normal end of a probe
                        // round, not an error worth a non-zero exit.
                        Err(e) => {
                            eprintln!("peer={peer} closed: {e}");
                            return Ok(());
                        }
                    };
                    let got = recv.read_to_end(64).await?;
                    eprintln!("peer={peer} recv={}", String::from_utf8_lossy(&got));
                    send.write_all(PONG).await?;
                    send.finish()?;
                }
            })
        }),
    );

    ep.accept_dispatch(handlers).await?;
    Ok(())
}

// --------------------------------------------------------------- dial

async fn cmd_dial(args: &Args) -> Result<()> {
    let raw = args
        .node_id
        .as_deref()
        .ok_or_else(|| anyhow!("dial needs a NODE_ID"))?;
    let peer = NodeId::from_str(raw).with_context(|| format!("parsing node id {raw}"))?;

    let bind_start = Instant::now();
    let ep = bind(args).await?;
    println!(
        "self_node_id={} bind_ms={}",
        ep.node_id(),
        bind_start.elapsed().as_millis()
    );
    println!("peer={peer} alpn={}", String::from_utf8_lossy(&args.alpn));
    println!("mode={}", if args.hold { "hold" } else { "cold-dial" });

    let mut dial_samples: Vec<u128> = Vec::new();
    let mut rtt_samples: Vec<u128> = Vec::new();
    let mut relayed = 0u32;
    let mut failures = 0u32;

    // --hold: one connection reused across rounds. The round that fails is
    // the answer to "how long does an idle connection survive here".
    let mut held: Option<mshr::Connection> = None;
    let held_since = Instant::now();

    for round in 1..=args.rounds {
        if round > 1 {
            tokio::time::sleep(args.sleep).await;
        }

        let t_dial = Instant::now();
        let conn = if args.hold {
            match held.take() {
                Some(c) => c,
                None => match tokio::time::timeout(
                    args.timeout,
                    ep.connect_alpn(mshr::EndpointAddr::new(peer), &args.alpn),
                )
                .await
                {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        failures += 1;
                        println!("round={round} result=dial_failed err={e}");
                        continue;
                    }
                    Err(_) => {
                        failures += 1;
                        println!(
                            "round={round} result=dial_timeout after_s={}",
                            args.timeout.as_secs()
                        );
                        continue;
                    }
                },
            }
        } else {
            match tokio::time::timeout(
                args.timeout,
                ep.connect_alpn(mshr::EndpointAddr::new(peer), &args.alpn),
            )
            .await
            {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    failures += 1;
                    println!("round={round} result=dial_failed err={e}");
                    continue;
                }
                Err(_) => {
                    failures += 1;
                    println!(
                        "round={round} result=dial_timeout after_s={}",
                        args.timeout.as_secs()
                    );
                    continue;
                }
            }
        };
        let dial_ms = t_dial.elapsed().as_millis();

        let t_rtt = Instant::now();
        let rtt = match tokio::time::timeout(args.timeout, ping(&conn)).await {
            Ok(Ok(())) => t_rtt.elapsed().as_millis(),
            Ok(Err(e)) => {
                failures += 1;
                println!(
                    "round={round} result=stream_failed held_s={} err={e}",
                    held_since.elapsed().as_secs()
                );
                continue;
            }
            Err(_) => {
                failures += 1;
                println!(
                    "round={round} result=stream_timeout held_s={}",
                    held_since.elapsed().as_secs()
                );
                continue;
            }
        };

        let (class, addrs) = path_report(&ep, peer).await;
        if class == "relay" {
            relayed += 1;
        }
        // Only the cold-dial numbers describe a dial; a held round reuses
        // the connection, so its dial_ms is ~0 and would skew the summary.
        if !args.hold || round == 1 {
            dial_samples.push(dial_ms);
        }
        rtt_samples.push(rtt);
        println!(
            "round={round} result=ok dial_ms={dial_ms} rtt_ms={rtt} path={class} addrs={addrs} held_s={}",
            held_since.elapsed().as_secs()
        );

        if args.hold {
            held = Some(conn);
        } else {
            conn.close(0u32.into(), b"probe round done");
        }
    }

    summarise("dial_ms", &dial_samples);
    summarise("rtt_ms", &rtt_samples);
    println!(
        "summary rounds={} failures={} relayed={}",
        args.rounds, failures, relayed
    );

    ep.close().await;
    if failures > 0 {
        // Non-zero exit so an `adb shell ... ; echo $?` loop or a CI step
        // can tell a clean run from a partially-failed one.
        std::process::exit(1);
    }
    Ok(())
}

async fn ping(conn: &mshr::Connection) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(PING).await?;
    send.finish()?;
    let got = recv.read_to_end(64).await?;
    if got != PONG {
        bail!("expected pong, got {:?}", String::from_utf8_lossy(&got));
    }
    Ok(())
}

fn summarise(label: &str, samples: &[u128]) {
    if samples.is_empty() {
        println!("summary {label} n=0");
        return;
    }
    let mut s = samples.to_vec();
    s.sort_unstable();
    let sum: u128 = s.iter().sum();
    println!(
        "summary {label} n={} min={} median={} max={} mean={}",
        s.len(),
        s[0],
        s[s.len() / 2],
        s[s.len() - 1],
        sum / s.len() as u128
    );
}

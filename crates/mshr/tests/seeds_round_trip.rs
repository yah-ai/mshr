//! End-to-end acceptance for [`mshr::Seeds`] (R609-F4).
//!
//! The ticket's second verify: *"`--xlb-seed` points it at an alternate seed
//! and it still connects."* Everything here runs offline — two in-process
//! endpoints, no relay, no pkarr, no network — because the thing under test
//! is whether a seed **string** an operator typed turns into a working dial,
//! and that question does not need n0's infrastructure to answer.
//!
//! What is deliberately *not* covered, and cannot be here: the shipped
//! default (n0's relay map + pkarr relay) requires reaching n0. Its
//! composition is asserted in `seeds.rs`'s unit tests; its *reachability* is
//! an operational check, not a test. See
//! `.yah/docs/guides/xlb-seeds-and-relays.md`.
//!
//! Part of R609-F4 — annotation in
//! `.yah/docs/working/W242-yubaba-mesh-raft-roadmap.md`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mshr::endpoint::{Alpn, AlpnHandler, BoxFut};
use mshr::{Connection, Endpoint, Keypair, RelayChoice, Seed, Seeds};

const ALPN: &[u8] = b"mshr/test/seeds/v1";

/// Spawn an echo handler on `ep` and return its task handle.
fn serve_echo(ep: &Endpoint) -> tokio::task::JoinHandle<()> {
    let ep = ep.clone();
    tokio::spawn(async move {
        let mut handlers: HashMap<Alpn, AlpnHandler> = HashMap::new();
        handlers.insert(
            ALPN.to_vec(),
            Arc::new(move |conn: Connection| {
                Box::pin(async move {
                    let (mut send, mut recv) = conn.accept_bi().await?;
                    let buf = recv.read_to_end(1024).await?;
                    send.write_all(&buf).await?;
                    send.finish()?;
                    let _ = conn.closed().await;
                    Ok(())
                }) as BoxFut<'static, anyhow::Result<()>>
            }),
        );
        let _ = ep.accept_dispatch(handlers).await;
    })
}

/// The headline: an operator pins a peer with one `--xlb-seed` string, and a
/// dial carrying **nothing but that peer's NodeId** connects.
///
/// This is the whole shape of the feature — the seed string is the only place
/// an address appears, and the camp spec never sees one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pinned_seed_makes_a_bare_node_id_dialable() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,mshr=info")
        .with_test_writer()
        .try_init();

    // Alice: reachable, but advertising herself to nobody.
    let alice = Seeds::none()
        .apply(Endpoint::builder())
        .keypair(Keypair::generate())
        .alpns([ALPN])
        .bind()
        .await
        .expect("alice bind");
    let alice_id = alice.node_id();
    let echo = serve_echo(&alice);

    // The string an operator would put behind `--xlb-seed` / `$YAH_XLB_SEED`,
    // built from alice's real bound address. Round-tripped through parsing on
    // purpose: a seed that only works when constructed in Rust is not the
    // feature.
    let spelled = format!(
        "mshr://{alice_id}{}",
        alice
            .endpoint_addr()
            .ip_addrs()
            .enumerate()
            .map(|(i, a)| format!("{}addr={a}", if i == 0 { '?' } else { '&' }))
            .collect::<String>()
    );
    let seed: Seed = spelled.parse().expect("the seed string parses");
    assert!(
        seed.is_resolvable_alone(),
        "alice must have bound at least one address: {spelled}"
    );

    let seeds = Seeds::none().with_pinned([seed]);
    assert!(seeds.resolves_bare_node_ids());

    let bob = seeds
        .apply(Endpoint::builder())
        .keypair(Keypair::generate())
        .alpns([ALPN])
        .bind()
        .await
        .expect("bob bind");
    assert!(
        bob.resolves_bare_node_ids(),
        "the pin must survive into the bound endpoint — this is what a dialer \
         checks before refusing a bare NodeId"
    );

    // The dial: a bare NodeId, no address anywhere in the call.
    let conn = tokio::time::timeout(
        Duration::from_secs(20),
        bob.connect_alpn(mshr::EndpointAddr::new(alice_id), ALPN),
    )
    .await
    .expect("connect within 20s")
    .expect("bob connects to alice through the pinned seed");

    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(b"seeded").await.expect("write");
    send.finish().expect("finish");
    assert_eq!(recv.read_to_end(1024).await.expect("read"), b"seeded");
    conn.close(0u32.into(), b"done");

    alice.close().await;
    bob.close().await;
    echo.abort();
}

/// The negative half. With no lane configured the same dial fails *quickly*,
/// not by hanging to the QUIC timeout — which is better than this ticket
/// assumed going in, and is why the claim is pinned here rather than asserted
/// in prose.
///
/// Refusing up front in `rpc_ssh::MshrRpcConfig::endpoint_addr` still earns
/// its keep, but for a smaller reason than "otherwise it hangs": the error a
/// caller can render says only `"No addressing information available"`, naming
/// no lane and no setting. (iroh does log the actionable `"No address lookup
/// configured"` — but at WARN, on the dialer, where nobody is looking.) Both
/// halves are asserted below so that rationale cannot quietly go stale.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_lane_the_same_dial_fails_fast_with_an_iroh_side_reason() {
    let alice = Seeds::none()
        .apply(Endpoint::builder())
        .keypair(Keypair::generate())
        .alpns([ALPN])
        .bind()
        .await
        .expect("alice bind");
    let alice_id = alice.node_id();
    let echo = serve_echo(&alice);

    let bob = Seeds::none()
        .apply(Endpoint::builder())
        .keypair(Keypair::generate())
        .alpns([ALPN])
        .bind()
        .await
        .expect("bob bind");
    assert!(!bob.resolves_bare_node_ids());

    let err = tokio::time::timeout(
        Duration::from_secs(3),
        bob.connect_alpn(mshr::EndpointAddr::new(alice_id), ALPN),
    )
    .await
    .expect("iroh refuses promptly rather than waiting out a timeout")
    .expect_err("an unresolvable bare NodeId cannot connect")
    .to_string();
    assert!(
        err.contains("No addressing information available"),
        "unexpected failure shape: {err}"
    );
    // …and that is exactly why the up-front refusal earns its keep: the
    // message names no lane, no variable, and no next step. `mshr` logs the
    // real cause ("No address lookup configured") at WARN, but the error a
    // caller can actually render says only that there was no address.
    assert!(
        !err.contains("lookup"),
        "if iroh ever names the missing lane here, rpc_ssh's up-front refusal \
         becomes redundant and should be revisited: {err}"
    );

    alice.close().await;
    bob.close().await;
    echo.abort();
}

/// The ticket's *first* verify — "a node with no `--xlb-seed` reaches the
/// default relay and becomes dialable" — against the real shipped default.
///
/// `#[ignore]` because it needs the public internet: it publishes this
/// endpoint's `EndpointInfo` to n0's pkarr relay and reads it back from
/// another endpoint in the same process. That is a genuine dependency on
/// third-party infrastructure being up, which is an operational check rather
/// than a unit of CI. Run it deliberately:
///
/// ```text
/// cargo test -p mshr --test seeds_round_trip -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the public internet: publishes to and resolves from n0's pkarr relay"]
async fn the_shipped_default_makes_a_node_dialable_with_no_configuration() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,mshr=info,iroh=info")
        .with_test_writer()
        .try_init();

    let alice = Seeds::defaults()
        .apply(Endpoint::builder())
        .keypair(Keypair::generate())
        .alpns([ALPN])
        .bind()
        .await
        .expect("alice bind");
    let alice_id = alice.node_id();
    let echo = serve_echo(&alice);

    // Let alice settle on a relay home and publish her record. Without this
    // the lookup can race the publish and fail for a reason that has nothing
    // to do with the configuration under test.
    alice.inner().online().await;
    eprintln!("alice published as {alice_id}");

    let bob = Seeds::defaults()
        .apply(Endpoint::builder())
        .keypair(Keypair::generate())
        .alpns([ALPN])
        .bind()
        .await
        .expect("bob bind");

    let conn = tokio::time::timeout(
        Duration::from_secs(30),
        bob.connect_alpn(mshr::EndpointAddr::new(alice_id), ALPN),
    )
    .await
    .expect("the default lanes resolve within 30s")
    .expect("bob reaches alice knowing only her NodeId");

    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(b"default-lanes").await.expect("write");
    send.finish().expect("finish");
    assert_eq!(
        recv.read_to_end(1024).await.expect("read"),
        b"default-lanes"
    );
    conn.close(0u32.into(), b"done");

    alice.close().await;
    bob.close().await;
    echo.abort();
}

/// A self-hosted relay reaches the endpoint through `Seeds`, not around it:
/// `--xlb-relay https://…` has to end up as the endpoint's relay map, and it
/// has to be the *only* thing in it. A silent n0 fallback next to an
/// operator's own relay would send traffic somewhere they explicitly opted
/// out of.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_self_hosted_relay_replaces_the_shipped_one() {
    let seeds = Seeds::defaults()
        .with_relays(RelayChoice::parse_list(["https://relay.example.org/"]).unwrap());
    let map = seeds
        .relay_map()
        .expect("a custom relay yields a relay map");
    let urls: Vec<String> = map.urls::<Vec<_>>().iter().map(|u| u.to_string()).collect();
    assert_eq!(
        urls.len(),
        1,
        "the shipped relays must not survive: {urls:?}"
    );
    assert!(urls[0].contains("relay.example.org"), "{urls:?}");

    // And it survives into a real bind — a relay map that only exists in the
    // Seeds value would be a configuration that does nothing.
    let ep = seeds
        .apply(Endpoint::builder())
        .keypair(Keypair::generate())
        .alpns([ALPN])
        .insecure_skip_tls_verify(true)
        .bind()
        .await
        .expect("bind with a custom relay map");
    ep.close().await;
}

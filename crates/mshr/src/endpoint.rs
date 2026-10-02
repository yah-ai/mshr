//! Thin wrapper around `iroh::Endpoint`. The wrapper exists so consumers
//! `use mshr::Endpoint` rather than `iroh::Endpoint` — one upgrade
//! point for the pre-1.0 substrate, and a transparent fork escape hatch.
//!
//! This phase (R105-F1) intentionally exposes the bare minimum API needed
//! for two endpoints in the same process to round-trip a stream:
//!
//! ```ignore
//! use mshr::{Endpoint, Keypair};
//!
//! let alice = Endpoint::builder()
//!     .keypair(Keypair::generate())
//!     .alpns(["yah/test/v1"])
//!     .bind().await?;
//!
//! let bob = Endpoint::builder()
//!     .keypair(Keypair::generate())
//!     .alpns(["yah/test/v1"])
//!     .bind().await?;
//!
//! let alice_addr = alice.endpoint_addr();
//! let conn = bob.connect_alpn(alice_addr, b"yah/test/v1").await?;
//! ```
//!
//! Discovery aggregation (mDNS / iroh-relay swarm / static / external
//! roster) lands in R105-F2..F3; this scaffolding deliberately leaves the
//! peer-resolution surface narrow.
//!
//! The accept path also carries a pluggable connection-acceptor hook
//! (R593-F3): register one via [`EndpointBuilder::acceptor`] to see each
//! incoming peer's authenticated [`NodeId`] and accept/deny it before
//! [`Endpoint::accept_dispatch`] hands the connection to its ALPN
//! handler. mshr stays account-agnostic — see [`Acceptor`]'s docs for
//! what the hook does and does not know.
//!
//! # Unreliable datagrams (R609-F6)
//!
//! A QUIC stream is the wrong carrier for a realtime class: it retransmits
//! and head-of-line blocks, so a late frame delays every frame behind it and
//! then arrives after its slot anyway. Datagrams are the right one — lost,
//! reordered, never retransmitted, and capped at one packet.
//!
//! **They ride [`Connection`], not [`Endpoint`], and that is deliberate.** A
//! datagram belongs to an established connection: its size limit is that
//! connection's current path MTU and its permission is that peer's advertised
//! transport parameter, neither of which an endpoint-level method could
//! answer for. So the surface is the one mshr already hands you — from
//! [`Endpoint::connect_alpn`] or from an [`AlpnHandler`] — plus everything
//! needed to use it without a direct `iroh` dependency:
//!
//! ```ignore
//! use mshr::{Bytes, SendDatagramError};
//!
//! let conn = ep.connect_alpn(peer, b"society/audio/1").await?;
//! // A path property, not a constant: re-read it, do not cache it.
//! let cap = conn.max_datagram_size().ok_or("peer refuses datagrams")?;
//! match conn.send_datagram(Bytes::from(frame)) {
//!     Ok(()) => {}
//!     Err(SendDatagramError::TooLarge) => { /* re-encode smaller */ }
//!     Err(e) => return Err(e.into()),
//! }
//! let inbound = conn.read_datagram().await?;
//! ```
//!
//! Three properties worth knowing before building on it:
//!
//! - **`max_datagram_size()` changes over the life of a connection.** It
//!   follows the path MTU estimate and the peer's advertised limit. Sizing a
//!   buffer from it once and keeping the number is how a working sender
//!   starts returning [`SendDatagramError::TooLarge`] after a path change.
//! - **`send_datagram` never blocks and never fragments.** It either queues
//!   the datagram or refuses it, and when the send buffer is full it evicts
//!   *older* datagrams to make room — newest-wins, which is what a realtime
//!   class wants. [`EndpointBuilder::datagram_send_buffer_size`] is what
//!   decides how deep the backlog gets before that kicks in.
//! - **`None` from `max_datagram_size()` is a real answer, not an error.**
//!   The peer disabled inbound datagrams
//!   ([`EndpointBuilder::datagram_receive_buffer_size`] with `None`), so a
//!   sender must fall back to a stream rather than retry.
//!
//! What is still *not* reachable here, so nobody re-derives it: **per-packet
//! DSCP / ToS marking.** All ALPNs multiplex over one UDP socket, and neither
//! iroh nor noq exposes per-datagram ToS — this is not an mshr omission that
//! a re-export fixes, and no escape hatch on this crate reaches it either.
//!
//! [`SendDatagramError::TooLarge`]: crate::SendDatagramError::TooLarge
//!
//! @yah:ticket(R609-F6, "Expose unreliable datagrams on mshr::Endpoint — QUIC streams are wrong for realtime classes; quinn already supports them, mshr does not surface them")
//! @yah:status(review)
//! @yah:at(2026-07-28T20:05:53Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R609)
//! @yah:next("OPEN QUESTION CARRIED FORWARD, not answered here: whether xlb wants datagrams for probe/keepalive traffic. Nothing in xlb asks for them today, so shaping the API around a hypothetical second consumer would have been speculative — but the surface that landed is connection-level and consumer-neutral, so it costs nothing if xlb does.")
//! @yah:next("VERSION NOT BUMPED — mshr stays 0.8.21. This is an additive change and the release flow owns versions; note that noisetable's crates/society/core/Cargo.toml pins `mshr = { version = \"0.8.21\" }`, so bumping here means bumping there or [patch.crates-io] stops applying with a 'patch was not used' warning.")
//! @yah:next("Per-packet DSCP / ToS is NOT reachable and is not a follow-up on this crate. Neither iroh nor noq exposes a per-datagram ToS/ECN setting, so `Endpoint::inner()` reaches nothing useful — making it real is an upstream iroh change. Recorded in the module doc so nobody re-derives it.")
//! @yah:handoff("SHIPPED. The premise needed correcting first: mshr was NOT streams-only. `Connection` is a re-export of `iroh::endpoint::Connection`, which has carried `send_datagram` / `send_datagram_wait` / `read_datagram` / `max_datagram_size` / `datagram_send_buffer_space` all along, and noq enables datagrams by default (receive buffer Some(~1.25 MB)). So the ask was never 'build datagram support' — it was 'make it callable'. What actually blocked a consumer: `SendDatagramError` and `bytes::Bytes` were unnameable from mshr, so calling `send_datagram` required the direct `iroh` dependency this crate exists to remove.")
//! @yah:handoff("SHAPE: NOT a first-class Endpoint method, and the ticket's request for one is declined with a reason. A datagram belongs to a CONNECTION — its size limit is that connection's current path MTU and its permission is that peer's advertised transport parameter. An `Endpoint::send_datagram` could not answer either without being handed the connection back, so it would be a worse spelling of what `connect_alpn` already returns. A `Datagrams` newtype over `Connection` was also considered and rejected: it would rename five methods that already exist and read correctly.")
//! @yah:handoff("LANDED: (1) lib.rs re-exports `Bytes`, `SendDatagramError`, `SendDatagram`, `ReadDatagram` beside the existing `Connection`/`ConnectionError` — the whole call surface nameable from mshr. (2) TWO REAL CAPABILITY ADDITIONS that no re-export gives you: `EndpointBuilder::datagram_send_buffer_size(usize)` and `datagram_receive_buffer_size(Option<usize>)`, threading a `QuicTransportConfig` into the iroh builder. Built from `QuicTransportConfig::builder()` (NOT noq's default — iroh's builder layers keep-alive / multipath / NAT-traversal overrides that are load-bearing for holepunching) and installed only when a knob was actually set, so iroh stays free to change values we do not name. (3) A `# Unreliable datagrams` section on the endpoint module doc.")
//! @yah:handoff("WHY THE SEND-BUFFER KNOB IS THE PART THAT MATTERS. noq's default outgoing datagram buffer is 1 MiB, and `send_datagram` makes room by evicting the OLDEST queued datagrams — newest-wins, which is the right policy for a realtime class. But at 1 MiB it does not engage until roughly a megabyte of already-stale audio is queued behind a stalled path: several seconds at A108's 192 B / 1 ms frames. Sizing this to a few frames is what turns newest-wins from a nominal property into a latency bound. mshr does NOT change the default — xlb and yubaba are not realtime — it exposes the knob and documents the reasoning.")
//! @yah:handoff("FOUR TESTS, all in endpoint.rs, all using only mshr's own surface with no `iroh` import: datagram_round_trip (through a real accept_dispatch ALPN handler; resends until the echo returns, because this is the unreliable path and a single-shot assert would be a flake generator); max_datagram_size_is_readable_and_oversize_is_refused (cap >= 1024 B for A108's vivarium_cv, and cap+1 is `TooLarge` rather than fragmented — the refusal is the feature); receive_buffer_none_refuses_at_the_sender (proves the knob reaches the transport parameters of an ACCEPTED connection, not just a dialed one: the dialer sees `max_datagram_size() == None` and `UnsupportedByPeer`, i.e. a fallback signal rather than a black hole); send_buffer_size_reaches_the_connection (asserts the number, not the call).")
//! @yah:handoff("CONSUMER-SIDE PROOF landed in the noisetable camp under R114-T5: `society_facility::net::endpoint`'s `a_realtime_protocol_can_carry_datagrams` round-trips a 1 ms PCM16 frame on the real `society/audio/1` ALPN importing only `mshr::Bytes`. society has no `iroh` dependency at all, so that test failing to compile would be the regression signal for this whole ticket.")
//! @yah:verify("cd oss/mshr && cargo test -p mshr --lib   # 24 passed, 0 failed (4 are the new datagram tests)")
//! @yah:verify("cd oss/mshr && cargo clippy -p mshr --all-targets   # clean")
//! @yah:verify("cd oss/mshr && RUSTDOCFLAGS='-D warnings' cargo doc -p mshr --no-deps   # clean")
//! @yah:verify("cd oss/xlb && cargo check -p xlb --all-targets   # clean — additive change breaks no consumer")
//! @yah:verify("cd oss/yubaba && cargo check -p yubaba   # clean")
//!
//! @yah:relay(R945, "mshr endpoint lifecycle over noq/iroh 1.0.0-rc.0: close and rebind")
//! @yah:at(2026-09-28T00:29:08Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//!
//! @yah:ticket(R945-B1, "Endpoint::close never drains a server-side connection mid-handshake (MultipathNotNegotiated), noq/iroh 1.0.0-rc.0")
//! @yah:status(review)
//! @yah:at(2026-09-28T01:54:41Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R945)
//! @yah:severity(high)
//! @yah:next("Found by noisetable R749-B14 (2026-09-27). REPRO: two noisetable-desktop instances on one Mac, both in open durable rooms on the LAN lane. Rebind both at the same moment, which is what a multi-role etude Join does. Just before the rebind, desk A dials desk B on society/clock/1, and B accepts A's Initial. Then both call mshr Endpoint::close -> iroh EndpointInner::close -> noq Endpoint::close + wait_idle. A's close takes exactly 3.0s: a 3xPTO drain at the initial RTT, because A's own half-open handshake gets no reply. B's close NEVER returns. B's server-side connection (noq id=2) logs `WARN noq_proto::connection failed closing path err=MultipathNotNegotiated` about 15s later, and wait_idle is still pending at 30s. Healthy closes take 80-270ms. Rate: ~15-25% of noisetable `./scripts/etude-rigs.sh --no-build desktop-desktop` runs, with RUST_LOG=noq=debug,iroh=debug. EVIDENCE (on the noisetable machine): /tmp/b14r_i5/run4/desk-b.log lines 840-899 (B, hung close) and desk-a.log (A, the 3s close); a second capture is in /tmp/b14r_i4/run6.")
//! @yah:next("Why a caller cannot bound it: once close has started, iroh EndpointInner::abort() returns early on is_closing(), so a timed-out close cannot be forced down and the UDP socket stays held by the noq drivers until the stuck connection drains. Wanted: (1) the stuck connection fixed upstream in noq (a server connection closed before multipath negotiation should still drain in 3xPTO); (2) mshr, and ideally iroh, gains a close that can be abandoned at a deadline and then really tears the endpoint down, releasing its sockets. noisetable works around this with a bounded close in crates/noise_table/core/src/node.rs spawn_society_endpoint (R749-B14).")
//! @yah:next("MEASURED 2026-09-27 in noisetable R749-B14: a caller has NO way to release the ports. (a) Bounding iroh close() with a 1s timeout and then dropping the mshr Endpoint leaves the UDP sockets bound, so the next bind on the same ports fails with 'Failed to bind sockets' (/tmp/b14r_bc/run5). (b) Skipping close() and just dropping the Endpoint, iroh's abort path, ALSO never frees the ports: 12/12 rebinds fell back to fresh ports (/tmp/b14r_drop). A caller that must keep its address across a rebind (a peer or controller holding ip:port) therefore needs mshr to own a close that releases its sockets at a deadline, or the noq drain fix.")
//! @yah:handoff("ROOT CAUSE (noq-proto 1.0.0-rc.0, crates.io, n0-owned; read in source): a server Connection whose FIRST datagram is the dialer's handshake-time CONNECTION_CLOSE (an Initial carrying only the close, which happens when the dialer's ClientHello never reached us and it then closed) enters Draining with no drain timer. Path: proto Endpoint::accept -> Connection::handle_first_packet -> process_decrypted_packet -> process_early_payload `Frame::Close => state.move_to_draining(..); return Ok(())`. handle_first_packet calls process_decrypted_packet directly, so it skips handle_packet's post-transition bookkeeping (connection/mod.rs ~4393: `if !was_closed && state.is_closed() { close_common(); set_close_timer(now) }`). The endpoint's later Close event is then a no-op (close_inner returns early on is_closed()). Nothing drains the connection except ConnTimer::Idle, i.e. noq's default max_idle_timeout of 30s. The `failed closing path err=MultipathNotNegotiated` warn is a symptom and not the cause: iroh's PATH_MAX_IDLE_TIMEOUT (15s) PathIdle timer was never reset (close_common never ran), and close_path_inner refuses because multipath was never negotiated. The ticket's hypothesis (a per-path close erroring and blocking the drain) is disproven. Evidence: /tmp/b14r_i5/run4/desk-b.log shows conn id=2 created from 192.168.0.36 and failing in mshr 'aborted by peer ... during the handshake' with no poll_send to that remote at all, and the warn fires 15s later.")
//! @yah:handoff("CORRECTION: close does not hang forever. The repro measured bob.close() at 29.69s, which is 30s idle minus the gap before close started. It was 'forever' only relative to the 30s budget.")
//! @yah:handoff("REPRO (mshr, fails before the fix): oss/mshr/crates/mshr/src/endpoint.rs test `close_is_bounded_when_a_dial_was_aborted_before_we_saw_it`. A UDP hop in front of bob drops alice's ClientHello, then opens just before alice.close(), so bob's first packet for that connection is the close-only Initial. Unfixed: FAILED, 'bob.close() still pending after 10.0s'; with a temporary 45s budget it took 29.69s. Fixed: passes in 5.6s. Outcome is Forced, close returns within DEFAULT_CLOSE_DEADLINE+2s, and bob's exact port rebinds within 1s.")
//! @yah:handoff("FIX, in mshr, because noq/iroh are plain crates.io. iroh cannot abandon a close once it has started (abort() returns early on is_closing()), and it can cancel its tasks only through a private runtime token. So mshr now owns the task lifetime. New private `Driver`: a per-endpoint single-worker tokio runtime (thread `mshr-endpoint`). bind, connect_alpn, and the accept_dispatch handshake run on it via Driver::run, so noq's endpoint and connection drivers are spawned there. The ALPN handlers still run on the caller's runtime. `Endpoint::close()` now returns `CloseOutcome` and is bounded by the new `pub const DEFAULT_CLOSE_DEADLINE` (5s). The new `close_within(Duration)` runs iroh's graceful close; past the deadline it drops the runtime (spawn_blocking shutdown_timeout), which drops the drivers holding the sockets. Result is Drained or Forced, and it is idempotent through a OnceCell, so concurrent callers share the first outcome. The ports free once the last Endpoint clone drops, the same contract as a drained close. `Driver` Drop does shutdown_background. Exports: lib.rs CloseOutcome and DEFAULT_CLOSE_DEADLINE; CHANGELOG [Unreleased] entry 'Changed - Endpoint::close is bounded and releases its sockets'. Documented limit: connections created via inner() or a raw accept() Incoming spawn their driver on the caller's runtime, out of a forced close's reach.")
//! @yah:handoff("WHY NOT THE ALTERNATIVES: an iroh custom transport (unstable-custom-transports) would change the address family peers dial and break the LAN/IP lanes. A shorter max_idle_timeout would bound only the wait, still not to 1s, and would change idle semantics for every connection. SO_REUSEPORT is ambiguous for unicast UDP. A plain drop, i.e. iroh's abort path, only works when no close has started.")
//! @yah:handoff("VERIFIED. mshr: `cargo test -p mshr` gives lib 60 passed / 0 failed / 6 ignored; relay_round_trip 2, seeds 3, others green. The baseline lib was 59 + 6 ignored plus this new test, which failed pre-fix. clippy --all-targets: 0 warnings. `cargo check` on xlb (--all-targets) and yubaba: clean. noisetable consumer (R749-B14): 12/12 desktop-desktop rig runs pass with 0 redial misses; see that ticket.")
//! @yah:handoff("DRAFTED UPSTREAM ISSUE for n0-computer/noq. NOT FILED: outward-facing, operator's call. Title: 'Server connection closed by its first packet never arms the drain timer (waits out max_idle_timeout)'. Body: if the first Initial a server accepts carries CONNECTION_CLOSE (the client aborted a dial whose earlier Initials were lost), Endpoint::accept -> Connection::handle_first_packet -> process_decrypted_packet -> process_early_payload moves the state to Draining but returns Ok. handle_first_packet bypasses handle_packet's `!was_closed && is_closed()` block, so close_common()/set_close_timer() never run. Endpoint::close() then no-ops on that connection, and Endpoint::wait_idle (hence iroh Endpoint::close) blocks until the 30s idle timer kills it. Stale PathIdle timers also fire and warn `failed closing path err=MultipathNotNegotiated`. Suggested patch: in handle_first_packet, after process_decrypted_packet, `if self.state.is_closed() { self.close_common(); if !self.state.is_drained() { self.set_close_timer(now) } }` (mirroring handle_packet), or route the first packet through the same post-processing. The repro shape is in mshr's test above.")
//! @yah:gotcha("`RUSTDOCFLAGS='-D warnings' cargo doc -p mshr --no-deps` is RED, but not from this change: 4 pre-existing `unresolved link to Unreleased` errors inside other tickets' @yah prose (discovery.rs:49, endpoint.rs:203 R944, lan/mod.rs:516-517).")
//! @yah:gotcha("Performance shift for every consumer: iroh/noq drivers now run on one dedicated `mshr-endpoint` worker per endpoint instead of the caller's runtime threads. That thread's QoS/priority is tokio's default. A realtime consumer (A108 datagrams) may want a knob for its priority.")

use std::collections::HashMap;
use std::future::{Future, IntoFuture};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{presets, BindOpts, Connection, Incoming, QuicTransportConfig};
use iroh::tls::CaRootsConfig;
use iroh::{RelayMap, RelayMode};

use crate::{Discovery, EndpointAddr, Error, Keypair, NodeId, Result};

/// ALPN bytes type alias — picked up from `iroh`'s convention.
pub type Alpn = Vec<u8>;

/// Pinned, boxed, send-able future. Inlined to avoid pulling `futures`
/// solely for one type alias at this phase.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Async handler for an accepted incoming connection on a particular ALPN.
///
/// Boxed for object safety; consumers usually wrap a method on a
/// per-protocol struct (e.g. `society::handle_v1`) in an `Arc`.
pub type AlpnHandler =
    Arc<dyn Fn(Connection) -> BoxFut<'static, anyhow::Result<()>> + Send + Sync + 'static>;

/// Decision returned by an [`Acceptor`] for one incoming connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptDecision {
    /// Accept the connection; hand it on to application dispatch (the
    /// [`AlpnHandler`] registered for its ALPN in [`Endpoint::accept_dispatch`]).
    Accept,
    /// Deny the connection. It is closed immediately — the registered
    /// `AlpnHandler` never runs and no application bytes are exchanged.
    Deny,
}

/// Pluggable connection-acceptor hook, registered via
/// [`EndpointBuilder::acceptor`].
///
/// Invoked once per incoming connection, immediately after the QUIC/TLS
/// handshake completes and *before* the connection reaches application
/// dispatch. iroh's handshake is mutually authenticated by construction —
/// the [`NodeId`] handed to [`Acceptor::accept`] comes from the peer's
/// verified TLS certificate, so no additional proof-of-possession step is
/// needed here.
///
/// mshr stays account-agnostic: this trait yields only the authenticated
/// `NodeId` and a decision. *Whether that NodeId is enrolled to anything*
/// (a user account, a fleet admission record) is a consumer's job —
/// kamaji-bin auth, yubaba admission. mshr never depends on the ledger
/// that answers that question (W268 "What stays deliberately separate":
/// the crate-DAG rule that mshr never depends on cheers or any
/// account/ledger crate — the binding is data in cheers, enforced by
/// services, never by the transport).
///
/// Implement this trait directly for stateful hooks (e.g. one holding a
/// ledger client); the blanket impl below covers the common case of a
/// plain `async fn(NodeId) -> AcceptDecision` closure.
pub trait Acceptor: Send + Sync + 'static {
    /// Decide whether to accept a connection from `remote`.
    fn accept(&self, remote: NodeId) -> BoxFut<'static, AcceptDecision>;
}

impl<F, Fut> Acceptor for F
where
    F: Fn(NodeId) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = AcceptDecision> + Send + 'static,
{
    fn accept(&self, remote: NodeId) -> BoxFut<'static, AcceptDecision> {
        Box::pin(self(remote))
    }
}

/// Builder for [`Endpoint`]. Returned by [`Endpoint::builder`].
///
/// @yah:relay(R944, "mshr 0.8.42: land + release noisetable's uncommitted EndpointBuilder additions (segmentation_offload, bind_addr, TransportAddr re-export)")
/// @yah:at(2026-10-01T23:04:08Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:next("Commit through yah's flow (NOT from noisetable): uncommitted in oss/mshr/crates/mshr. (1) noisetable R743-F27: EndpointBuilder::segmentation_offload(bool) in src/endpoint.rs (field + method + bind() wiring into QuicTransportConfig::enable_segmentation_offload, installed only when set, like the datagram knobs), test endpoint::tests::gso_off_still_carries_a_multi_megabyte_stream (3 MiB stream, GSO off both ends), CHANGELOG [Unreleased] entry 'Added - EndpointBuilder::segmentation_offload'. Why: iroh 1.0.0-rc.0 snapshots max_transmit_segments at TransportsSender creation (iroh socket/transports.rs:415, :1201), so noq-udp's EIO GSO fallback never reaches the connection and every multi-datagram flight is dropped on a NIC without GSO (Android emulator). (2) noisetable R743-F26: EndpointBuilder::bind_addr(addr, prefix_len) + `pub use iroh::TransportAddr` in lib.rs, tests bind_addr_pins_an_endpoint_to_its_named_socket / bind_addr_rejects_a_bad_prefix_at_bind.")
/// @yah:next("Bump mshr to 0.8.42 (working copy is 0.8.41) and publish. `cargo test -p mshr --lib endpoint::` was 17 passed on 2026-09-25.")
/// @yah:next("Unblocks noisetable: society_facility compiles today only under `scripts/devcrate.sh on mshr`. After the release noisetable sets crates/society/core/Cargo.toml mshr = 0.8.42 and runs `scripts/devcrate.sh off mshr` (tracked there on R743-F26 + R743-F27). Upstream follow-up worth filing with iroh: re-read max_transmit_segments after a GSO fallback instead of caching it.")
/// @yah:handoff("2026-10-01: code + tests were already committed by sync commits (8fb16523..84caba1e); only gap was a CHANGELOG entry for bind_addr/TransportAddr, now added under [Unreleased] in oss/mshr/crates/mshr/CHANGELOG.md. cargo test -p mshr --lib endpoint:: -> 18 passed, 0 failed, 1 ignored. Operator asked for a full lockstep release instead of an mshr-only bump: started yah-release-wizard spec=0.8.42, run c8f664f2-5df6-4c0e-b07e-ec6a2f1a07a6. It parks at authorize-release (operator gate).")
/// @yah:gotcha("The wizard's commit-and-tag runs `git commit -a` on the live tree, so it sweeps in whatever is uncommitted at that moment. At launch that included oss/cheers/crates/cheers-axum/src/passkey.rs and .yah/AGENTS.md, which are not R944 edits.")
/// @yah:handoff("Wizard reruns at 0.8.42 were blocked by stale tests left by the store-plugin commits (3c7c8665/8fb16523), fixed in this pass: (a) app/yah/cli/src/plugin_grants.rs every_builtin_manifest_lowers_on_both_backends gained a yah-store arm (only outbound rule is the proxy's exact loopback port, proxy env set); live every_builtin_grant_set_produces_a_profile_that_boots now spawns with a stand-in egress proxy, since a hostname grant refuses to lower without one. plugin_grants:: 31/31 pass. (b) crates/yah/agent-tools/src/skill_tools.rs tripwire 11 -> 14 (chaos, store-asset-portal, store-console). Runs c8f664f2 and 1d900460 failed at release-check on these.")
/// @yah:handoff("More release-check fixes: (c) crates/yah/fleet-metrics/tests/fleet_inventory_split.rs us-west-014 EXPECTED -> 100.64.0.11 (R935-T4 re-join). (d) oss/yubaba/crates/yubaba/cluster-epochs.json cluster_protocol surface re-recorded, NOT BREAKING, surface_rerecords entry 2026-10-01: R937-F3 added a `machine` key to GET /raft/status member JSON; all consumers tolerate unknown keys. (e) xtask/tests/mirror_ingress.rs: us-south-001 now declares cap:bundle-serving on disk (R936-B12); in-memory grant narrowed to us-west-001 and capable list updated; its no-appliance taint keeps live placements unchanged. Full workspace cargo test + xtask tests + drift guards green locally.")
pub struct EndpointBuilder {
    keypair: Option<Keypair>,
    alpns: Vec<Alpn>,
    discovery: Option<Discovery>,
    relay_map: Option<RelayMap>,
    insecure_skip_tls_verify: bool,
    acceptor: Option<Arc<dyn Acceptor>>,
    datagram_send_buffer_size: Option<usize>,
    /// Outer `Option` is "was it set"; inner is the value, where `None`
    /// *disables* inbound datagrams. See
    /// [`EndpointBuilder::datagram_receive_buffer_size`].
    datagram_receive_buffer_size: Option<Option<usize>>,
    /// `(addr, prefix_len)` sockets that *replace* iroh's default wildcard
    /// sockets. Empty = iroh's defaults. See [`EndpointBuilder::bind_addr`].
    bind_addrs: Vec<(SocketAddr, u8)>,
    /// `Some(false)` turns UDP GSO off. `None` leaves iroh's default (on).
    /// See [`EndpointBuilder::segmentation_offload`].
    segmentation_offload: Option<bool>,
}

impl EndpointBuilder {
    fn new() -> Self {
        Self {
            keypair: None,
            alpns: Vec::new(),
            discovery: None,
            relay_map: None,
            insecure_skip_tls_verify: false,
            acceptor: None,
            datagram_send_buffer_size: None,
            datagram_receive_buffer_size: None,
            bind_addrs: Vec::new(),
            segmentation_offload: None,
        }
    }

    /// Bind an IP socket on `addr`, whose local subnet is `prefix_len` bits
    /// long. Repeatable. The first call **drops iroh's default wildcard
    /// sockets** (`0.0.0.0:0` / `[::]:0`), so the endpoint then has exactly
    /// the sockets named here and no others.
    ///
    /// This is how a caller pins an endpoint to one local interface: bind
    /// only that interface's address. The prefix feeds iroh's source-socket
    /// routing table (a destination inside the prefix leaves by this socket;
    /// see `iroh::endpoint::BindOpts::set_prefix_len`). It chooses a socket
    /// by subnet, not by interface — iroh sets no `IP_BOUND_IF` /
    /// `SO_BINDTODEVICE` — so two interfaces sharing one subnet cannot be
    /// told apart this way.
    ///
    /// Pinning is per *endpoint*, not per connection: iroh keeps one
    /// selected path per remote `NodeId` across all of an endpoint's
    /// connections to it. A caller wanting one connection on a different
    /// path than another to the same peer needs a second endpoint with its
    /// own keypair (R743-S15).
    ///
    /// Port 0 picks an ephemeral port. An invalid `prefix_len` (> 32 for
    /// v4, > 128 for v6) or a second address of the same family is reported
    /// by [`EndpointBuilder::bind`].
    pub fn bind_addr(mut self, addr: SocketAddr, prefix_len: u8) -> Self {
        self.bind_addrs.push((addr, prefix_len));
        self
    }

    /// Attach a [`Discovery`] composition. When omitted, the endpoint
    /// binds with no address-lookup services — peers must be reachable
    /// via fully-formed `EndpointAddr`s passed to `connect_alpn`.
    pub fn discovery(mut self, d: Discovery) -> Self {
        self.discovery = Some(d);
        self
    }

    /// Register a connection-acceptor hook, invoked for every incoming
    /// connection (after the handshake completes, before application
    /// dispatch) with the peer's authenticated [`NodeId`]. Returning
    /// [`AcceptDecision::Deny`] closes the connection before its ALPN
    /// handler ever runs.
    ///
    /// Cheap sync-friendly default: when no acceptor is registered, every
    /// connection is accepted — current (pre-hook) behavior is unchanged.
    pub fn acceptor<A: Acceptor>(mut self, acceptor: A) -> Self {
        self.acceptor = Some(Arc::new(acceptor));
        self
    }

    /// Use a custom relay (typically a yubaba-hosted [`crate::relay::Server`])
    /// for NAT-traversal proxying and QUIC address discovery. Wraps
    /// `iroh::RelayMode::Custom`.
    ///
    /// Build the [`RelayMap`] via [`crate::relay::Server::relay_map`] (when
    /// hosting locally in a test) or [`crate::relay::relay_map_for_https`]
    /// (when the URL is known out-of-band, e.g. from fleet config).
    pub fn relay_map(mut self, map: RelayMap) -> Self {
        self.relay_map = Some(map);
        self
    }

    /// Skip TLS certificate verification on relay connections. **Tests
    /// only** — required when the relay uses a self-signed cert. Mirrors
    /// `iroh::CaRootsConfig::insecure_skip_verify()`.
    pub fn insecure_skip_tls_verify(mut self, skip: bool) -> Self {
        self.insecure_skip_tls_verify = skip;
        self
    }

    /// Bytes of *outgoing* datagram backlog to buffer. Defaults to noq's
    /// 1 MiB.
    ///
    /// This is the knob a realtime sender actually wants, and its default is
    /// wrong for one: when the buffer is full, [`Connection::send_datagram`]
    /// makes room by dropping the **oldest** queued datagrams, which is the
    /// right policy — but a 1 MiB buffer means it does not take effect until
    /// roughly a megabyte of already-stale audio or CV is queued behind a
    /// stalled path. Sizing this to a few frames is what turns "newest wins"
    /// from a nominal property into a latency bound. A sender that wants
    /// backpressure instead of drops should use
    /// [`Connection::send_datagram_wait`], which waits for space rather than
    /// evicting.
    pub fn datagram_send_buffer_size(mut self, bytes: usize) -> Self {
        self.datagram_send_buffer_size = Some(bytes);
        self
    }

    /// Whether QUIC may batch several datagrams into one UDP Generic
    /// Segmentation Offload send. Defaults to on (iroh's default).
    ///
    /// Turn it off on a host whose NIC cannot do GSO. In principle `noq-udp`
    /// falls back by itself: the first GSO `sendmsg` that fails with `EIO`
    /// sets its segment limit to 1. But iroh 1.0.0-rc.0 snapshots
    /// `max_transmit_segments` once, when the transport sender is created
    /// (`socket/transports.rs`), and keeps handing the connection the stale
    /// value. So every later multi-segment transmit is built anyway and dropped
    /// with `EIO`. Any flight larger than one datagram — a multi-MB stream
    /// write, and whatever is queued behind it — never arrives, and PTO
    /// retransmits of it are dropped the same way. Measured on the Android
    /// emulator, whose virtio NIC has no checksum offload (noisetable
    /// R743-F27).
    ///
    /// With this off, the connection itself caps every transmit at one
    /// datagram (`noq-proto`'s `enable_segmentation_offload`), so the stale
    /// socket value is never consulted. The cost is CPU per packet on bulk
    /// sends, not correctness.
    pub fn segmentation_offload(mut self, enabled: bool) -> Self {
        self.segmentation_offload = Some(enabled);
        self
    }

    /// Bytes of *incoming* datagram backlog to buffer, or `None` to refuse
    /// datagrams entirely. Defaults to noq's ~1.25 MB.
    ///
    /// This value is advertised to the peer in the transport parameters, so
    /// it does two things at once: it caps the aggregate unread backlog
    /// (older datagrams are dropped once it is exceeded) *and* it forbids the
    /// peer from sending any single datagram larger than it.
    ///
    /// `None` disables inbound datagrams and tells the peer so. Its
    /// `Connection::max_datagram_size()` then reports `None` and its sends
    /// fail with [`SendDatagramError::UnsupportedByPeer`] — a refusal at the
    /// sender rather than a silent black hole, which is why this is worth
    /// setting deliberately on a connection that has no datagram protocol.
    ///
    /// [`SendDatagramError::UnsupportedByPeer`]: crate::SendDatagramError::UnsupportedByPeer
    pub fn datagram_receive_buffer_size(mut self, bytes: Option<usize>) -> Self {
        self.datagram_receive_buffer_size = Some(bytes);
        self
    }

    /// Bind the endpoint to the given keypair. Required.
    pub fn keypair(mut self, kp: Keypair) -> Self {
        self.keypair = Some(kp);
        self
    }

    /// ALPN strings the endpoint will accept on. The accept loop dispatches
    /// to the registered handler matching the ALPN reported by the peer.
    pub fn alpns<I, S>(mut self, alpns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        self.alpns = alpns.into_iter().map(|s| s.as_ref().to_vec()).collect();
        self
    }

    /// Bind the endpoint, returning a clone-able handle.
    pub async fn bind(self) -> Result<Endpoint> {
        let keypair = self
            .keypair
            .ok_or_else(|| Error::Endpoint("EndpointBuilder: keypair() is required".into()))?;
        let alpns = self.alpns;

        // F1 uses the `Minimal` preset: it picks a TLS crypto provider but
        // does NOT install n0's DNS lookup or relay endpoints. F2/F3 layer
        // discovery on top; this phase keeps two in-process endpoints
        // self-sufficient for the round-trip test (and for any caller that
        // hands a fully-formed `EndpointAddr` out-of-band).
        let relay_mode = match self.relay_map {
            Some(map) => RelayMode::Custom(map),
            None => RelayMode::Disabled,
        };
        let mut b = iroh::Endpoint::builder(presets::Minimal)
            .secret_key(keypair.secret().clone())
            .relay_mode(relay_mode);
        if self.insecure_skip_tls_verify {
            b = b.ca_roots_config(CaRootsConfig::insecure_skip_verify());
        }
        // Only build a transport config when a datagram knob was actually
        // set. `QuicTransportConfig::builder()` is not `noq`'s default — it
        // layers iroh's own keep-alive / multipath / NAT-traversal overrides
        // on top, and those are load-bearing for holepunching — so it is the
        // right base to amend, but installing it unconditionally would still
        // pin values iroh is free to change between releases.
        if self.datagram_send_buffer_size.is_some()
            || self.datagram_receive_buffer_size.is_some()
            || self.segmentation_offload.is_some()
        {
            let mut tc = QuicTransportConfig::builder();
            if let Some(enabled) = self.segmentation_offload {
                tc = tc.enable_segmentation_offload(enabled);
            }
            if let Some(bytes) = self.datagram_send_buffer_size {
                tc = tc.datagram_send_buffer_size(bytes);
            }
            if let Some(bytes) = self.datagram_receive_buffer_size {
                tc = tc.datagram_receive_buffer_size(bytes);
            }
            b = b.transport_config(tc.build());
        }
        if !alpns.is_empty() {
            b = b.alpns(alpns.clone());
        }
        if !self.bind_addrs.is_empty() {
            b = b.clear_ip_transports();
            for (addr, prefix_len) in self.bind_addrs {
                b = b
                    .bind_addr_with_opts(addr, BindOpts::default().set_prefix_len(prefix_len))
                    .map_err(|e| Error::Endpoint(format!("bind_addr {addr}/{prefix_len}: {e}")))?;
            }
        }
        let mut resolves_bare_node_ids = false;
        if let Some(d) = self.discovery {
            resolves_bare_node_ids = d.resolves_bare_node_ids();
            b = d.apply(b);
        }

        // Bind on the endpoint's own runtime so every task iroh spawns for
        // it (socket actors, the noq endpoint driver) lives there and can be
        // dropped by a forced close. See [`Driver`].
        let driver = Arc::new(Driver::new()?);
        let inner = driver
            .run(b.bind())
            .await?
            .map_err(|e| Error::Endpoint(format!("bind failed: {e}")))?;

        Ok(Endpoint {
            inner,
            driver,
            keypair,
            registered_alpns: Arc::new(alpns),
            acceptor: self.acceptor,
            resolves_bare_node_ids,
        })
    }
}

/// Process-wide endpoint handle. `Clone + Send + Sync`; clones share the
/// underlying socket and connection pool.
#[derive(Clone)]
pub struct Endpoint {
    inner: iroh::Endpoint,
    driver: Arc<Driver>,
    keypair: Keypair,
    registered_alpns: Arc<Vec<Alpn>>,
    acceptor: Option<Arc<dyn Acceptor>>,
    /// Snapshot of [`Discovery::resolves_bare_node_ids`] at bind time. Kept
    /// as a bool rather than the whole `Discovery` because `Discovery` is
    /// consumed by the iroh builder and the answer cannot change afterwards.
    resolves_bare_node_ids: bool,
}

impl Endpoint {
    /// Start a new builder. See [`EndpointBuilder`].
    pub fn builder() -> EndpointBuilder {
        EndpointBuilder::new()
    }

    /// This endpoint's `NodeId` (Ed25519 pubkey).
    pub fn node_id(&self) -> NodeId {
        self.keypair.node_id()
    }

    /// Borrow the keypair this endpoint was bound with.
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// ALPNs the endpoint was registered to accept on.
    pub fn alpns(&self) -> &[Alpn] {
        &self.registered_alpns
    }

    /// Snapshot the current `EndpointAddr` (NodeId + best-known direct addrs +
    /// optional relay URL). Useful for handing to a peer in tests or for
    /// out-of-band rendezvous before the discovery layer lands (F2/F3).
    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.inner.addr()
    }

    /// Whether this endpoint can dial a peer given nothing but its
    /// [`NodeId`] — i.e. whether a discovery lane that resolves addresses was
    /// configured at bind time (see
    /// [`Discovery::resolves_bare_node_ids`] and [`crate::Seeds`]).
    ///
    /// A dialer asks this so it can *refuse* a bare-NodeId dial with a
    /// reason. Attempting one on an endpoint with no resolver fails promptly
    /// but uselessly — `"No addressing information available"`, which names
    /// neither the missing lane nor the setting that supplies it.
    pub fn resolves_bare_node_ids(&self) -> bool {
        self.resolves_bare_node_ids
    }

    /// Borrow the wrapped `iroh::Endpoint`. Escape hatch — prefer the
    /// methods on this wrapper where possible so the dep stays swappable.
    ///
    /// A connection opened through it (`inner().connect(..)`) has its noq
    /// driver spawned on the *caller's* runtime rather than this endpoint's,
    /// so a forced [`Endpoint::close_within`] cannot drop it; and a clone of
    /// the `iroh::Endpoint` kept past close holds the UDP sockets open.
    pub fn inner(&self) -> &iroh::Endpoint {
        &self.inner
    }

    /// Open a connection to a peer by `EndpointAddr` on the given ALPN.
    pub async fn connect_alpn(
        &self,
        peer: impl Into<EndpointAddr>,
        alpn: &[u8],
    ) -> Result<Connection> {
        let (inner, peer, alpn) = (self.inner.clone(), peer.into(), alpn.to_vec());
        // On the endpoint's runtime: that is where noq spawns the
        // connection's driver task.
        self.driver
            .run(async move { inner.connect(peer, &alpn).await })
            .await?
            .map_err(|e| Error::Endpoint(format!("connect: {e}")))
    }

    /// The registered connection-acceptor hook, if any. `None` means the
    /// default accept-all behavior — see [`EndpointBuilder::acceptor`].
    pub fn acceptor(&self) -> Option<&Arc<dyn Acceptor>> {
        self.acceptor.as_ref()
    }

    /// Accept the next incoming connection (raw — no ALPN dispatch, and
    /// no handshake yet: `Incoming` is pre-handshake). This is an escape
    /// hatch for callers driving the handshake and dispatch themselves;
    /// it does **not** consult the registered [`Acceptor`] hook (there is
    /// no application dispatch step here for the hook to gate). Callers
    /// using this method who still want the same accept/deny policy
    /// should complete the handshake, read [`Connection::remote_id`], and
    /// consult [`Endpoint::acceptor`] themselves. Prefer
    /// [`Endpoint::accept_dispatch`], which wires the hook in for you.
    /// Returns `None` once the endpoint is closed.
    ///
    /// Awaiting the returned `Incoming` spawns its connection driver on the
    /// caller's runtime, out of reach of a forced [`Endpoint::close_within`]
    /// (see [`Endpoint::inner`]); `accept_dispatch` runs the handshake on the
    /// endpoint's own runtime.
    pub async fn accept(&self) -> Option<Incoming> {
        self.inner.accept().await
    }

    /// Run an ALPN-dispatching accept loop. Spawns a task per connection.
    /// For each: the handshake completes, the registered [`Acceptor`]
    /// hook (if any) is consulted with the peer's authenticated
    /// [`NodeId`], and only on [`AcceptDecision::Accept`] (or when no
    /// hook is registered) does the connection reach the handler
    /// registered for its ALPN. A [`AcceptDecision::Deny`] closes the
    /// connection immediately — no application bytes are exchanged and
    /// the ALPN handler never runs. Connections whose ALPN has no
    /// registered handler are dropped (logged at `tracing::warn`).
    ///
    /// The loop runs until the endpoint is closed; returns `Ok(())` after
    /// a clean shutdown.
    pub async fn accept_dispatch(&self, handlers: HashMap<Alpn, AlpnHandler>) -> Result<()> {
        let handlers = Arc::new(handlers);
        let acceptor = self.acceptor.clone();
        while let Some(incoming) = self.inner.accept().await {
            let handlers = handlers.clone();
            let acceptor = acceptor.clone();
            let driver = self.driver.clone();
            tokio::spawn(async move {
                if let Err(e) = dispatch_one(incoming, handlers, acceptor, &driver).await {
                    tracing::warn!(error = %e, "mshr accept_dispatch: connection failed");
                }
            });
        }
        Ok(())
    }

    /// Close the endpoint, forcing it down if it has not drained within
    /// [`DEFAULT_CLOSE_DEADLINE`]. See [`Endpoint::close_within`].
    pub async fn close(&self) -> CloseOutcome {
        self.close_within(DEFAULT_CLOSE_DEADLINE).await
    }

    /// Close the endpoint: close every connection, wait up to `deadline`
    /// for them to drain, then stop every task the endpoint runs.
    ///
    /// A graceful close waits until each connection has drained, which is
    /// normally 3×PTO. It can instead take noq's whole idle timeout (30 s):
    /// a server connection whose first packet was the dialer's
    /// handshake-time CONNECTION_CLOSE never gets a drain timer in noq
    /// 1.0.0-rc.0 (R945-B1). iroh cannot abandon its own close once started,
    /// so past `deadline` mshr drops the endpoint's runtime instead, and with
    /// it every driver still holding the UDP sockets. The sockets are then
    /// released when the last clone of this `Endpoint` is dropped, exactly
    /// as after a drained close.
    ///
    /// Idempotent: concurrent and later calls wait for, and return, the
    /// first call's outcome.
    pub async fn close_within(&self, deadline: Duration) -> CloseOutcome {
        *self
            .driver
            .closed
            .get_or_init(|| async {
                let inner = self.inner.clone();
                let graceful = self.driver.run(async move { inner.close().await });
                let outcome = match tokio::time::timeout(deadline, graceful).await {
                    Ok(Ok(())) => CloseOutcome::Drained,
                    // `Ok(Err)` is the runtime going away under the close,
                    // which only a forced shutdown does: not a drain either.
                    Ok(Err(_)) | Err(_) => CloseOutcome::Forced,
                };
                if outcome == CloseOutcome::Forced {
                    tracing::warn!(
                        ?deadline,
                        "mshr: endpoint did not drain in time; forcing it down \
                         (a connection mid-handshake, R945-B1)"
                    );
                }
                self.driver.shut_down().await;
                outcome
            })
            .await
    }
}

/// How long [`Endpoint::close`] waits for connections to drain before it
/// forces the endpoint down. A healthy drain is 3×PTO: about 3 s for a dial
/// still at the initial RTT, well under a second otherwise.
pub const DEFAULT_CLOSE_DEADLINE: Duration = Duration::from_secs(5);

/// How [`Endpoint::close_within`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseOutcome {
    /// Every connection drained; peers saw the close.
    Drained,
    /// The deadline passed first and the endpoint's tasks were dropped. A
    /// peer whose CONNECTION_CLOSE was lost learns of it by idle timeout.
    Forced,
}

/// Grace for [`Driver::shut_down`] to drop the endpoint's tasks. Dropping a
/// task is prompt; this only bounds a task stuck in a blocking call.
const RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// The tokio runtime that runs every task iroh and noq spawn for one
/// endpoint (R945-B1).
///
/// iroh spawns its tasks onto whichever runtime is current when it is
/// called, and can cancel them only through a private token that its own
/// `abort` skips once a close has started. So a stuck close pins the UDP
/// sockets in the noq drivers with nothing a caller can do about it. Owning
/// the runtime gives mshr that lever: [`Driver::shut_down`] drops every task
/// on it. mshr therefore runs every iroh call that spawns (bind, connect,
/// the accept handshake) through [`Driver::run`].
struct Driver {
    handle: tokio::runtime::Handle,
    /// `None` once shut down.
    runtime: std::sync::Mutex<Option<tokio::runtime::Runtime>>,
    /// The first close's outcome; see [`Endpoint::close_within`].
    closed: tokio::sync::OnceCell<CloseOutcome>,
}

impl Driver {
    fn new() -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("mshr-endpoint")
            .enable_all()
            .build()?;
        Ok(Self {
            handle: runtime.handle().clone(),
            runtime: std::sync::Mutex::new(Some(runtime)),
            closed: tokio::sync::OnceCell::new(),
        })
    }

    /// Run `fut` on the endpoint's runtime and await it from any context.
    /// Errs once the runtime has been shut down.
    async fn run<F>(&self, fut: F) -> Result<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.handle
            .spawn(fut)
            .await
            .map_err(|e| Error::Endpoint(format!("endpoint runtime: {e}")))
    }

    /// Drop every task on the endpoint's runtime and wait until they are
    /// gone. Idempotent.
    async fn shut_down(&self) {
        let runtime = self.runtime.lock().expect("poisoned").take();
        if let Some(runtime) = runtime {
            // `shutdown_timeout` blocks, and a runtime may not be dropped
            // from async context at all.
            let _ = tokio::task::spawn_blocking(move || {
                runtime.shutdown_timeout(RUNTIME_SHUTDOWN_GRACE)
            })
            .await;
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // Last clone gone without a close: the only shutdown that is legal
        // from any context, async included.
        if let Some(runtime) = self.runtime.get_mut().ok().and_then(Option::take) {
            runtime.shutdown_background();
        }
    }
}

/// Error code carried on the CONNECTION_CLOSE frame when the registered
/// [`Acceptor`] hook denies a connection. Arbitrary but stable — consumers
/// may match on it to distinguish an acceptor-hook deny from other
/// close reasons in logs/metrics.
///
/// Public because that sentence is only true if a dialer can name it:
/// "you are not entitled to this node" and "the network dropped" are the
/// same `ConnectionError` variant otherwise, and the first one has an
/// action attached to it (get your NodeId admitted) while the second does
/// not. Pair it with [`ACCEPTOR_DENY_REASON`], which the same close
/// carries.
pub const ACCEPTOR_DENY_ERROR_CODE: u32 = 1;

/// Reason bytes carried alongside [`ACCEPTOR_DENY_ERROR_CODE`] on an
/// acceptor-hook deny.
pub const ACCEPTOR_DENY_REASON: &[u8] = b"denied";

async fn dispatch_one(
    incoming: Incoming,
    handlers: Arc<HashMap<Alpn, AlpnHandler>>,
    acceptor: Option<Arc<dyn Acceptor>>,
    driver: &Driver,
) -> anyhow::Result<()> {
    // `Incoming::into_future()` (via IntoFuture) drives the handshake to
    // completion and yields a `Connection<HandshakeCompleted>` whose
    // `alpn()` we can dispatch on and whose `remote_id()` is the peer's
    // TLS-authenticated `NodeId`. It runs on the endpoint's runtime, where
    // noq spawns the connection's driver; the handler below stays on ours.
    let conn: Connection = driver.run(incoming.into_future()).await??;

    // Acceptor hook runs before any application data is read from the
    // connection (we haven't called `accept_bi`/`accept_uni`/etc. yet),
    // so a `Deny` here closes the connection with no application bytes
    // exchanged and the ALPN handler below never runs.
    if let Some(acceptor) = &acceptor {
        let remote = conn.remote_id();
        if acceptor.accept(remote).await == AcceptDecision::Deny {
            tracing::debug!(remote = %remote, "mshr: connection denied by acceptor hook");
            conn.close(ACCEPTOR_DENY_ERROR_CODE.into(), ACCEPTOR_DENY_REASON);
            return Ok(());
        }
    }

    let alpn = conn.alpn();
    let handler = handlers.get(alpn).cloned().ok_or_else(|| {
        anyhow::anyhow!(
            "no handler registered for ALPN {:?}",
            String::from_utf8_lossy(alpn)
        )
    })?;
    handler(conn).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Bytes, SendDatagramError};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// An `AlpnHandler` that reads datagrams forever and sends each one
    /// straight back. Shared by the datagram tests below.
    fn datagram_echo_handler() -> AlpnHandler {
        Arc::new(|conn: Connection| {
            Box::pin(async move {
                while let Ok(payload) = conn.read_datagram().await {
                    // A failed echo is not fatal: this is the unreliable
                    // path, and the dialer retries.
                    let _ = conn.send_datagram(payload);
                }
                Ok(())
            }) as BoxFut<'static, anyhow::Result<()>>
        })
    }

    /// Spawn `accept_dispatch` for a single ALPN/handler pair.
    fn serve(
        ep: &Endpoint,
        alpn: &'static [u8],
        handler: AlpnHandler,
    ) -> tokio::task::JoinHandle<()> {
        let ep = ep.clone();
        tokio::spawn(async move {
            let mut handlers: HashMap<Alpn, AlpnHandler> = HashMap::new();
            handlers.insert(alpn.to_vec(), handler);
            let _ = ep.accept_dispatch(handlers).await;
        })
    }

    /// With `segmentation_offload(false)` on both ends, a multi-MB stream
    /// write — hundreds of datagrams, the flight shape that GSO would batch —
    /// still arrives whole. The knob must change how packets leave, not
    /// whether they do.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gso_off_still_carries_a_multi_megabyte_stream() {
        const ALPN: &[u8] = b"xlb-net/test/gso-off/v1";
        const LEN: usize = 3 * 1024 * 1024;

        let bind = || {
            Endpoint::builder()
                .keypair(Keypair::generate())
                .alpns([ALPN])
                .segmentation_offload(false)
                .bind()
        };
        let alice = bind().await.expect("alice bind");
        let bob = bind().await.expect("bob bind");

        let sink: AlpnHandler = Arc::new(|conn: Connection| {
            Box::pin(async move {
                let (mut send, mut recv) = conn.accept_bi().await?;
                let got = recv.read_to_end(LEN + 1).await?;
                send.write_all(&(got.len() as u64).to_le_bytes()).await?;
                send.finish()?;
                let _ = conn.closed().await;
                Ok(())
            }) as BoxFut<'static, anyhow::Result<()>>
        });
        let server = serve(&alice, ALPN, sink);

        let conn = bob.connect_alpn(alice.endpoint_addr(), ALPN).await.expect("connect");
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        let payload: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
        send.write_all(&payload).await.expect("write");
        send.finish().expect("finish");
        let echoed = tokio::time::timeout(Duration::from_secs(30), recv.read_to_end(8))
            .await
            .expect("the receiver answers")
            .expect("read the length");
        assert_eq!(u64::from_le_bytes(echoed.try_into().unwrap()), LEN as u64);

        conn.close(0u32.into(), b"done");
        alice.close().await;
        bob.close().await;
        server.abort();
    }

    /// Two endpoints in the same process, directly addressed via
    /// `EndpointAddr`, round-trip a single bidirectional stream.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn round_trip_stream() {
        const ALPN: &[u8] = b"xlb-net/test/v1";

        let alice = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("alice bind");

        let bob = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("bob bind");

        // Alice runs a tiny echo server via accept_dispatch.
        let saw_request = Arc::new(AtomicBool::new(false));
        let saw_request_h = saw_request.clone();
        let alice_handle = alice.clone();
        let server = tokio::spawn(async move {
            let mut handlers: HashMap<Alpn, AlpnHandler> = HashMap::new();
            let flag = saw_request_h.clone();
            handlers.insert(
                ALPN.to_vec(),
                Arc::new(move |conn: Connection| {
                    let flag = flag.clone();
                    Box::pin(async move {
                        let (mut send, mut recv) = conn.accept_bi().await?;
                        let buf = recv.read_to_end(1024).await?;
                        flag.store(true, Ordering::SeqCst);
                        send.write_all(&buf).await?;
                        send.finish()?;
                        // Wait for the peer to close so iroh doesn't drop
                        // unsent stream frames.
                        let _ = conn.closed().await;
                        Ok(())
                    }) as BoxFut<'static, anyhow::Result<()>>
                }),
            );
            let _ = alice_handle.accept_dispatch(handlers).await;
        });

        let alice_addr = alice.endpoint_addr();

        // Bob dials Alice on ALPN and echoes a payload.
        let conn = bob
            .connect_alpn(alice_addr, ALPN)
            .await
            .expect("bob connect");
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(b"hello yah").await.expect("write");
        send.finish().expect("finish");
        let echoed = recv.read_to_end(1024).await.expect("read");
        assert_eq!(echoed, b"hello yah");
        conn.close(0u32.into(), b"done");

        // Allow Alice's handler to observe.
        for _ in 0..50 {
            if saw_request.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(saw_request.load(Ordering::SeqCst), "alice handler ran");

        alice.close().await;
        bob.close().await;
        server.abort();
    }

    /// Static-lane discovery: alice's `EndpointAddr` is pinned in bob's
    /// `Discovery::with_static`, so bob can dial alice using the bare
    /// `EndpointId` (no inline addrs) and the MemoryLookup resolves it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn static_lane_resolves_node_id() {
        const ALPN: &[u8] = b"xlb-net/test/static-lane/v1";

        let alice = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("alice bind");
        let alice_addr = alice.endpoint_addr();
        let alice_id = alice.node_id();

        let bob = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .discovery(Discovery::new().with_static([alice_addr]))
            .bind()
            .await
            .expect("bob bind");

        let alice_handle = alice.clone();
        let server = tokio::spawn(async move {
            let mut handlers: HashMap<Alpn, AlpnHandler> = HashMap::new();
            handlers.insert(
                ALPN.to_vec(),
                Arc::new(|conn: Connection| {
                    Box::pin(async move {
                        let (mut send, mut recv) = conn.accept_bi().await?;
                        let buf = recv.read_to_end(64).await?;
                        send.write_all(&buf).await?;
                        send.finish()?;
                        let _ = conn.closed().await;
                        Ok(())
                    }) as BoxFut<'static, anyhow::Result<()>>
                }),
            );
            let _ = alice_handle.accept_dispatch(handlers).await;
        });

        // Dial by bare EndpointId — only resolvable through the static lane.
        let conn = bob
            .connect_alpn(EndpointAddr::from(alice_id), ALPN)
            .await
            .expect("static-lane connect");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"static").await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(64).await.unwrap();
        assert_eq!(echoed, b"static");
        conn.close(0u32.into(), b"done");

        alice.close().await;
        bob.close().await;
        server.abort();
    }

    /// Smoke-check that the LAN lane binds everywhere. The real round-trip
    /// is [`lan_lane_resolves_node_id`], `#[ignore]`d because multicast in
    /// CI sandboxes and container networks is unreliable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lan_lane_binds() {
        let ep = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([b"xlb-net/test/lan/v1"])
            .discovery(Discovery::new().with_lan())
            .bind()
            .await
            .expect("bind with LAN discovery");
        ep.close().await;
    }

    /// R938: two endpoints with ONLY the LAN lane find each other by bare
    /// `EndpointId` — publish through the system responder (dns_sd on
    /// Apple, mdns-sd elsewhere), browse, resolve, dial. Needs a host where
    /// multicast works: `cargo test -p mshr --lib lan_lane -- --ignored`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs working local multicast / system mDNS responder"]
    async fn lan_lane_resolves_node_id() {
        const ALPN: &[u8] = b"xlb-net/test/lan-resolve/v1";

        let alice = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .discovery(Discovery::new().with_lan())
            .bind()
            .await
            .expect("alice bind");
        let alice_id = alice.node_id();
        let bob = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .discovery(Discovery::new().with_lan())
            .bind()
            .await
            .expect("bob bind");

        let alice_handle = alice.clone();
        let server = tokio::spawn(async move {
            let mut handlers: HashMap<Alpn, AlpnHandler> = HashMap::new();
            handlers.insert(
                ALPN.to_vec(),
                Arc::new(|conn: Connection| {
                    Box::pin(async move {
                        let (mut send, mut recv) = conn.accept_bi().await?;
                        let buf = recv.read_to_end(64).await?;
                        send.write_all(&buf).await?;
                        send.finish()?;
                        let _ = conn.closed().await;
                        Ok(())
                    }) as BoxFut<'static, anyhow::Result<()>>
                }),
            );
            let _ = alice_handle.accept_dispatch(handlers).await;
        });

        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            bob.connect_alpn(EndpointAddr::from(alice_id), ALPN),
        )
        .await
        .expect("lan-lane connect timed out")
        .expect("lan-lane connect");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"lan").await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(64).await.unwrap();
        assert_eq!(echoed, b"lan");
        conn.close(0u32.into(), b"done");

        alice.close().await;
        bob.close().await;
        server.abort();
    }

    /// R609-F4: the bound endpoint reports whether a bare NodeId is dialable
    /// through it, so a dialer can refuse with a reason instead of hanging to
    /// the QUIC timeout. Bound to the *snapshot* taken at bind time, since
    /// `Discovery` is consumed by the iroh builder.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_endpoint_reports_whether_it_resolves_bare_node_ids() {
        let bare = Endpoint::builder()
            .keypair(Keypair::generate())
            .bind()
            .await
            .expect("bind with no discovery");
        assert!(!bare.resolves_bare_node_ids());
        bare.close().await;

        let resolving = crate::Seeds::defaults()
            .apply(Endpoint::builder().keypair(Keypair::generate()))
            .bind()
            .await
            .expect("bind with the shipped seed defaults");
        assert!(resolving.resolves_bare_node_ids());
        resolving.close().await;
    }

    /// External-roster lane: a `MockPeerSource` pushes alice's
    /// `EndpointAddr` into bob's discovery pool. Bob then dials alice
    /// by bare `EndpointId` and the connect resolves through the
    /// roster's `MemoryLookup`. F2's static lane is *not* configured —
    /// only the roster — so any dial that succeeds proves the F3 path
    /// is wired end-to-end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn external_roster_resolves_node_id() {
        use crate::{PeerHint, PeerHintStream, PeerSource};
        use std::sync::Mutex;
        use tokio::sync::mpsc;

        const ALPN: &[u8] = b"xlb-net/test/roster/v1";

        struct MockSource {
            rx: Mutex<Option<mpsc::UnboundedReceiver<PeerHint>>>,
        }
        impl PeerSource for MockSource {
            fn subscribe(&self) -> PeerHintStream {
                let rx = self
                    .rx
                    .lock()
                    .unwrap()
                    .take()
                    .expect("subscribe called once");
                Box::pin(RxStream(rx))
            }
        }
        struct RxStream(mpsc::UnboundedReceiver<PeerHint>);
        impl futures_core::Stream for RxStream {
            type Item = PeerHint;
            fn poll_next(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                self.0.poll_recv(cx)
            }
        }

        let (tx, rx) = mpsc::unbounded_channel::<PeerHint>();
        let source = MockSource {
            rx: Mutex::new(Some(rx)),
        };

        let alice = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("alice bind");
        let alice_addr = alice.endpoint_addr();
        let alice_id = alice.node_id();

        let bob = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .discovery(Discovery::new().with_external_roster(source))
            .bind()
            .await
            .expect("bob bind");

        // Push alice's addr into bob's roster *after* bind (the pump
        // task is already subscribed). Give the pump a beat to drain.
        tx.send(PeerHint::Found(alice_addr)).expect("roster send");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let alice_handle = alice.clone();
        let server = tokio::spawn(async move {
            let mut handlers: HashMap<Alpn, AlpnHandler> = HashMap::new();
            handlers.insert(
                ALPN.to_vec(),
                Arc::new(|conn: iroh::endpoint::Connection| {
                    Box::pin(async move {
                        let (mut send, mut recv) = conn.accept_bi().await?;
                        let buf = recv.read_to_end(64).await?;
                        send.write_all(&buf).await?;
                        send.finish()?;
                        let _ = conn.closed().await;
                        Ok(())
                    }) as BoxFut<'static, anyhow::Result<()>>
                }),
            );
            let _ = alice_handle.accept_dispatch(handlers).await;
        });

        let conn = bob
            .connect_alpn(EndpointAddr::from(alice_id), ALPN)
            .await
            .expect("roster-lane connect");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"roster").await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(64).await.unwrap();
        assert_eq!(echoed, b"roster");
        conn.close(0u32.into(), b"done");

        alice.close().await;
        bob.close().await;
        server.abort();
    }

    /// Swarm-lane builder smoke: configuring `with_relays(default_relays())`
    /// must not crash the bind step. Real pkarr round-trips against n0's
    /// public relay aren't appropriate for a unit test (network egress,
    /// flaky CI); end-to-end pkarr lives in an integration test against
    /// a yubaba-hosted relay (R105-F4).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn swarm_lane_binds() {
        use crate::default_relays;

        let ep = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([b"xlb-net/test/swarm/v1"])
            .discovery(Discovery::new().with_relays(default_relays()))
            .bind()
            .await
            .expect("bind with swarm discovery");
        ep.close().await;
    }

    /// An unreliable datagram round-trips between two mshr endpoints, using
    /// only `mshr`'s own surface — `Connection`, `Bytes`, `SendDatagramError`
    /// — with no `iroh` import anywhere in the test. That last part is the
    /// point of R609-F6: the capability was always in the re-exported
    /// `Connection`, but calling it required naming iroh types.
    ///
    /// Datagrams may be lost, so the dialer resends until the echo comes back
    /// rather than asserting on a single shot. On loopback this passes on the
    /// first attempt; the loop is what keeps it from being a flake generator
    /// on a loaded machine.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn datagram_round_trip() {
        const ALPN: &[u8] = b"xlb-net/test/datagram-round-trip/v1";

        let alice = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("alice bind");
        let bob = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("bob bind");

        let server = serve(&alice, ALPN, datagram_echo_handler());

        let conn = bob
            .connect_alpn(alice.endpoint_addr(), ALPN)
            .await
            .expect("bob connect");

        let mut echoed = None;
        for _ in 0..50 {
            conn.send_datagram(Bytes::from_static(b"unreliable hello"))
                .expect("send_datagram");
            match tokio::time::timeout(Duration::from_millis(100), conn.read_datagram()).await {
                Ok(Ok(payload)) => {
                    echoed = Some(payload);
                    break;
                }
                Ok(Err(e)) => panic!("connection lost while awaiting echo: {e}"),
                Err(_elapsed) => continue,
            }
        }
        assert_eq!(
            echoed.as_deref(),
            Some(&b"unreliable hello"[..]),
            "datagram must round-trip through the ALPN handler"
        );

        conn.close(0u32.into(), b"done");
        alice.close().await;
        bob.close().await;
        server.abort();
    }

    /// `max_datagram_size()` is available on an established connection, is
    /// large enough for A108's 1024 B `vivarium_cv` cap, and is *enforced* —
    /// one byte over and the send is refused with `TooLarge` rather than
    /// fragmented. Fragmentation is exactly what a realtime class gave up
    /// reliability to avoid, so the refusal is the feature.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn max_datagram_size_is_readable_and_oversize_is_refused() {
        const ALPN: &[u8] = b"xlb-net/test/datagram-size/v1";

        let alice = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("alice bind");
        let bob = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("bob bind");

        let server = serve(&alice, ALPN, datagram_echo_handler());

        let conn = bob
            .connect_alpn(alice.endpoint_addr(), ALPN)
            .await
            .expect("bob connect");

        let cap = conn
            .max_datagram_size()
            .expect("datagrams are enabled by default on both sides");
        assert!(
            cap >= 1024,
            "a datagram must fit A108's 1024 B vivarium_cv cap; path allows {cap} B"
        );

        assert_eq!(
            conn.send_datagram(Bytes::from(vec![0u8; cap + 1])),
            Err(SendDatagramError::TooLarge),
            "one byte over the cap is refused, not fragmented"
        );
        conn.send_datagram(Bytes::from(vec![0u8; cap]))
            .expect("exactly the cap is sendable");

        conn.close(0u32.into(), b"done");
        alice.close().await;
        bob.close().await;
        server.abort();
    }

    /// `datagram_receive_buffer_size(None)` is advertised to the peer, not
    /// merely applied locally: the *dialer* learns datagrams are unavailable
    /// before sending one. This is the difference between a fallback and a
    /// black hole — and it is also what proves the builder knob reaches the
    /// transport parameters of an accepted connection, not just a dialed one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn receive_buffer_none_refuses_at_the_sender() {
        const ALPN: &[u8] = b"xlb-net/test/datagram-disabled/v1";

        let alice = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .datagram_receive_buffer_size(None)
            .bind()
            .await
            .expect("alice bind");
        let bob = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("bob bind");

        let server = serve(&alice, ALPN, datagram_echo_handler());

        let conn = bob
            .connect_alpn(alice.endpoint_addr(), ALPN)
            .await
            .expect("bob connect");

        assert_eq!(
            conn.max_datagram_size(),
            None,
            "a peer that disabled inbound datagrams reports no size at all"
        );
        assert_eq!(
            conn.send_datagram(Bytes::from_static(b"nope")),
            Err(SendDatagramError::UnsupportedByPeer),
            "the sender must be told, so it can fall back to a stream"
        );

        conn.close(0u32.into(), b"done");
        alice.close().await;
        bob.close().await;
        server.abort();
    }

    /// `datagram_send_buffer_size` reaches the live connection. The default
    /// is 1 MiB of backlog before newest-wins eviction begins, which is
    /// several seconds of stale audio on a stalled path — so a realtime
    /// sender configuring a few frames' worth needs the value to actually
    /// arrive, and this asserts the number rather than the call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_buffer_size_reaches_the_connection() {
        const ALPN: &[u8] = b"xlb-net/test/datagram-send-buffer/v1";
        const SEND_BUFFER: usize = 4096;

        let alice = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("alice bind");
        let bob = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .datagram_send_buffer_size(SEND_BUFFER)
            .bind()
            .await
            .expect("bob bind");

        let server = serve(&alice, ALPN, datagram_echo_handler());

        let conn = bob
            .connect_alpn(alice.endpoint_addr(), ALPN)
            .await
            .expect("bob connect");

        assert_eq!(
            conn.datagram_send_buffer_space(),
            SEND_BUFFER,
            "an idle connection's free send-buffer space is the configured size"
        );

        conn.close(0u32.into(), b"done");
        alice.close().await;
        bob.close().await;
        server.abort();
    }

    #[test]
    fn builder_requires_keypair() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let res = rt.block_on(async { Endpoint::builder().alpns([b"x"]).bind().await });
        match res {
            Err(Error::Endpoint(_)) => {}
            other => panic!("expected Error::Endpoint, got {:?}", other.err()),
        }
    }

    /// No acceptor registered: `Endpoint::acceptor()` reports `None` and
    /// the connection round-trips exactly like `round_trip_stream` above —
    /// the default (pre-hook) behavior is unchanged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_acceptor_registered_accepts_as_before() {
        const ALPN: &[u8] = b"xlb-net/test/acceptor-default/v1";

        let alice = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("alice bind");
        assert!(
            alice.acceptor().is_none(),
            "no acceptor() call on the builder means no hook registered"
        );

        let bob = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("bob bind");

        let alice_handle = alice.clone();
        let server = tokio::spawn(async move {
            let mut handlers: HashMap<Alpn, AlpnHandler> = HashMap::new();
            handlers.insert(
                ALPN.to_vec(),
                Arc::new(|conn: Connection| {
                    Box::pin(async move {
                        let (mut send, mut recv) = conn.accept_bi().await?;
                        let buf = recv.read_to_end(64).await?;
                        send.write_all(&buf).await?;
                        send.finish()?;
                        let _ = conn.closed().await;
                        Ok(())
                    }) as BoxFut<'static, anyhow::Result<()>>
                }),
            );
            let _ = alice_handle.accept_dispatch(handlers).await;
        });

        let conn = bob
            .connect_alpn(alice.endpoint_addr(), ALPN)
            .await
            .expect("bob connect");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"no hook").await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(64).await.unwrap();
        assert_eq!(echoed, b"no hook");
        conn.close(0u32.into(), b"done");

        alice.close().await;
        bob.close().await;
        server.abort();
    }

    /// Registered acceptor hook observes the dialer's real, TLS-authenticated
    /// `NodeId` (not some placeholder) and an `Accept` decision lets the
    /// connection proceed to its ALPN handler exactly as if no hook were
    /// registered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn acceptor_observes_dialer_node_id_and_accepts() {
        use std::sync::Mutex;

        const ALPN: &[u8] = b"xlb-net/test/acceptor-accept/v1";

        let seen_remote: Arc<Mutex<Option<NodeId>>> = Arc::new(Mutex::new(None));
        let seen_remote_h = seen_remote.clone();

        let alice = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .acceptor(move |remote: NodeId| {
                let seen_remote_h = seen_remote_h.clone();
                async move {
                    *seen_remote_h.lock().unwrap() = Some(remote);
                    AcceptDecision::Accept
                }
            })
            .bind()
            .await
            .expect("alice bind");

        let bob = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("bob bind");
        let bob_id = bob.node_id();

        let alice_handle = alice.clone();
        let server = tokio::spawn(async move {
            let mut handlers: HashMap<Alpn, AlpnHandler> = HashMap::new();
            handlers.insert(
                ALPN.to_vec(),
                Arc::new(|conn: Connection| {
                    Box::pin(async move {
                        let (mut send, mut recv) = conn.accept_bi().await?;
                        let buf = recv.read_to_end(64).await?;
                        send.write_all(&buf).await?;
                        send.finish()?;
                        let _ = conn.closed().await;
                        Ok(())
                    }) as BoxFut<'static, anyhow::Result<()>>
                }),
            );
            let _ = alice_handle.accept_dispatch(handlers).await;
        });

        let conn = bob
            .connect_alpn(alice.endpoint_addr(), ALPN)
            .await
            .expect("bob connect");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"hook accept").await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(64).await.unwrap();
        assert_eq!(echoed, b"hook accept");
        conn.close(0u32.into(), b"done");

        assert_eq!(
            *seen_remote.lock().unwrap(),
            Some(bob_id),
            "acceptor hook must see the dialer's real authenticated NodeId"
        );

        alice.close().await;
        bob.close().await;
        server.abort();
    }

    /// Registered acceptor hook denies the connection: the connection is
    /// closed before the registered ALPN handler ever runs (no application
    /// bytes flow), and the dialer observes an `ApplicationClosed` error
    /// carrying the hook's close code/reason.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn acceptor_deny_closes_before_application_dispatch() {
        use iroh::endpoint::ConnectionError;

        const ALPN: &[u8] = b"xlb-net/test/acceptor-deny/v1";

        let alice = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .acceptor(|_remote: NodeId| async move { AcceptDecision::Deny })
            .bind()
            .await
            .expect("alice bind");

        let bob = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind()
            .await
            .expect("bob bind");

        // Proves "no application bytes flow": if the ALPN handler ran at
        // all (even without reading a byte), this flips to true.
        let handler_ran = Arc::new(AtomicBool::new(false));
        let handler_ran_h = handler_ran.clone();
        let alice_handle = alice.clone();
        let server = tokio::spawn(async move {
            let mut handlers: HashMap<Alpn, AlpnHandler> = HashMap::new();
            let flag = handler_ran_h.clone();
            handlers.insert(
                ALPN.to_vec(),
                Arc::new(move |_conn: Connection| {
                    flag.store(true, Ordering::SeqCst);
                    Box::pin(async move { Ok(()) }) as BoxFut<'static, anyhow::Result<()>>
                }),
            );
            let _ = alice_handle.accept_dispatch(handlers).await;
        });

        // The QUIC/TLS handshake itself still completes (mutual auth is
        // intrinsic to iroh) — `connect_alpn` succeeds. The deny decision
        // is enforced *after* the handshake, before app dispatch.
        let conn = bob
            .connect_alpn(alice.endpoint_addr(), ALPN)
            .await
            .expect("handshake succeeds; the acceptor hook denies afterwards");

        match conn.closed().await {
            ConnectionError::ApplicationClosed(app_close) => {
                assert_eq!(
                    u64::from(app_close.error_code),
                    1,
                    "denies use the acceptor-hook close code"
                );
                assert_eq!(app_close.reason.as_ref(), b"denied");
            }
            other => panic!("expected ApplicationClosed(denied), got {other:?}"),
        }

        assert!(
            !handler_ran.load(Ordering::SeqCst),
            "the ALPN handler must never run for a denied connection"
        );

        alice.close().await;
        bob.close().await;
        server.abort();
    }

    /// Every IP path `conn` currently holds, as socket addresses.
    fn ip_paths(conn: &Connection) -> Vec<SocketAddr> {
        conn.paths()
            .iter()
            .map(|p| match p.remote_addr() {
                crate::TransportAddr::Ip(a) => *a,
                other => panic!("relay is off, so no non-IP path may exist: {other:?}"),
            })
            .collect()
    }

    /// R743-F26: `bind_addr` replaces the wildcard sockets, and an endpoint
    /// bound on one family's loopback keeps every path to a dual-stack peer
    /// on that family — even when dialed with the peer's full address set,
    /// v6 included. A second endpoint bound on the other family, to the same
    /// peer, stays on *its* family: pinning is per endpoint.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bind_addr_pins_an_endpoint_to_its_named_socket() {
        const ALPN: &[u8] = b"mshr/test/pinned/v1";
        let v4: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let v6: SocketAddr = "[::1]:0".parse().unwrap();

        let server = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind_addr(v4, 8)
            .bind_addr(v6, 128)
            .bind()
            .await
            .expect("server bind");
        let _srv = serve(
            &server,
            ALPN,
            Arc::new(|conn: Connection| {
                Box::pin(async move {
                    let _ = conn.closed().await;
                    Ok(())
                }) as BoxFut<'static, anyhow::Result<()>>
            }),
        );
        let server_addr = server.endpoint_addr();
        assert!(server_addr.ip_addrs().any(|a| a.is_ipv4()));
        assert!(server_addr.ip_addrs().any(|a| a.is_ipv6()));

        let pinned4 = Endpoint::builder()
            .keypair(Keypair::generate())
            .bind_addr(v4, 8)
            .bind()
            .await
            .expect("v4 bind");
        let pinned6 = Endpoint::builder()
            .keypair(Keypair::generate())
            .bind_addr(v6, 128)
            .bind()
            .await
            .expect("v6 bind");
        let bound4 = pinned4.inner().bound_sockets();
        assert!(!bound4.is_empty() && bound4.iter().all(|a| a.ip() == v4.ip()), "{bound4:?}");
        let bound6 = pinned6.inner().bound_sockets();
        assert!(!bound6.is_empty() && bound6.iter().all(|a| a.ip() == v6.ip()), "{bound6:?}");

        let c4 = pinned4.connect_alpn(server_addr.clone(), ALPN).await.expect("dial v4");
        let c6 = pinned6.connect_alpn(server_addr, ALPN).await.expect("dial v6");
        // Let holepunching / path selection settle before judging.
        tokio::time::sleep(Duration::from_secs(3)).await;

        let p4 = ip_paths(&c4);
        let p6 = ip_paths(&c6);
        assert!(!p4.is_empty() && p4.iter().all(|a| a.ip() == v4.ip()), "v4-pinned paths: {p4:?}");
        assert!(!p6.is_empty() && p6.iter().all(|a| a.ip() == v6.ip()), "v6-pinned paths: {p6:?}");

        pinned4.close().await;
        pinned6.close().await;
        server.close().await;
    }

    /// An out-of-range prefix is a caller error iroh rejects; it must
    /// surface from `bind()`, naming the address, rather than panic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bind_addr_rejects_a_bad_prefix_at_bind() {
        let err = Endpoint::builder()
            .keypair(Keypair::generate())
            .bind_addr("127.0.0.1:0".parse().unwrap(), 33)
            .bind()
            .await
            .err()
            .expect("prefix 33 is not a v4 prefix");
        assert!(err.to_string().contains("bind_addr 127.0.0.1:0/33"), "{err}");
    }

    /// R945-B1: a server connection whose *first* packet is the dialer's
    /// handshake-time CONNECTION_CLOSE never drains in noq 1.0.0-rc.0, so the
    /// graceful close waits out the 30 s idle timeout. `close` must still
    /// return within its deadline, and the port must be bindable again once
    /// the endpoint is dropped.
    ///
    /// A lossy hop in front of bob drops alice's ClientHello; it opens just
    /// before alice closes her half-open dial, so the first datagram bob ever
    /// sees for that connection is the close-only Initial.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_is_bounded_when_a_dial_was_aborted_before_we_saw_it() {
        use std::sync::atomic::AtomicUsize;
        const ALPN: &[u8] = b"mshr/test/aborted-dial/v1";
        let lo: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let bob = Endpoint::builder()
            .keypair(Keypair::generate())
            .alpns([ALPN])
            .bind_addr(lo, 8)
            .bind()
            .await
            .expect("bob bind");
        let bob_socket = bob.inner().bound_sockets()[0];
        let srv = serve(
            &bob,
            ALPN,
            Arc::new(|conn: Connection| {
                Box::pin(async move {
                    let _ = conn.closed().await;
                    Ok(())
                }) as BoxFut<'static, anyhow::Result<()>>
            }),
        );

        let hop = tokio::net::UdpSocket::bind(lo).await.expect("hop bind");
        let hop_addr = hop.local_addr().unwrap();
        let open = Arc::new(AtomicBool::new(false));
        let forwarded = Arc::new(AtomicUsize::new(0));
        let hop_task = {
            let (open, forwarded) = (open.clone(), forwarded.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                while let Ok((n, _)) = hop.recv_from(&mut buf).await {
                    if open.load(Ordering::SeqCst) {
                        let _ = hop.send_to(&buf[..n], bob_socket).await;
                        forwarded.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        };

        let alice = Endpoint::builder()
            .keypair(Keypair::generate())
            .bind_addr(lo, 8)
            .bind()
            .await
            .expect("alice bind");
        let dial_to = EndpointAddr::new(bob.node_id()).with_ip_addr(hop_addr);
        let dial = {
            let alice = alice.clone();
            tokio::spawn(async move { alice.connect_alpn(dial_to, ALPN).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        open.store(true, Ordering::SeqCst);
        let alice_close = {
            let alice = alice.clone();
            tokio::spawn(async move { alice.close().await })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while forwarded.load(Ordering::SeqCst) == 0 {
            assert!(std::time::Instant::now() < deadline, "alice's close never reached the hop");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Let bob accept the Initial and fail its handshake.
        tokio::time::sleep(Duration::from_millis(300)).await;

        let started = std::time::Instant::now();
        let closed = tokio::time::timeout(Duration::from_secs(10), bob.close()).await;
        let took = started.elapsed();
        assert!(closed.is_ok(), "bob.close() still pending after {took:?}");
        assert_eq!(closed.unwrap(), CloseOutcome::Forced, "the stuck connection cannot drain");
        assert!(took < DEFAULT_CLOSE_DEADLINE + Duration::from_secs(2), "close took {took:?}");

        drop(srv);
        drop(bob);
        let rebind_deadline = std::time::Instant::now() + Duration::from_secs(1);
        let rebound = loop {
            match std::net::UdpSocket::bind(bob_socket) {
                Ok(s) => break Ok(s),
                Err(e) if std::time::Instant::now() >= rebind_deadline => break Err(e),
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        };
        assert!(rebound.is_ok(), "{bob_socket} still held after close: {rebound:?}");

        hop_task.abort();
        let _ = dial.await;
        let _ = alice_close.await;
    }
}

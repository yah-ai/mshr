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

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use iroh::endpoint::{presets, Connection, Incoming, QuicTransportConfig};
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
        }
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
        if self.datagram_send_buffer_size.is_some() || self.datagram_receive_buffer_size.is_some() {
            let mut tc = QuicTransportConfig::builder();
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
        let mut resolves_bare_node_ids = false;
        if let Some(d) = self.discovery {
            resolves_bare_node_ids = d.resolves_bare_node_ids();
            b = d.apply(b);
        }

        let inner = b
            .bind()
            .await
            .map_err(|e| Error::Endpoint(format!("bind failed: {e}")))?;

        Ok(Endpoint {
            inner,
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
    pub fn inner(&self) -> &iroh::Endpoint {
        &self.inner
    }

    /// Open a connection to a peer by `EndpointAddr` on the given ALPN.
    pub async fn connect_alpn(
        &self,
        peer: impl Into<EndpointAddr>,
        alpn: &[u8],
    ) -> Result<Connection> {
        self.inner
            .connect(peer, alpn)
            .await
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
            tokio::spawn(async move {
                if let Err(e) = dispatch_one(incoming, handlers, acceptor).await {
                    tracing::warn!(error = %e, "mshr accept_dispatch: connection failed");
                }
            });
        }
        Ok(())
    }

    /// Close the endpoint. Idempotent.
    pub async fn close(&self) {
        self.inner.close().await;
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
) -> anyhow::Result<()> {
    // `Incoming::into_future()` (via IntoFuture) drives the handshake to
    // completion and yields a `Connection<HandshakeCompleted>` whose
    // `alpn()` we can dispatch on and whose `remote_id()` is the peer's
    // TLS-authenticated `NodeId`.
    let conn: Connection = incoming.await?;

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

    /// LAN-lane mDNS discovery is wired through to iroh, but real
    /// multicast in unit-test environments is unreliable (CI sandboxes,
    /// container networks, hosts with multicast disabled). We keep this
    /// test as a smoke-check that the builder compiles and binds; an
    /// end-to-end mDNS round-trip belongs in an environment-conditional
    /// integration test once the network harness exists.
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
}

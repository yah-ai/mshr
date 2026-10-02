//! Discovery aggregator. Composes the four discovery lanes from
//! `xlb-net.md` (Lan / Swarm / Static / ExternalRoster) and feeds them to
//! the underlying `iroh::Endpoint::Builder` as `address_lookup` services.
//!
//! Lanes:
//!
//! - **Lan** (R105-F2, R938): DNS-SD local-subnet discovery — system
//!   Bonjour on Apple platforms, `mdns-sd` elsewhere, one wire. See
//!   [`crate::lan`] for why this is not `iroh-mdns-address-lookup`.
//! - **Static** (R105-F2): pinned `EndpointAddr`s known up-front, backed
//!   by `iroh::address_lookup::memory::MemoryLookup`.
//! - **Swarm** (R105-F3): pkarr-relay-mediated peer discovery. Each
//!   configured pkarr relay URL gets a `PkarrPublisher` (so this endpoint
//!   advertises itself) and a `PkarrResolver` (so this endpoint can look
//!   up peers that advertised on the same relay).
//! - **ExternalRoster** (R105-F3): pluggable [`PeerSource`] feed —
//!   society's mesh roster, yubaba's raft state, anything that can stream
//!   `(node_id, addrs)` tuples. Bridged into a `MemoryLookup` updated by
//!   a background task driven by the source's stream.
//!
//! ## Why this layer exists
//!
//! Consumers of mshr (society, yubaba, xlb itself) shouldn't each have
//! to assemble their own discovery composition. Putting the aggregator
//! here means there's one place to standardize defaults and one place to
//! revisit if iroh's address-lookup model changes between rc.0 and 1.0.
//!
//! @yah:relay(R938, "mshr LAN discovery on iOS via system Bonjour (dns_sd) instead of raw multicast")
//! @yah:at(2026-09-23T06:13:10Z)
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:next("iOS rejects raw multicast sends (EHOSTUNREACH, 'error sending mDNS: No route to host') without the Apple-gated com.apple.developer.networking.multicast entitlement. Operator chose (2026-09-22, noisetable chat) to route Apple-platform LAN discovery through dns_sd instead of requesting the entitlement. Child feature carries the design.")
//! @yah:handoff("R938-F1 is in review. iOS LAN discovery now goes through system Bonjour (dns_sd) on a new standard DNS-SD wire, `_mshr._udp`, shared by every platform (mdns-sd off Apple). iroh-mdns is dropped because swarm-discovery is not DNS-SD-conformant and cannot interoperate with Bonjour. To close: set noisetable NSBonjourServices to `_mshr._udp`, point noisetable at this mshr (publish or devcrate), and run the iOS+desktop same-Wi-Fi E2E.")
//!
//! @yah:ticket(R938-F1, "DnsSdAddressLookup: Bonjour-backed AddressLookup wire-compatible with iroh-mdns (_irohv1._udp)")
//! @yah:status(review)
//! @yah:at(2026-09-23T06:13:06Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R938)
//! @yah:next("Symptom (noisetable iOS, 2026-09-23): `WARN swarm_discovery::socket] error sending mDNS: No route to host (os error 65)`. Path: Discovery::with_lan → Discovery::apply() → MdnsAddressLookup (iroh-mdns-address-lookup 0.2.0) → swarm-discovery 0.6.3 socket.rs:454 raw sendto 224.0.0.251:5353. iOS 14+ fails that with EHOSTUNREACH unless the app holds com.apple.developer.networking.multicast (Apple-approval-gated). Bonjour APIs need only NSLocalNetworkUsageDescription + NSBonjourServices.")
//! @yah:next("Operator decision 2026-09-22: ship this. mDNS is ADDITIVE to society's other discovery (point-to-point, local + remote gossip, relay/pkarr, rosters) — \"more the merrier for identifying peers\". Its unique value is cold-start on a LAN with no relay and no known peer. Do not remove or gate any other lane on iOS to make room for it.")
//! @yah:verify("Unit (any host): cargo test -p mshr --lib lan  (record/TXT round-trip, stranger rejection, resolve stream)")
//! @yah:verify("Live, on a Mac: cargo test -p mshr --lib lan -- --ignored  (dns_sd<->dns_sd, dns_sd->mdns-sd, mdns-sd->dns_sd, withdrawal, and lan_lane_resolves_node_id: two Endpoints with ONLY with_lan() dial by bare id)")
//! @yah:verify("E2E (operator): iOS device + Mac/Linux desktop on the same Wi-Fi, both with_lan(), no relay; each resolves the other by bare endpoint id; no 'error sending mDNS' in the iOS log. Needs noisetable's NSBonjourServices to list _mshr._udp and noisetable to consume this mshr (publish, or scripts/devcrate.sh on mshr).")
//! @yah:handoff("PREMISE CORRECTED: 'wire-compatible with iroh-mdns' is impossible. swarm-discovery 0.6.3 is not DNS-SD-conformant. make_response (sender.rs) emits NO PTR record and TTL 0 on every record (mDNS defines TTL 0 as a goodbye). The receiver answers only PTR queries and reads SRV/TXT only from answers and A/AAAA only from additionals, while Bonjour puts SRV/TXT in additionals. Measured: `dns-sd -B _irohv1._udp` saw 0 instances in 12s with a live swarm-discovery peer (yah desktop, pid 42865) on the same Mac. The instance label is RFC4648 base32 lowercase, not z-base32 as filed.")
//! @yah:handoff("SHIPPED: the LAN lane moved wholesale to standard DNS-SD under a new service type `_mshr._udp` (new module oss/mshr/crates/mshr/src/lan/). Apple (target_vendor=apple: iOS/macOS/tvOS/visionOS) uses the dns_sd FFI in lan/dnssd.rs, with signatures transcribed from the SDK dns_sd.h: one ShareConnection owned by one thread, Browse -> Resolve kept open for TXT updates, and reconnect when mDNSResponder restarts. Other platforms use mdns-sd 0.21 (lan/mdns.rs). cfg picks by platform, never a runtime flag. Wire: instance = base32(endpoint id); TXT a0..aN = socket addrs (authoritative, since v4/v6 ports differ), plus relay and user-data. Discovery::apply installs LanLookupBuilder; iroh-mdns-address-lookup was dropped, taking swarm-discovery, portmapper and igd-next out of every consumer's tree.")
//! @yah:handoff("VERIFIED on this Mac: 13 lan unit tests; 4 live interop tests (dns_sd<->dns_sd, dns_sd->mdns-sd, mdns-sd->dns_sd, withdrawal); lan_lane_resolves_node_id, where two Endpoints with ONLY with_lan() dial by bare id (1.2s); full mshr suite 55 passed; clippy --all-targets clean; cargo doc clean; cargo check -p mshr --target aarch64-apple-ios clean; root cargo check -p push-relay and -p mobile --target aarch64-apple-ios clean. NOT verified: the Linux target (cross-check dies in ring's C build — no Linux toolchain on the Mac; the mdns-sd backend itself is compiled and exercised on macOS under cfg(test)), and the iOS-device E2E.")
//! @yah:handoff("Lockfiles regenerated: oss/mshr, oss/cheers and the root Cargo.lock. The root needed `cargo update -p mio -p libc -p fastrand` (1.1.0->1.2.3, 0.2.186->0.2.189, 2.3.0->2.5.0) for mdns-sd; expect one camp-wide rebuild from the libc bump. The oss/yubaba, xlb and yah-base locks resolved unchanged.")
//! @yah:handoff("Also changed: endpoint.rs gains the ignored LAN e2e test; CHANGELOG [Unreleased] and README carry the iOS Info.plist requirement.")
//! @yah:handoff("Operator follow-up (noisetable repo, not this tree): Info.plist NSBonjourServices has an uncommitted `_irohv1._udp` entry from the old plan. It must become `_mshr._udp`, and noisetable consumes mshr from crates.io, so it needs an mshr publish or `scripts/devcrate.sh on mshr` before the iOS E2E.")
//! @yah:assumes("mdns-sd interop with Linux avahi/other responders is assumed from its standard wire; only mdns-sd<->mDNSResponder was exercised live.")

use std::pin::Pin;
use std::sync::Arc;

use futures_core::Stream;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::address_lookup::{PkarrPublisher, PkarrResolver, N0_DNS_PKARR_RELAY_PROD};
use iroh::endpoint::Builder as IrohBuilder;
use url::Url;

use crate::lan::{LanLookupBuilder, LanSightings};
use crate::{EndpointAddr, NodeId};

/// A peer-hint event emitted by an external roster source.
///
/// `Found` adds (or refreshes) addressing info for `node_id`; `Lost`
/// removes any cached info for `node_id`.
#[derive(Debug, Clone)]
pub enum PeerHint {
    /// A peer is reachable at the given addresses (either an
    /// [`EndpointAddr`] with relay URL + direct addrs, or just a bare
    /// `NodeId` if the source only knows identity).
    Found(EndpointAddr),

    /// The peer with this `NodeId` is no longer reachable through this
    /// source. Removes any cached `EndpointAddr` keyed on the id.
    Lost(NodeId),
}

/// Boxed `Stream` of [`PeerHint`]s, returned by [`PeerSource::subscribe`].
pub type PeerHintStream = Pin<Box<dyn Stream<Item = PeerHint> + Send + 'static>>;

/// External-roster feed for the discovery aggregator.
///
/// Implementors stream `(node_id, addrs)` hints from outside mshr —
/// society's gossip mesh, yubaba's raft state, an operator-supplied
/// hint file. `mshr` subscribes once at endpoint-bind time and
/// consumes updates for the life of the [`crate::Endpoint`].
///
/// mshr deliberately knows nothing about the source: dependency
/// direction is one-way (society/yubaba depend on mshr, never the
/// reverse). The trait is `Send + Sync + 'static` so a single source can
/// be shared across crate boundaries via `Arc<dyn PeerSource>`.
pub trait PeerSource: Send + Sync + 'static {
    /// Stream of peer-hint events. Called once per [`crate::Endpoint`]
    /// at bind time.
    fn subscribe(&self) -> PeerHintStream;
}

/// Default pkarr-relay URLs used when [`Discovery::with_relays`] is
/// called with the result of this function — n0's public pkarr relay.
///
/// Once yubaba cloud nodes host their own pkarr relays (R105-F4 +
/// yubaba's deploy track), this list will be `vec![<yubaba-url>,
/// <n0-fallback>]`. For now it's the n0 fallback only; production
/// callers should pass their own URLs explicitly.
pub fn default_relays() -> Vec<Url> {
    vec![N0_DNS_PKARR_RELAY_PROD
        .parse()
        .expect("static N0 pkarr relay URL parses")]
}

/// Composition of discovery lanes to layer onto an [`crate::Endpoint`].
///
/// Build with [`Discovery::new`] (or [`Discovery::default`]) and the
/// `with_*` methods, then hand to [`crate::EndpointBuilder::discovery`].
#[derive(Default, Clone)]
pub struct Discovery {
    lan: bool,
    lan_sightings: Option<LanSightings>,
    static_seeds: Vec<EndpointAddr>,
    relay_urls: Vec<Url>,
    rosters: Vec<Arc<dyn PeerSource>>,
}

impl std::fmt::Debug for Discovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discovery")
            .field("lan", &self.lan)
            .field("lan_sightings", &self.lan_sightings.is_some())
            .field("static_seeds", &self.static_seeds.len())
            .field("relay_urls", &self.relay_urls)
            .field("rosters", &self.rosters.len())
            .finish()
    }
}

impl Discovery {
    /// New, empty discovery composition. Equivalent to [`Discovery::default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable the LAN (DNS-SD) lane. Discovers other mshr endpoints on
    /// the same local subnet without any relay or DNS infra. Cheap and
    /// fast on shared networks; a no-op on hosts where multicast is
    /// blocked (the lookup service simply finds nothing). An iOS app must
    /// list `_mshr._udp` in `NSBonjourServices` — see [`crate::lan`].
    pub fn with_lan(mut self) -> Self {
        self.lan = true;
        self
    }

    /// Enable the LAN lane and report its sightings — who is advertising,
    /// found and lost — into `sightings`, a handle the caller keeps. The
    /// handle serves one endpoint; binding a second endpoint through a
    /// cloned `Discovery` fails that bind. The lane runs in the handle's
    /// [`LanScope`](crate::LanScope), changeable live with
    /// [`LanSightings::set_scope`].
    pub fn with_lan_sightings(mut self, sightings: LanSightings) -> Self {
        self.lan = true;
        self.lan_sightings = Some(sightings);
        self
    }

    /// Enable the LAN lane only if the predicate is true. Ergonomic
    /// shortcut for `if cond { d.with_lan() } else { d }`.
    pub fn with_lan_if(self, cond: bool) -> Self {
        if cond {
            self.with_lan()
        } else {
            self
        }
    }

    /// Add pinned `EndpointAddr`s the endpoint should always know about.
    /// Typical entries: yah-cloud permanent seeds, customer-camp yubaba.
    /// Replaces any previously-set static seeds; chain-call to merge.
    pub fn with_static<I>(mut self, seeds: I) -> Self
    where
        I: IntoIterator<Item = EndpointAddr>,
    {
        self.static_seeds = seeds.into_iter().collect();
        self
    }

    /// Append additional static seeds (does not replace existing).
    pub fn add_static(mut self, seed: EndpointAddr) -> Self {
        self.static_seeds.push(seed);
        self
    }

    /// Enable the **Swarm** lane via pkarr relays. Each URL gets a
    /// publisher (advertising this endpoint's `EndpointInfo`) plus a
    /// resolver (looking up other endpoints that advertised on the same
    /// relay).
    ///
    /// Pass [`default_relays`] for n0's public pkarr relay, or supply
    /// your own (typically a yubaba cloud node running an embedded
    /// relay::Server, see R105-F4). Calling with an empty iterator
    /// leaves the swarm lane disabled.
    pub fn with_relays<I>(mut self, urls: I) -> Self
    where
        I: IntoIterator<Item = Url>,
    {
        self.relay_urls = urls.into_iter().collect();
        self
    }

    /// Append a single pkarr relay URL (does not replace existing).
    pub fn add_relay(mut self, url: Url) -> Self {
        self.relay_urls.push(url);
        self
    }

    /// Attach an external roster source. mshr subscribes once at
    /// bind time and feeds emitted [`PeerHint`]s into a private
    /// `MemoryLookup` for the life of the endpoint.
    ///
    /// Multiple roster sources can be layered (society + yubaba, say)
    /// — each chain call appends another source.
    pub fn with_external_roster<S>(mut self, source: S) -> Self
    where
        S: PeerSource,
    {
        self.rosters.push(Arc::new(source));
        self
    }

    /// Attach an `Arc<dyn PeerSource>` directly — useful when the same
    /// source is shared across crate boundaries (e.g. society and
    /// yubaba both holding the same roster).
    pub fn with_external_roster_arc(mut self, source: Arc<dyn PeerSource>) -> Self {
        self.rosters.push(source);
        self
    }

    /// LAN lane on?
    pub fn lan_enabled(&self) -> bool {
        self.lan
    }

    /// Currently-pinned static seeds.
    pub fn static_seeds(&self) -> &[EndpointAddr] {
        &self.static_seeds
    }

    /// Configured pkarr relay URLs for the swarm lane.
    pub fn relay_urls(&self) -> &[Url] {
        &self.relay_urls
    }

    /// Number of attached external-roster sources.
    pub fn roster_count(&self) -> usize {
        self.rosters.len()
    }

    /// Whether any configured lane can turn a *bare* [`NodeId`] into a path.
    ///
    /// The single definition of that question in the crate —
    /// [`crate::Seeds::resolves_bare_node_ids`] and
    /// [`crate::Endpoint::resolves_bare_node_ids`] both delegate here, so a
    /// caller cannot be told "yes" by one and "no" by another.
    ///
    /// A pinned seed counts only when it carries addresses or a relay of its
    /// own: pinning a bare NodeId resolves nothing, it *is* the thing needing
    /// resolution. Rosters count because a source exists to emit addresses,
    /// even though it may not have emitted any yet.
    ///
    /// Worth asking at all because of what the failure looks like otherwise.
    /// iroh does refuse a bare NodeId with no lane promptly — but with
    /// `"No addressing information available"`, which names no lane, no
    /// setting and no next step (the actionable half, `"No address lookup
    /// configured"`, only reaches a WARN log). A caller that asks this first
    /// can say which knob is missing instead. Pinned in
    /// `tests/seeds_round_trip.rs`.
    pub fn resolves_bare_node_ids(&self) -> bool {
        self.lan
            || !self.relay_urls.is_empty()
            || !self.rosters.is_empty()
            || self.static_seeds.iter().any(|a| !a.is_empty())
    }

    /// Apply the configured lanes to an `iroh::endpoint::Builder`. Called
    /// by [`crate::EndpointBuilder::bind`]; not normally invoked by hand.
    pub(crate) fn apply(self, mut b: IrohBuilder) -> IrohBuilder {
        if !self.static_seeds.is_empty() {
            let mem = MemoryLookup::with_provenance("mshr/static");
            for seed in self.static_seeds {
                mem.add_endpoint_info(seed);
            }
            b = b.address_lookup(mem);
        }
        if self.lan {
            b = b.address_lookup(match self.lan_sightings {
                Some(s) => LanLookupBuilder::with_sightings(s),
                None => LanLookupBuilder::default(),
            });
        }
        for url in self.relay_urls {
            // Both publisher and resolver target the same relay URL.
            // PkarrPublisherBuilder + PkarrResolverBuilder implement
            // AddressLookupBuilder, so they pick up secret_key + tls
            // config from the constructed Endpoint.
            b = b
                .address_lookup(PkarrPublisher::builder(url.clone()))
                .address_lookup(PkarrResolver::builder(url));
        }
        for source in self.rosters {
            // Each roster gets its own MemoryLookup (one provenance per
            // source) with a background task forwarding the stream.
            let mem = MemoryLookup::with_provenance("mshr/roster");
            spawn_roster_pump(source, mem.clone());
            b = b.address_lookup(mem);
        }
        b
    }
}

fn spawn_roster_pump(source: Arc<dyn PeerSource>, sink: MemoryLookup) {
    use std::task::Poll;

    let mut stream = source.subscribe();
    tokio::spawn(async move {
        // Hand-rolled `next()` over the boxed Stream so we don't pull
        // in `futures-util` just for one helper. `Pin<Box<S>>` derefs
        // to `S`, and `as_mut()` projects to `Pin<&mut S>` for poll.
        std::future::poll_fn(move |cx| -> Poll<()> {
            loop {
                match stream.as_mut().poll_next(cx) {
                    Poll::Ready(Some(PeerHint::Found(addr))) => {
                        sink.add_endpoint_info(addr);
                    }
                    Poll::Ready(Some(PeerHint::Lost(id))) => {
                        sink.remove_endpoint_info(id);
                    }
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_off() {
        let d = Discovery::new();
        assert!(!d.lan_enabled());
        assert!(d.static_seeds().is_empty());
        assert!(d.relay_urls().is_empty());
        assert_eq!(d.roster_count(), 0);
    }

    #[test]
    fn with_static_collects() {
        use iroh::SecretKey;
        let id = SecretKey::generate().public();
        let d = Discovery::new().with_static([EndpointAddr::from(id)]);
        assert_eq!(d.static_seeds().len(), 1);
    }

    #[test]
    fn default_relays_parses() {
        let urls = default_relays();
        assert_eq!(urls.len(), 1);
    }

    #[test]
    fn with_relays_collects() {
        let d = Discovery::new().with_relays(default_relays());
        assert_eq!(d.relay_urls().len(), 1);
    }

    #[test]
    fn add_relay_appends() {
        let d = Discovery::new()
            .with_relays(default_relays())
            .add_relay("https://relay.example/pkarr".parse().unwrap());
        assert_eq!(d.relay_urls().len(), 2);
    }

    struct EmptyStream;
    impl Stream for EmptyStream {
        type Item = PeerHint;
        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(None)
        }
    }

    struct EmptySource;
    impl PeerSource for EmptySource {
        fn subscribe(&self) -> PeerHintStream {
            Box::pin(EmptyStream)
        }
    }

    #[test]
    fn with_external_roster_collects() {
        let d = Discovery::new().with_external_roster(EmptySource);
        assert_eq!(d.roster_count(), 1);
    }
}

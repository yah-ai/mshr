//! LAN lane: standards-conformant DNS-SD (RFC 6762 / RFC 6763) discovery.
//!
//! One wire format, two backends chosen by platform — never by a runtime
//! flag:
//!
//! - **Apple** (`target_vendor = "apple"`: iOS, macOS, tvOS, visionOS) —
//!   the system `dns_sd` API in libSystem, i.e. mDNSResponder. iOS 14+
//!   refuses raw multicast sends (`EHOSTUNREACH`) without the
//!   Apple-approval-gated `com.apple.developer.networking.multicast`
//!   entitlement; Bonjour needs only `NSLocalNetworkUsageDescription` plus
//!   `_mshr._udp` in the app's `NSBonjourServices`. macOS takes the same
//!   path so the code iOS ships is the code the dev box exercises.
//! - **Everything else** — the pure-Rust `mdns-sd` responder.
//!
//! ## Why not `iroh-mdns-address-lookup`
//!
//! That crate (and the `swarm-discovery` wire under it, checked at 0.6.3)
//! is not DNS-SD-conformant, so no Bonjour stack can interoperate with it
//! in either direction: its responses carry no PTR record, every record
//! has TTL 0 (which mDNS defines as a goodbye), it answers only PTR
//! queries, and it reads addresses only from the additionals section while
//! reading SRV/TXT only from answers. Measured 2026-09-22: `dns-sd -B
//! _irohv1._udp` on a Mac running a swarm-discovery peer saw nothing in
//! 12s. The LAN lane therefore moved wholesale to standard DNS-SD on every
//! platform (R938) under its own service type, so the two wires never
//! misread each other's packets.
//!
//! ## Record format
//!
//! Service `_mshr._udp.local.`; instance label = lowercase RFC 4648
//! base32 (no padding) of the 32-byte endpoint id (52 chars, inside the
//! 63-byte label limit). TXT keys:
//!
//! - `a0`..`aN` — one direct socket address each (`1.2.3.4:5`,
//!   `[fe80::1]:5`). Authoritative: iroh's v4 and v6 sockets can sit on
//!   different ports and a DNS-SD instance carries only one SRV port.
//! - `relay` — home relay URL, if any.
//! - `user-data` — iroh `UserData` (≤245 bytes, so `user-data=` + value
//!   still fits the 255-byte TXT string limit).
//! - `scope` — the endpoint's [`LanScope`]; absent for the public scope.
//!
//! ## Scopes
//!
//! A [`LanScope`] partitions one LAN into private discovery groups. An
//! endpoint advertises its scope and keeps only sightings whose scope is
//! *exactly* its own; unscoped (public) endpoints are one more such group.
//! A filtered-out peer never enters the book, so it is invisible to
//! [`LanSightings`] and to iroh's resolve alike. This is noise control, not
//! access control: the scope travels in cleartext multicast, and anyone who
//! learns an endpoint id can still dial it through any other lane.
//!
//! The SRV port is the first advertised address's port and the SRV host is
//! whatever the backend owns; neither is read back.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_core::Stream;
use iroh::address_lookup::{
    AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, EndpointData, EndpointInfo,
    Error as LookupError, Item,
};
use iroh::Endpoint as IrohEndpoint;
use tokio::sync::{broadcast, mpsc};
use tracing::debug;

use crate::EndpointId;

#[cfg(target_vendor = "apple")]
mod dnssd;
#[cfg(any(not(target_vendor = "apple"), test))]
mod mdns;

#[cfg(target_vendor = "apple")]
use dnssd::Backend;
#[cfg(not(target_vendor = "apple"))]
use mdns::Backend;

/// DNS-SD service type, without the domain.
pub(crate) const SERVICE_TYPE: &str = "_mshr._udp";

/// Provenance tag on every [`Item`] this lane yields.
const PROVENANCE: &str = "mshr/lan";

/// How long a `resolve` keeps listening for the peer to show up — the same
/// window `iroh-mdns-address-lookup` used.
const LOOKUP_DURATION: Duration = Duration::from_secs(10);

/// Cap on advertised addresses: keeps the TXT record inside one packet.
const MAX_ADDRS: usize = 16;

const RELAY_KEY: &str = "relay";
const USER_DATA_KEY: &str = "user-data";
const SCOPE_KEY: &str = "scope";

/// A private LAN discovery scope — see the [module docs](self#scopes).
///
/// Non-empty, at most [`LanScope::MAX_LEN`] bytes, no control characters.
/// The bound is what keeps `scope=<value>` inside one TXT string: a scope
/// the wire could not carry would otherwise be dropped from the advert and
/// the endpoint would silently look public.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LanScope(String);

impl LanScope {
    /// Longest scope, in bytes.
    pub const MAX_LEN: usize = 64;

    /// Validate `scope`. Compared byte-for-byte: no case folding or
    /// normalisation, so `Band` and `band` are different scopes.
    pub fn new(scope: impl Into<String>) -> Result<Self, crate::Error> {
        let scope = scope.into();
        if scope.is_empty() {
            return Err(crate::Error::Endpoint("LAN scope is empty".into()));
        }
        if scope.len() > Self::MAX_LEN {
            return Err(crate::Error::Endpoint(format!(
                "LAN scope is {} bytes, the limit is {}",
                scope.len(),
                Self::MAX_LEN
            )));
        }
        if scope.chars().any(char::is_control) {
            return Err(crate::Error::Endpoint(
                "LAN scope contains a control character".into(),
            ));
        }
        Ok(Self(scope))
    }

    /// The scope as advertised.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LanScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// DNS-SD instance label for an endpoint id.
pub(crate) fn instance_name(id: &EndpointId) -> String {
    data_encoding::BASE32_NOPAD
        .encode(id.as_bytes())
        .to_ascii_lowercase()
}

/// Inverse of [`instance_name`]. Accepts a bare label or a full service
/// name (`<label>._mshr._udp.local.`); `None` for anything that is not one
/// of ours.
pub(crate) fn parse_instance(name: &str) -> Option<EndpointId> {
    let label = name.split('.').next()?;
    let bytes = data_encoding::BASE32_NOPAD
        .decode(label.to_ascii_uppercase().as_bytes())
        .ok()?;
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    EndpointId::from_bytes(&bytes).ok()
}

/// What one endpoint advertises on the LAN, already in wire terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Advert {
    pub instance: String,
    pub port: u16,
    /// TXT key/value pairs, in wire order.
    pub txt: Vec<(String, String)>,
    /// Distinct IPs of the advertised socket addresses (for backends that
    /// publish their own A/AAAA records).
    pub ips: Vec<IpAddr>,
}

impl Advert {
    /// `None` when there is nothing dialable to advertise — a relay-only
    /// endpoint gains nothing from LAN discovery.
    pub(crate) fn new(
        id: &EndpointId,
        data: &EndpointData,
        scope: Option<&LanScope>,
    ) -> Option<Self> {
        let mut addrs: Vec<SocketAddr> = data
            .ip_addrs()
            .filter(|a| !a.ip().is_unspecified() && a.port() != 0)
            .copied()
            .collect();
        // v4 first so the SRV port is the v4 socket's, which every LAN has.
        addrs.sort_by_key(|a| (a.is_ipv6(), *a));
        addrs.dedup();
        addrs.truncate(MAX_ADDRS);
        let port = addrs.first()?.port();

        let mut txt: Vec<(String, String)> = addrs
            .iter()
            .enumerate()
            .map(|(i, a)| (format!("a{i}"), a.to_string()))
            .collect();
        if let Some(relay) = data.relay_urls().next() {
            txt.push((RELAY_KEY.to_string(), relay.to_string()));
        }
        if let Some(user_data) = data.user_data() {
            txt.push((USER_DATA_KEY.to_string(), user_data.to_string()));
        }
        if let Some(scope) = scope {
            // Always fits: `LanScope::MAX_LEN` keeps it under the cut below.
            txt.push((SCOPE_KEY.to_string(), scope.as_str().to_string()));
        }
        // A TXT string is length-prefixed by one byte.
        txt.retain(|(k, v)| k.len() + 1 + v.len() <= 255);

        let mut ips: Vec<IpAddr> = addrs.iter().map(|a| a.ip()).collect();
        ips.dedup();
        Some(Self {
            instance: instance_name(id),
            port,
            txt,
            ips,
        })
    }
}

/// A peer's decoded TXT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record {
    pub data: EndpointData,
    /// The advertised `scope`, raw: a peer's scope is compared, never
    /// validated — an invalid one simply matches no [`LanScope`].
    pub scope: Option<String>,
}

/// Decode a peer's TXT pairs. `None` when the record carries no usable
/// address — a stranger on our service type, or a peer mid-update.
pub(crate) fn decode_txt<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<Record> {
    let mut addrs = BTreeSet::new();
    let mut relay = None;
    let mut user_data = None;
    let mut scope = None;
    for (k, v) in pairs {
        match k {
            RELAY_KEY => relay = v.parse().ok(),
            USER_DATA_KEY => user_data = v.parse().ok(),
            SCOPE_KEY => scope = Some(v.to_string()),
            _ if k.len() > 1 && k.starts_with('a') && k[1..].bytes().all(|b| b.is_ascii_digit()) => {
                if let Ok(a) = v.parse::<SocketAddr>() {
                    addrs.insert(a);
                }
            }
            _ => {}
        }
    }
    if addrs.is_empty() {
        return None;
    }
    let mut data = EndpointData::from(addrs);
    if let Some(relay) = relay {
        data.add_relay_url(relay);
    }
    data.set_user_data(user_data);
    Some(Record { data, scope })
}

/// Buffered sightings per subscriber before it counts as lagged (and is
/// resynced from the book — see [`LanSightingsReceiver::recv`]).
const SIGHTINGS_CAPACITY: usize = 64;

/// Everything the LAN has told us, plus the resolves and sightings
/// subscribers waiting on it. Shared between the backend (writer),
/// [`LanLookup`] (reader) and any [`LanSightings`] handle.
#[derive(Debug)]
pub(crate) struct Book {
    /// Our own endpoint id, filtered out of every sighting. Set once, when
    /// the lookup is built: a [`LanSightings`] handle exists before the
    /// endpoint (and so its id) does. No backend runs before it is set.
    own: OnceLock<EndpointId>,
    inner: Mutex<BookInner>,
    /// Sent to under `inner`'s lock, so a subscriber's snapshot and its
    /// receiver agree on where the stream starts.
    sightings: broadcast::Sender<LanSighting>,
    /// What we advertise, so a scope change can re-advertise it.
    advertising: Mutex<Advertising>,
}

#[derive(Debug, Default)]
struct BookInner {
    /// The scope sightings must match exactly; `None` = public. Changeable
    /// at any time ([`Book::set_scope`]).
    scope: Option<LanScope>,
    /// Every record the LAN holds, whatever its scope — what a scope change
    /// re-filters, so a peer already advertising in the new scope is found
    /// at once rather than at its next announcement.
    heard: HashMap<EndpointId, Record>,
    /// The in-scope subset of `heard`: what sightings and resolves see.
    peers: HashMap<EndpointId, EndpointData>,
    waiters: HashMap<EndpointId, Vec<mpsc::Sender<Item>>>,
}

/// The backend a book advertises through, and the last data iroh published.
#[derive(Debug, Default)]
struct Advertising {
    /// Weak: the backend owns an `Arc` of this book.
    backend: Option<std::sync::Weak<Backend>>,
    published: Option<EndpointData>,
}

fn in_scope(scope: &Option<LanScope>, record: &Record) -> bool {
    record.scope.as_deref() == scope.as_ref().map(LanScope::as_str)
}

impl Book {
    fn unbound() -> Arc<Self> {
        Arc::new(Self {
            own: OnceLock::new(),
            inner: Mutex::default(),
            sightings: broadcast::channel(SIGHTINGS_CAPACITY).0,
            advertising: Mutex::default(),
        })
    }

    #[cfg(test)]
    pub(crate) fn new(own: EndpointId) -> Arc<Self> {
        let book = Self::unbound();
        book.bind(own).expect("fresh book is unbound");
        book
    }

    /// Fix the endpoint this book belongs to. Idempotent for the same id;
    /// an error for a different one (one book per endpoint).
    fn bind(&self, own: EndpointId) -> Result<(), EndpointId> {
        match self.own.get_or_init(|| own) {
            bound if *bound == own => Ok(()),
            bound => Err(*bound),
        }
    }

    /// Is `id` the endpoint this book belongs to?
    pub(crate) fn is_own(&self, id: &EndpointId) -> bool {
        self.own.get() == Some(id)
    }

    /// The scope this book admits; `None` = public.
    pub(crate) fn scope(&self) -> Option<LanScope> {
        self.inner.lock().expect("lan book poisoned").scope.clone()
    }

    /// Move to `scope`: re-filter everything already heard — a `Lost` for
    /// each peer left behind, a `Found` for each one already advertising in
    /// the new scope — then re-advertise under it. No-op if unchanged.
    pub(crate) fn set_scope(&self, scope: Option<LanScope>) {
        {
            let mut inner = self.inner.lock().expect("lan book poisoned");
            if inner.scope == scope {
                return;
            }
            debug!(from = ?inner.scope, to = ?scope, "lan: scope changed");
            inner.scope = scope;
            let inner = &mut *inner;
            let left: Vec<EndpointId> = inner
                .peers
                .keys()
                .filter(|id| !inner.heard.get(*id).is_some_and(|r| in_scope(&inner.scope, r)))
                .copied()
                .collect();
            for id in left {
                inner.peers.remove(&id);
                let _ = self.sightings.send(LanSighting::Lost(id));
            }
            let joined: Vec<(EndpointId, EndpointData)> = inner
                .heard
                .iter()
                .filter(|(id, r)| in_scope(&inner.scope, r) && inner.peers.get(*id) != Some(&r.data))
                .map(|(id, r)| (*id, r.data.clone()))
                .collect();
            for (id, data) in joined {
                self.admit(inner, id, data);
            }
        }
        self.readvertise();
    }

    /// A peer announced (or re-announced) itself. Kept whatever its scope;
    /// sighted only in ours — and a peer that re-announces out of our scope
    /// has departed it.
    pub(crate) fn found(&self, id: EndpointId, record: Record) {
        if self.is_own(&id) {
            return;
        }
        let mut inner = self.inner.lock().expect("lan book poisoned");
        let inner = &mut *inner;
        let admitted = in_scope(&inner.scope, &record);
        let data = record.data.clone();
        inner.heard.insert(id, record);
        if !admitted {
            debug!(%id, "lan: peer outside our scope");
            if inner.peers.remove(&id).is_some() {
                let _ = self.sightings.send(LanSighting::Lost(id));
            }
            return;
        }
        if inner.peers.get(&id) == Some(&data) {
            return;
        }
        self.admit(inner, id, data);
    }

    /// Put an in-scope peer in the book: wake its resolves, announce it.
    fn admit(&self, inner: &mut BookInner, id: EndpointId, data: EndpointData) {
        debug!(%id, ?data, "lan: peer found");
        if let Some(waiters) = inner.waiters.get_mut(&id) {
            let item = item(id, data.clone());
            waiters.retain(|w| w.try_send(item.clone()).is_ok() || !w.is_closed());
        }
        // Err = no subscriber right now, which is fine.
        let _ = self
            .sightings
            .send(LanSighting::Found(EndpointInfo::from_parts(id, data.clone())));
        inner.peers.insert(id, data);
    }

    /// A peer withdrew (goodbye, or browse lost it on every interface).
    pub(crate) fn lost(&self, id: EndpointId) {
        let mut inner = self.inner.lock().expect("lan book poisoned");
        inner.heard.remove(&id);
        if inner.peers.remove(&id).is_some() {
            debug!(%id, "lan: peer lost");
            let _ = self.sightings.send(LanSighting::Lost(id));
        }
    }

    /// Advertise through `backend` from now on.
    fn attach(&self, backend: &Arc<Backend>) {
        self.advertising.lock().expect("lan advertising poisoned").backend = Some(Arc::downgrade(backend));
    }

    /// iroh published new addresses: advertise them under our scope.
    fn publish(&self, data: &EndpointData) {
        self.advertising.lock().expect("lan advertising poisoned").published = Some(data.clone());
        self.readvertise();
    }

    fn readvertise(&self) {
        // The advertising lock first, then the scope: a publish racing a
        // scope change advertises whichever scope is newer, never an old one
        // last.
        let advertising = self.advertising.lock().expect("lan advertising poisoned");
        let (Some(own), scope) = (self.own.get(), self.scope()) else { return };
        let (Some(backend), Some(data)) =
            (advertising.backend.as_ref().and_then(std::sync::Weak::upgrade), &advertising.published)
        else {
            return;
        };
        backend.advertise(Advert::new(own, data, scope.as_ref()));
    }

    /// Every current peer, plus a receiver positioned right after them.
    fn snapshot(&self) -> (Vec<EndpointInfo>, broadcast::Receiver<LanSighting>) {
        let inner = self.inner.lock().expect("lan book poisoned");
        let rx = self.sightings.subscribe();
        let peers = inner
            .peers
            .iter()
            .map(|(id, data)| EndpointInfo::from_parts(*id, data.clone()))
            .collect();
        (peers, rx)
    }

    /// Current entry for `id`, if any.
    #[cfg(test)]
    pub(crate) fn get(&self, id: &EndpointId) -> Option<EndpointData> {
        self.inner.lock().expect("lan book poisoned").peers.get(id).cloned()
    }

    fn subscribe(&self, id: EndpointId) -> mpsc::Receiver<Item> {
        let (tx, rx) = mpsc::channel(8);
        let mut inner = self.inner.lock().expect("lan book poisoned");
        if let Some(data) = inner.peers.get(&id) {
            let _ = tx.try_send(item(id, data.clone()));
        }
        let waiters = inner.waiters.entry(id).or_default();
        waiters.retain(|w| !w.is_closed());
        waiters.push(tx);
        rx
    }
}

fn item(id: EndpointId, data: EndpointData) -> Item {
    Item::new(EndpointInfo::from_parts(id, data), PROVENANCE, None)
}

/// One change in who is advertising `_mshr._udp` on the LAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LanSighting {
    /// A peer appeared, or re-announced with different addresses. Carries
    /// everything it advertises (direct addrs, relay, user data);
    /// [`EndpointInfo::into_endpoint_addr`] gives a dialable address.
    Found(EndpointInfo),
    /// A peer withdrew its advertisement (goodbye, or no interface sees it),
    /// or it or we left the other's [`LanScope`].
    Lost(EndpointId),
}

/// Handle on the LAN lane's sightings: every peer currently advertising,
/// and a subscription to arrivals and departures.
///
/// Create it *before* the endpoint and hand a clone to
/// [`crate::Discovery::with_lan_sightings`] (or
/// [`LanLookupBuilder::with_sightings`]); the lookup iroh builds then
/// writes into it. One handle serves one endpoint: binding it to a second
/// endpoint id fails the build.
#[derive(Debug, Clone)]
pub struct LanSightings {
    book: Arc<Book>,
}

impl Default for LanSightings {
    fn default() -> Self {
        Self::new()
    }
}

impl LanSightings {
    /// A handle not yet attached to any lookup; it sees nothing until one is
    /// built with it.
    pub fn new() -> Self {
        Self {
            book: Book::unbound(),
        }
    }

    /// Move the lane to `scope` (`None` = public), live: the endpoint
    /// re-advertises under it, and the sightings re-filter at once — a
    /// [`LanSighting::Lost`] for each peer left behind and a
    /// [`LanSighting::Found`] for each one already in the new scope. Nothing
    /// is rebound and no connection is touched: a scope decides who is
    /// *discovered*, not who stays connected. Called before the lookup is
    /// built, it sets the scope the lookup starts in.
    pub fn set_scope(&self, scope: Option<LanScope>) {
        self.book.set_scope(scope);
    }

    /// The scope the lane is in now.
    pub fn scope(&self) -> Option<LanScope> {
        self.book.scope()
    }

    /// Everyone advertising right now.
    pub fn peers(&self) -> Vec<EndpointInfo> {
        self.book.snapshot().0
    }

    /// Subscribe: first a [`LanSighting::Found`] for every current peer, then
    /// each change as it happens.
    pub fn subscribe(&self) -> LanSightingsReceiver {
        let (peers, rx) = self.book.snapshot();
        LanSightingsReceiver {
            book: self.book.clone(),
            pending: peers.into_iter().map(LanSighting::Found).collect(),
            rx,
            present: HashSet::new(),
        }
    }
}

/// Receiving half of [`LanSightings::subscribe`].
#[derive(Debug)]
pub struct LanSightingsReceiver {
    book: Arc<Book>,
    pending: VecDeque<LanSighting>,
    rx: broadcast::Receiver<LanSighting>,
    /// Ids this receiver has reported found and not yet lost — what a resync
    /// diffs against.
    present: HashSet<EndpointId>,
}

impl LanSightingsReceiver {
    /// Next sighting. Never misses a departure: a receiver that falls more
    /// than the channel capacity behind is resynced from the book — a `Lost`
    /// for each peer it knew that is gone, then a `Found` for every current
    /// one — rather than skipping events.
    pub async fn recv(&mut self) -> LanSighting {
        loop {
            if let Some(s) = self.pending.pop_front() {
                return self.track(s);
            }
            match self.rx.recv().await {
                Ok(s) => return self.track(s),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    debug!(skipped, "lan: sightings receiver lagged; resyncing");
                    self.resync();
                }
                Err(broadcast::error::RecvError::Closed) => {
                    unreachable!("the sender lives in the book this receiver holds")
                }
            }
        }
    }

    fn track(&mut self, s: LanSighting) -> LanSighting {
        match &s {
            LanSighting::Found(info) => {
                self.present.insert(info.endpoint_id);
            }
            LanSighting::Lost(id) => {
                self.present.remove(id);
            }
        }
        s
    }

    fn resync(&mut self) {
        let (peers, rx) = self.book.snapshot();
        let now: HashSet<EndpointId> = peers.iter().map(|p| p.endpoint_id).collect();
        self.pending = self
            .present
            .iter()
            .filter(|id| !now.contains(*id))
            .map(|id| LanSighting::Lost(*id))
            .chain(peers.into_iter().map(LanSighting::Found))
            .collect();
        self.rx = rx;
    }
}

/// iroh [`AddressLookup`] over the LAN lane. Build via [`LanLookupBuilder`]
/// (what [`crate::Discovery::with_lan`] installs).
#[derive(Debug, Clone)]
pub struct LanLookup {
    book: Arc<Book>,
    /// The only strong reference: the book advertises through a weak one,
    /// so dropping the lookup still withdraws the advert.
    #[allow(dead_code)]
    backend: Arc<Backend>,
}

impl LanLookup {
    /// Start browsing and (once iroh publishes addresses) advertising for
    /// `own`.
    pub fn spawn(own: EndpointId) -> std::io::Result<Self> {
        Self::spawn_with(own, &LanSightings::new())
    }

    /// [`LanLookup::spawn`], reporting what it sees into `sightings`, in the
    /// scope `sightings` is in ([`LanSightings::set_scope`]). Fails if
    /// `sightings` already serves a different endpoint.
    pub fn spawn_with(own: EndpointId, sightings: &LanSightings) -> std::io::Result<Self> {
        let book = sightings.book.clone();
        book.bind(own).map_err(|bound| {
            std::io::Error::other(format!(
                "LanSightings already bound to endpoint {bound}, cannot serve {own}"
            ))
        })?;
        let backend = Arc::new(Backend::spawn(book.clone())?);
        book.attach(&backend);
        Ok(Self { book, backend })
    }
}

impl AddressLookup for LanLookup {
    fn publish(&self, data: &EndpointData) {
        // Through the book, which knows the scope and keeps `data` to
        // re-advertise under a new one.
        self.book.publish(data);
    }

    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<Pin<Box<dyn Stream<Item = Result<Item, LookupError>> + Send + 'static>>> {
        Some(Box::pin(Resolving {
            rx: self.book.subscribe(endpoint_id),
            deadline: None,
        }))
    }
}

/// Yields the cached entry (if any) and every update for one peer, for
/// [`LOOKUP_DURATION`].
struct Resolving {
    rx: mpsc::Receiver<Item>,
    /// Created on first poll: `tokio::time::sleep` needs a runtime context,
    /// and `resolve` makes no promise of one.
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Stream for Resolving {
    type Item = Result<Item, LookupError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Poll::Ready(item) = self.rx.poll_recv(cx) {
            return Poll::Ready(item.map(Ok));
        }
        let deadline = self
            .deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(LOOKUP_DURATION)));
        match deadline.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

use std::future::Future as _;

/// [`AddressLookupBuilder`] for [`LanLookup`] — picks up the endpoint id
/// from the endpoint being built.
///
/// @yah:relay(R942, "mshr LAN sightings subscription: list who is advertising _mshr._udp, not just resolve known ids")
/// @yah:status(review)
/// @yah:at(2026-09-26T03:41:33Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:next("LanLookup only answers AddressLookup::resolve(endpoint_id). Book (pub(crate)) holds every sighting, but the LanLookup is built inside iroh by LanLookupBuilder::into_address_lookup, so no caller keeps a handle. The primitive: a sightings subscription (found/lost per EndpointId + addrs) created BEFORE the endpoint is built and threaded into the lookup, e.g. a LanLookupBuilder carrying a shared Book or broadcast sender. Both backends (dnssd on Apple, mdns-sd elsewhere) already feed Book::found/lost.")
/// @yah:next("Consumer: noisetable R748-F6 feeds each sighting into society's net::PresenceRoster as PeerHint::Found. Then W203's society_* étude telemetry reads the roster. noisetable doc: .yah/docs/working/W203-multi-instance-etudes.md Gap 2.")
/// @yah:next("Ships in the normal distribution, not dev-only: Society telemetry is a product goal. Keep it to std/tokio channels.")
/// @yah:verify("Unit test in lan/tests.rs: two LanLookups on loopback; the subscriber sees the other's EndpointId appear (found) and disappear on drop (lost).")
/// @yah:handoff("SHIPPED (unpublished; do not publish without operator): public LanSightings handle in oss/mshr/crates/mshr/src/lan/mod.rs. Book is now shared and created before the endpoint, with own id in a OnceLock bound at into_address_lookup; one handle per endpoint, and a second id fails the build. Book::found/lost broadcast LanSighting::{Found(EndpointInfo), Lost(EndpointId)} under the book lock, so subscribe() snapshots current peers atomically, and a lagged receiver resyncs (Lost for vanished ids, then Found for all). Wiring: Discovery::with_lan_sightings, LanLookupBuilder::with_sightings (no longer Copy), LanLookup::spawn_with, re-exported at the crate root. dnssd.rs uses Book::is_own. CHANGELOG [Unreleased] entry added. Consumer: noisetable R748-F6 via scripts/devcrate.sh on mshr.")
/// @yah:verify("cargo test -p mshr: 58 lib passed (6 ignored) + all integration suites green; 3 new non-live tests (snapshot then changes, lag resync keeps departures, one endpoint per handle); live test lan_lookup_sightings_found_then_lost (--ignored, two LanLookups on loopback, found then lost on drop) passed in 2.5s on macOS dnssd; clippy --all-targets clean; cargo check --target aarch64-apple-ios clean; cargo doc has only the pre-existing discovery.rs [Unreleased] link warning.")
#[derive(Debug, Default, Clone)]
pub struct LanLookupBuilder {
    sightings: Option<LanSightings>,
}

impl LanLookupBuilder {
    /// Builder whose lookup reports into `sightings`, and runs in the scope
    /// `sightings` is in ([`LanSightings::set_scope`]).
    pub fn with_sightings(sightings: LanSightings) -> Self {
        Self {
            sightings: Some(sightings),
        }
    }
}

impl AddressLookupBuilder for LanLookupBuilder {
    fn into_address_lookup(
        self,
        endpoint: &IrohEndpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        let sightings = self.sightings.unwrap_or_default();
        LanLookup::spawn_with(endpoint.id(), &sightings)
            .map_err(|e| AddressLookupBuilderError::from_err(PROVENANCE, e))
    }
}

#[cfg(test)]
mod tests;

//! Apple backend: mDNSResponder via the `dns_sd` C API in libSystem.
//!
//! Signatures and constants are transcribed from the SDK's
//! `usr/include/dns_sd.h`. Every operation shares one connection
//! (`kDNSServiceFlagsShareConnection`) owned by a single dedicated thread:
//! `DNSServiceRef`s are not thread-safe, so the thread is the only thing
//! that ever touches one, and the rest of mshr talks to it over a channel.
//! Callbacks run synchronously inside `DNSServiceProcessResult` on that
//! same thread; anything they would start or stop is queued and applied
//! after it returns, so no callback re-enters the API.
//!
//! Flow: Browse `_mshr._udp` → per new instance, a TXT record query (kept
//! open so TXT changes stream in) → decode TXT into the [`Book`]. Browse
//! removal on the instance's last interface stops the query and drops the
//! peer.
//!
//! Peer-to-peer links (AWDL) are excluded from `kDNSServiceInterfaceIndexAny`
//! unless a call sets `kDNSServiceFlagsIncludeP2P`, and AWDL specifically
//! also `kDNSServiceFlagsIncludeAWDL` (dns_sd.h). Every call sets both or
//! neither, per [`super::LanSightings::set_peer_to_peer`]; a switch tears the
//! connection down and rebuilds it under the new flags.
//!
//! The TXT comes from `DNSServiceQueryRecord`, not `DNSServiceResolve`. A
//! Resolve keeps ONE TXT and ONE SRV for the instance across every
//! interface: each reply carries the TXT added last on *any* interface,
//! labelled with the interface of whichever record's arrival triggered it,
//! and removals are never delivered, they only blank the slot until both
//! record types arrive again. Measured on macOS against an iPad over USB,
//! Wi-Fi and AWDL (noisetable R803-B20): three replies labelled `en0` while
//! the TXT records sat on `en8`, `en9` and `en0`. So per-interface
//! bookkeeping built on Resolve replies files one interface's TXT under
//! another, and once an interface goes away it keeps whichever TXT was
//! filed under the survivor. A record query reports every TXT record
//! mDNSResponder holds, each with the interface it was heard on, and reports
//! removals too. [`TxtRecords`] mirrors exactly that set, every link-local
//! address re-scoped to its record's interface ([`super::Record::heard_on`]),
//! and the Book gets the union.
//!
//! @yah:relay(R961, "mshr LAN lane over AWDL: Apple dns_sd excludes awdl0 by default (no kDNSServiceFlagsIncludeAWDL), and a resolved fe80 address keeps the advertiser's scope id")
//! @yah:status(review)
//! @yah:at(2026-10-08T06:33:16Z)
//! @yah:assignee(bundle-anthropic-ashguard)
//! @yah:next("FLAGS. lan/dnssd.rs calls DNSServiceBrowse, DNSServiceRegister and DNSServiceResolve with interfaceIndex 0 and flags FLAGS_SHARE_CONNECTION (plus NO_AUTO_RENAME on Register). They never set kDNSServiceFlagsIncludeAWDL (0x100000) or IncludeP2P (0x20000). The MacOSX SDK dns_sd.h says of IncludeP2P: 'By default, specifying kDNSServiceInterfaceIndexAny does not include P2P interfaces'. Of IncludeAWDL it says 'Include AWDL interface when kDNSServiceInterfaceIndexAny is specified.' So a peer reachable only over awdl0 is never registered toward or sighted (a source read plus the header, not yet measured). Deciding whether AWDL inclusion is always on or an opt-in is this camp's call. Inference: an active AWDL browse makes the radio time-share with infrastructure Wi-Fi. noisetable R742-T16 measured ping6 averaging 103-171 ms over AWDL.")
//! @yah:next("SCOPE. on_resolve ignores its interface index. decode_txt parses each aN with SocketAddr::from_str, which keeps a %N scope (std core/src/net/parser.rs read_scope_id). So a TXT entry [fe80::x%14]:p arrives carrying the ADVERTISER's interface index, which names a different interface or none on the receiver. A link-local address resolved on interface N should be re-scoped to N, because a scope id is local to each host (noisetable R742-S15). A resolve can answer on several interfaces, so how the Book merges per-interface scopes is part of the design.")
//! @yah:next("CONSUMER: noisetable R803-F18 (awdl0 as a knock route, Mac+iPad, Wi-Fi and Bluetooth off). Its knock dials PresenceRoster::nearby_addr, which is fed only by LAN sightings, BLE hints and proven presence connections. With no Wi-Fi and no Bluetooth, only an awdl0 sighting can give the iPad the desk's address. noisetable will advertise its own fe80::%awdl0 through iroh add_external_addr, as R803-F17 does for 169.254.x. iroh's scope-id fix and netwatch's SO_RECV_ANYIF are already in noisetable's iroh/netwatch bursts. A cross-camp notify_on is inert, so whoever lands this should update noisetable R803-F18 (board path /Users/leif/ss/noisetable).")
//! @yah:handoff("FLAGS (my call: opt-in, matching Apple's includePeerToPeer default; reversing it means flipping the Advertising default in lan/mod.rs). New public LanSightings::set_peer_to_peer(bool) / peer_to_peer(). Book holds the flag under the advertising lock, and attach() pushes it to the backend, so a switch made before build is never lost. In dnssd.rs every Browse/Register/Resolve takes State::flags(), which adds IncludeP2P|IncludeAWDL when on. A switch arrives as Command::PeerToPeer, tears the connection down and rebuilds it. Switching off first drops peers reached only over peer-to-peer (State::leave_peer_to_peer). mdns.rs gets a documented no-op set_peer_to_peer.")
//! @yah:handoff("SCOPE. Record::heard_on(iface) re-scopes every link-local v6 address to the receiving interface. Record::merge unions per-interface records into a set-sorted EndpointData, so the order something was heard in never looks like a change. dnssd keeps one Record per Resolve interface (Seen::records) and Seen::prune drops what a browse REMOVE took. Browse reports AWDL finds under the pseudo index kDNSServiceInterfaceIndexP2P while Resolve gives the real awdl0 index, so the two are reconciled by kind: is_peer_to_peer checks the P2P index or an if_indextoname of awdl*/llw*. Resolve answers on 0 or a pseudo index (LocalOnly, same host) keep the advertiser's scope. Extra: the same bug existed in the mdns-sd backend, which now re-scopes to the interfaces its link-local AAAA ScopedIp arrived on.")
//! @yah:handoff("Dropped the @arch:see to noisetable's W226: it doesn't exist in this tree. Appended a handoff to noisetable R803-F18 (path /Users/leif/ss/noisetable) with the opt-in API and the gate-cleared note. CHANGELOG [Unreleased] has an Added entry (AWDL) and a Fixed entry (scope).")
//! @yah:verify("cargo test -p mshr --lib lan:: -- --include-ignored --test-threads=1: 22 passed, live dns_sd + mdns-sd interop included. New tests: heard_on_rescopes_link_local_only, merge_unions_interfaces_deterministically, peer_to_peer_defaults_off_and_switches, and the live lan_lookup_peer_to_peer_switch_is_live (both ends on, peer found; both switched off, peer kept and its update heard). cargo test -p mshr: 73 passed. clippy --all-targets: clean. cargo check --target aarch64-apple-ios: clean. cargo doc: only the existing [Unreleased] annotation-link warnings.")
//! @yah:verify("NOT measured: an actual awdl0 sighting between two devices (needs Mac+iPad hardware; noisetable R803-F18 owns that run). The claims that browse reports kDNSServiceInterfaceIndexP2P and that IncludeAWDL is needed in addition to IncludeP2P come from reading dns_sd.h, not from observation.")
//! @yah:assumes("The dnssd change assumes Resolve reports the real awdl0/llw0 index for a P2P answer (dns_sd.h line ~970 says so). If it reported the P2P pseudo index instead, heard_on is skipped (pseudo index) and the fe80 address would keep the advertiser's scope.")

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use super::{decode_txt, parse_instance, Advert, Book, Record, SERVICE_TYPE};

type DNSServiceRef = *mut c_void;
type DNSServiceFlags = u32;
type DNSServiceErrorType = i32;

const FLAGS_ADD: DNSServiceFlags = 0x2;
const FLAGS_NO_AUTO_RENAME: DNSServiceFlags = 0x8;
const FLAGS_SHARE_CONNECTION: DNSServiceFlags = 0x4000;
const FLAGS_INCLUDE_P2P: DNSServiceFlags = 0x20000;
const FLAGS_INCLUDE_AWDL: DNSServiceFlags = 0x100000;

/// `kDNSServiceInterfaceIndexP2P`: what browse reports for an instance
/// found over a peer-to-peer link.
const IF_INDEX_P2P: u32 = 0xffff_fffd;
/// `kDNSServiceInterfaceIndexInfra`, the lowest of the pseudo indices
/// (`..LocalOnly = 0xffffffff`); none of them names a real interface.
const IF_INDEX_PSEUDO_MIN: u32 = 0xffff_fffb;

const ERR_NO_ERROR: DNSServiceErrorType = 0;
const ERR_NAME_CONFLICT: DNSServiceErrorType = -65548;
const ERR_POLICY_DENIED: DNSServiceErrorType = -65570;

type RegisterReply = extern "C" fn(
    DNSServiceRef,
    DNSServiceFlags,
    DNSServiceErrorType,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
);
type BrowseReply = extern "C" fn(
    DNSServiceRef,
    DNSServiceFlags,
    u32,
    DNSServiceErrorType,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
);
type QueryRecordReply = extern "C" fn(
    DNSServiceRef,
    DNSServiceFlags,
    u32,
    DNSServiceErrorType,
    *const c_char,
    u16,
    u16,
    u16,
    *const u8,
    u32,
    *mut c_void,
);

extern "C" {
    fn DNSServiceCreateConnection(sd_ref: *mut DNSServiceRef) -> DNSServiceErrorType;
    fn DNSServiceRefSockFD(sd_ref: DNSServiceRef) -> c_int;
    fn DNSServiceProcessResult(sd_ref: DNSServiceRef) -> DNSServiceErrorType;
    fn DNSServiceRefDeallocate(sd_ref: DNSServiceRef);
    fn DNSServiceRegister(
        sd_ref: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        host: *const c_char,
        port_be: u16,
        txt_len: u16,
        txt_record: *const c_void,
        callback: RegisterReply,
        context: *mut c_void,
    ) -> DNSServiceErrorType;
    fn DNSServiceUpdateRecord(
        sd_ref: DNSServiceRef,
        record_ref: *mut c_void,
        flags: DNSServiceFlags,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
    ) -> DNSServiceErrorType;
    fn DNSServiceBrowse(
        sd_ref: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        regtype: *const c_char,
        domain: *const c_char,
        callback: BrowseReply,
        context: *mut c_void,
    ) -> DNSServiceErrorType;
    fn DNSServiceQueryRecord(
        sd_ref: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        fullname: *const c_char,
        rrtype: u16,
        rrclass: u16,
        callback: QueryRecordReply,
        context: *mut c_void,
    ) -> DNSServiceErrorType;
    fn DNSServiceConstructFullName(
        full_name: *mut c_char,
        service: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
    ) -> DNSServiceErrorType;
}

/// `kDNSServiceType_TXT` / `kDNSServiceClass_IN`.
const TYPE_TXT: u16 = 16;
const CLASS_IN: u16 = 1;
/// `kDNSServiceMaxDomainName`: the buffer `DNSServiceConstructFullName` fills.
const MAX_DOMAIN_NAME: usize = 1009;

/// How long the thread blocks in `poll` before checking for commands.
const TICK_MS: c_int = 200;
/// Backoff before reconnecting after mDNSResponder drops us.
const RECONNECT_AFTER: Duration = Duration::from_secs(1);

/// Handle to the dns_sd thread. Dropping it stops the thread, which
/// withdraws our registration (mDNSResponder sends the goodbye).
#[derive(Debug)]
pub(crate) struct Backend {
    tx: Mutex<mpsc::Sender<Command>>,
}

enum Command {
    /// Replace what we advertise; `None` withdraws it.
    Advertise(Option<Advert>),
    /// Include peer-to-peer interfaces (AWDL) from now on, or stop.
    PeerToPeer(bool),
}

impl Backend {
    /// Starts with peer-to-peer off; [`Book::attach`] sends the book's mode.
    pub(crate) fn spawn(book: Arc<Book>) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("mshr-lan-dnssd".into())
            .spawn(move || run(book, rx))?;
        Ok(Self { tx: Mutex::new(tx) })
    }

    /// Replace what we advertise; `None` withdraws it.
    pub(crate) fn advertise(&self, advert: Option<Advert>) {
        self.send(Command::Advertise(advert));
    }

    /// See [`super::LanSightings::set_peer_to_peer`].
    pub(crate) fn set_peer_to_peer(&self, on: bool) {
        self.send(Command::PeerToPeer(on));
    }

    fn send(&self, command: Command) {
        let _ = self.tx.lock().expect("dnssd tx poisoned").send(command);
    }
}

/// Is `index` a peer-to-peer link: browse's pseudo index for one, or a real
/// AWDL / low-latency-WLAN interface (`awdl0`, `llw0`)?
fn is_peer_to_peer(index: u32) -> bool {
    if index == IF_INDEX_P2P {
        return true;
    }
    if index == 0 || index >= IF_INDEX_PSEUDO_MIN {
        return false;
    }
    let mut buf = [0 as c_char; libc::IF_NAMESIZE];
    // SAFETY: buf is IF_NAMESIZE bytes, as if_indextoname requires.
    let name = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if name.is_null() {
        return false;
    }
    // SAFETY: on success if_indextoname wrote a NUL-terminated name to buf.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    name.starts_with(b"awdl") || name.starts_with(b"llw")
}

/// Wire encoding of TXT rdata: each `key=value` string prefixed by its
/// length byte. [`Advert::new`] already dropped anything over 255 bytes.
pub(crate) fn encode_txt(pairs: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in pairs {
        let s = format!("{k}={v}");
        if let Ok(len) = u8::try_from(s.len()) {
            out.push(len);
            out.extend_from_slice(s.as_bytes());
        }
    }
    out
}

/// Inverse of [`encode_txt`]; tolerant of malformed trailing bytes and of
/// value-less keys.
pub(crate) fn decode_txt_wire(mut bytes: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    while let Some((&len, rest)) = bytes.split_first() {
        let len = len as usize;
        if rest.len() < len {
            break;
        }
        let (s, rest) = rest.split_at(len);
        bytes = rest;
        let Ok(s) = std::str::from_utf8(s) else { continue };
        let (k, v) = s.split_once('=').unwrap_or((s, ""));
        if !k.is_empty() {
            out.push((k.to_string(), v.to_string()));
        }
    }
    out
}

enum Pending {
    StartQuery(String),
    StopQuery(String),
}

#[derive(Default)]
struct Seen {
    /// Interfaces browse currently reports the instance on. Only whether it
    /// is empty matters: which addresses each interface reached is
    /// [`TxtRecords`]' business.
    interfaces: BTreeSet<u32>,
    /// The instance's TXT record query, kept open.
    query: Option<DNSServiceRef>,
    txt: TxtRecords,
}

/// Every TXT record mDNSResponder holds for one instance, as its record
/// query reports them: added and removed one record at a time, each keyed by
/// the interface it was heard on and its rdata, since a removal names
/// exactly that pair. Several can coexist on one interface (mDNS keeps every
/// member of a record set received within a second of the others).
///
/// @yah:ticket(R961-B1, "dnssd: a kept-open DNSServiceResolve files one interface's TXT under another and never reports removals, so a peer met over USB+AWDL keeps a stale record once the cable goes (noisetable R803-B20); track TXT records with DNSServiceQueryRecord")
/// @yah:status(review)
/// @yah:at(2026-10-09T00:47:34Z)
/// @yah:assignee(agent:bundle-anthropic-glimmerstone)
/// @yah:parent(R961)
/// @yah:severity(high)
/// @yah:handoff("ROOT CAUSE (found under noisetable R803-B20, courier Glimmerstone session:f1fa3113, 2026-10-08). R961's receiver used a kept-open DNSServiceResolve and kept one Record per reply interface (Seen::records, pruned by browse). A Resolve keeps ONE TXT slot and ONE SRV slot across every interface. Each reply carries the TXT added last on any interface, labelled with the interface of whichever record triggered it. A removal is never delivered: it blanks the slot, and the Resolve stays silent until both record types arrive again. Read from mDNSResponder uds_daemon.c (main), resolve_result_save_answer / resolve_result_callback. Measured on this Mac in /tmp/b20-s1-monitor.log, from /tmp/b20-scripts/monitor.py, which runs Resolve and QueryRecord side by side. Two RESOLVE replies were labelled en9, yet one carried the stale TXT that the TXT query placed on en0. At the cable pull, the en8/en9 removals produced no Resolve reply at all.")
/// @yah:handoff("FIX (oss/mshr/crates/mshr/src/lan/dnssd.rs). Each browsed instance gets a kept-open DNSServiceQueryRecord(TXT) on the shared connection; the full name comes from DNSServiceConstructFullName. The new TxtRecords holds exactly the TXT records mDNSResponder reports, keyed by (interface, rdata), each record's link-local addresses re-scoped to its own interface. Removals apply; relay, user data and scope come from the latest record; the Book gets the union. Browse now only decides whether the instance exists, so Seen::prune and the P2P-index reconciliation are gone. is_peer_to_peer stays for leave_peer_to_peer. Module doc rewritten. CHANGELOG [Unreleased] has a Fixed entry. The temporary b20_trace hooks were removed after the hardware run.")
/// @yah:handoff("HARDWARE (noisetable R803-B20 run, Mac + iPad, iPad Wi-Fi off from Control Center, Bluetooth off; app launched and desk booted with the cable IN, then the cable pulled). Before the pull, the iPad's record of the desk was scoped %13 (awdl0), %4 and %6 (USB). After it, three queries over a minute read [v4s, fe80::f4cd:c0ff:fe7f:f1d%13] (the desk's awdl0 address). Étude 655 passed (Verdict 0), and every iroh path::selected to the iPad was Mac awdl0 fe80 -> iPad awdl0 fe80%16. The iPad-side trace, /tmp/b20-s1-ipad.trace, shows the desk's registration-time TXT (IPv4 only) arriving on awdl0 twice, once per desk process, and coexisting with the full TXT for 2-6 s until mDNS flushed it. Under the Resolve model, one reply filing it under awdl0, followed by any removal that silenced the Resolve, gives exactly R803-B20 run 3's frozen IPv4-only record.")
/// @yah:handoff("OBSERVATION, not acted on (the decision is this camp's). Over AWDL a fresh P2P query on macOS swapped the iOS mshr advertiser's current TXT for its registration-time TXT: TXT RMV current, then ADD a 1-entry TXT on awdl0. Seen twice, on two app launches. mshr registers iroh's first publish, which can lack the link-local addresses noisetable adds a moment later, so a receiver handed only that TXT on awdl0 would again lack the awdl0 address. Python and desk advertisers on macOS never showed it toward the iPad in 7 variants. Not needed for R803-B20's acceptance; an advertiser-side settle before the first register would remove the exposure.")
/// @yah:verify("cd oss/mshr && cargo test -p mshr --lib lan:: -- --include-ignored --test-threads=1 -> 25 passed (R961 baseline 22, +3 new: txt_records_follow_each_interface_through_a_cable_pull, txt_records_remove_exactly_what_was_named, txt_records_carry_the_latest_records_metadata)")
/// @yah:verify("cd oss/mshr && cargo test -p mshr -> lib 70 passed / 8 ignored, other binaries 2+3+1 (76 total; R961 baseline 73)")
/// @yah:verify("cd oss/mshr && cargo clippy -p mshr --all-targets -> clean; cargo check -p mshr --target aarch64-apple-ios -> clean")
#[derive(Debug, Default)]
pub(super) struct TxtRecords {
    /// Decoded, link-local addresses re-scoped to the key's interface.
    held: BTreeMap<(u32, Vec<u8>), Record>,
    /// The key added most recently, whose relay, user data and scope the
    /// merged record carries.
    latest: Option<(u32, Vec<u8>)>,
}

impl TxtRecords {
    /// mDNSResponder added `rdata` as a TXT record heard on `interface`.
    /// Returns whether what [`Self::merged`] gives may have changed. A TXT
    /// without a usable address (a stranger on our service type, a peer
    /// mid-update) is not held.
    pub(super) fn add(&mut self, interface: u32, rdata: &[u8]) -> bool {
        let pairs = decode_txt_wire(rdata);
        let Some(record) = decode_txt(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str()))) else {
            return false;
        };
        // A pseudo index (LocalOnly: a peer on this same host) names no link,
        // and on this host the advertiser's own scope ids are already the
        // right ones.
        let record = if interface == 0 || interface >= IF_INDEX_PSEUDO_MIN {
            record
        } else {
            record.heard_on(interface)
        };
        let key = (interface, rdata.to_vec());
        self.held.insert(key.clone(), record);
        self.latest = Some(key);
        true
    }

    /// mDNSResponder removed the TXT record `rdata` heard on `interface`
    /// (a goodbye, an expiry, a newer record set flushing it, or the
    /// interface going away).
    pub(super) fn remove(&mut self, interface: u32, rdata: &[u8]) -> bool {
        let key = (interface, rdata.to_vec());
        if self.held.remove(&key).is_none() {
            return false;
        }
        if self.latest.as_ref() == Some(&key) {
            self.latest = None;
        }
        true
    }

    /// Drop every record heard on an interface `keep` rejects.
    pub(super) fn retain_interfaces(&mut self, keep: impl Fn(u32) -> bool) {
        self.held.retain(|(interface, _), _| keep(*interface));
        if self.latest.as_ref().is_some_and(|(interface, _)| !keep(*interface)) {
            self.latest = None;
        }
    }

    /// What the Book should hold: every record's addresses, unioned. `None`
    /// while no record is held.
    pub(super) fn merged(&self) -> Option<Record> {
        let latest = self
            .latest
            .as_ref()
            .and_then(|key| self.held.get(key))
            .or_else(|| self.held.values().next_back())?;
        Some(Record::merge(latest, self.held.values()))
    }
}

/// Thread-owned state; callbacks reach it through the context pointer.
struct State {
    book: Arc<Book>,
    conn: DNSServiceRef,
    registered: Option<(DNSServiceRef, Advert)>,
    want: Option<Advert>,
    seen: HashMap<String, Seen>,
    pending: Vec<Pending>,
    /// Include peer-to-peer interfaces in every call.
    peer_to_peer: bool,
}

impl State {
    /// `ShareConnection`, plus the peer-to-peer inclusions when on.
    fn flags(&self) -> DNSServiceFlags {
        let p2p = if self.peer_to_peer {
            FLAGS_INCLUDE_P2P | FLAGS_INCLUDE_AWDL
        } else {
            0
        };
        FLAGS_SHARE_CONNECTION | p2p
    }

    /// Put `name`'s merged record in the Book, or drop the peer if no
    /// interface still reaches it.
    fn report(&self, name: &str) {
        let Some(id) = parse_instance(name) else { return };
        match self.seen.get(name).map(|seen| seen.txt.merged()) {
            Some(Some(record)) => self.book.found(id, record),
            // Browse sees it but no TXT record is held: none has arrived yet,
            // or one record set was removed and its successor is still to come.
            Some(None) => {}
            None => self.book.lost(id),
        }
    }

    /// Peer-to-peer was switched off: drop what only it reached, before the
    /// reconnect forgets which interface reached what.
    fn leave_peer_to_peer(&mut self) {
        let names: Vec<String> = self.seen.keys().cloned().collect();
        for name in names {
            let Some(seen) = self.seen.get_mut(&name) else { continue };
            seen.interfaces.retain(|i| !is_peer_to_peer(*i));
            seen.txt.retain_interfaces(|i| !is_peer_to_peer(i));
            if seen.interfaces.is_empty() {
                self.seen.remove(&name);
            }
            self.report(&name);
        }
    }
}

fn run(book: Arc<Book>, rx: mpsc::Receiver<Command>) {
    let state = Box::into_raw(Box::new(State {
        book,
        conn: ptr::null_mut(),
        registered: None,
        want: None,
        seen: HashMap::new(),
        pending: Vec::new(),
        peer_to_peer: false,
    }));
    let ctx = state.cast::<c_void>();
    let mut retry_at = Instant::now();
    loop {
        // SAFETY: `state` is owned by this thread until the `Box::from_raw`
        // below. Callbacks derive their own `&mut` from `ctx` while
        // `DNSServiceProcessResult` runs, so this borrow is re-derived each
        // iteration and never held across that call.
        let st = unsafe { &mut *state };
        let mut changed = false;
        loop {
            match rx.try_recv() {
                Ok(Command::Advertise(advert)) => {
                    changed |= st.want != advert;
                    st.want = advert;
                }
                Ok(Command::PeerToPeer(on)) if on != st.peer_to_peer => {
                    if !on {
                        st.leave_peer_to_peer();
                    }
                    st.peer_to_peer = on;
                    // Every ref carries its flags from creation: rebuild them
                    // all, now. Re-registering is what peers see as a goodbye.
                    teardown(st);
                    retry_at = Instant::now();
                }
                Ok(Command::PeerToPeer(_)) => {}
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    teardown(st);
                    // SAFETY: allocated by Box::into_raw above; no callback
                    // can fire after teardown deallocated the connection.
                    drop(unsafe { Box::from_raw(state) });
                    return;
                }
            }
        }

        if st.conn.is_null() {
            if Instant::now() < retry_at {
                thread::sleep(Duration::from_millis(TICK_MS as u64));
                continue;
            }
            if let Err(err) = connect(st, ctx) {
                warn!(err, "lan: dns_sd connect failed; retrying");
                teardown(st);
                retry_at = Instant::now() + RECONNECT_AFTER;
                continue;
            }
            changed = true;
        }
        if changed {
            apply_registration(st, ctx);
        }

        let mut pfd = libc::pollfd {
            fd: unsafe { DNSServiceRefSockFD(st.conn) },
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let ready = unsafe { libc::poll(&mut pfd, 1, TICK_MS) };
        if ready > 0 {
            let conn = st.conn;
            // SAFETY: conn is a live main ref; callbacks get `ctx`.
            let err = unsafe { DNSServiceProcessResult(conn) };
            // SAFETY: re-derived after the callbacks' borrows ended.
            let st = unsafe { &mut *state };
            if err != ERR_NO_ERROR {
                warn!(err, "lan: mDNSResponder connection lost; reconnecting");
                teardown(st);
                retry_at = Instant::now() + RECONNECT_AFTER;
                continue;
            }
            apply_pending(st, ctx);
        }
    }
}

fn connect(st: &mut State, ctx: *mut c_void) -> Result<(), DNSServiceErrorType> {
    // SAFETY: out-pointer to a local.
    let err = unsafe { DNSServiceCreateConnection(&mut st.conn) };
    if err != ERR_NO_ERROR {
        st.conn = ptr::null_mut();
        return Err(err);
    }
    let regtype = CString::new(SERVICE_TYPE).expect("static");
    let mut browse = st.conn;
    // SAFETY: browse starts as the main ref, as ShareConnection requires.
    let err = unsafe {
        DNSServiceBrowse(
            &mut browse,
            st.flags(),
            0,
            regtype.as_ptr(),
            ptr::null(),
            on_browse,
            ctx,
        )
    };
    if err != ERR_NO_ERROR {
        if err == ERR_POLICY_DENIED {
            warn!("lan: Bonjour browse denied — add `{SERVICE_TYPE}` to NSBonjourServices and set NSLocalNetworkUsageDescription in Info.plist");
        }
        return Err(err);
    }
    // The browse ref dies with the main connection; nothing else to keep.
    Ok(())
}

/// Deallocating the main ref implicitly deallocates every subordinate ref
/// (dns_sd.h, ShareConnection), so only the pointers need clearing. The
/// Book is left alone: a reconnect re-browses and refreshes it.
fn teardown(st: &mut State) {
    if !st.conn.is_null() {
        // SAFETY: live main ref, deallocated exactly once.
        unsafe { DNSServiceRefDeallocate(st.conn) };
        st.conn = ptr::null_mut();
    }
    st.registered = None;
    st.seen.clear();
    st.pending.clear();
}

fn apply_registration(st: &mut State, ctx: *mut c_void) {
    let Some(want) = st.want.clone() else {
        if let Some((reg, _)) = st.registered.take() {
            // SAFETY: live subordinate ref.
            unsafe { DNSServiceRefDeallocate(reg) };
        }
        return;
    };
    let txt = encode_txt(&want.txt);
    let Ok(txt_len) = u16::try_from(txt.len()) else {
        warn!(len = txt.len(), "lan: TXT record too large; not advertising");
        return;
    };
    if let Some((reg, cur)) = &st.registered {
        if cur == &want {
            return;
        }
        if cur.instance == want.instance && cur.port == want.port {
            // SAFETY: live registration ref; NULL record = its TXT record.
            let err = unsafe {
                DNSServiceUpdateRecord(*reg, ptr::null_mut(), 0, txt_len, txt.as_ptr().cast(), 0)
            };
            if err == ERR_NO_ERROR {
                st.registered = Some((*reg, want));
                return;
            }
            warn!(err, "lan: TXT update failed; re-registering");
        }
    }
    if let Some((reg, _)) = st.registered.take() {
        // SAFETY: live subordinate ref.
        unsafe { DNSServiceRefDeallocate(reg) };
    }
    let (Ok(name), Ok(regtype)) = (CString::new(want.instance.clone()), CString::new(SERVICE_TYPE))
    else {
        return;
    };
    let mut reg = st.conn;
    // SAFETY: reg starts as the main ref (ShareConnection); strings and TXT
    // outlive the call, which copies them.
    let err = unsafe {
        DNSServiceRegister(
            &mut reg,
            st.flags() | FLAGS_NO_AUTO_RENAME,
            0,
            name.as_ptr(),
            regtype.as_ptr(),
            ptr::null(),
            ptr::null(),
            want.port.to_be(),
            txt_len,
            txt.as_ptr().cast(),
            on_register,
            ctx,
        )
    };
    if err == ERR_NO_ERROR {
        debug!(instance = %want.instance, port = want.port, "lan: registered");
        st.registered = Some((reg, want));
    } else {
        warn!(err, "lan: DNSServiceRegister failed");
    }
}

fn apply_pending(st: &mut State, ctx: *mut c_void) {
    let flags = st.flags();
    for p in std::mem::take(&mut st.pending) {
        match p {
            Pending::StartQuery(name) => {
                let Some(seen) = st.seen.get_mut(&name) else { continue };
                if seen.query.is_some() {
                    continue;
                }
                let (Ok(cname), Ok(regtype), Ok(domain)) = (
                    CString::new(name.clone()),
                    CString::new(SERVICE_TYPE),
                    CString::new("local."),
                ) else {
                    continue;
                };
                let mut fullname = [0 as c_char; MAX_DOMAIN_NAME];
                // SAFETY: fullname is kDNSServiceMaxDomainName bytes, as the
                // call requires; the inputs are NUL-terminated.
                let err = unsafe {
                    DNSServiceConstructFullName(
                        fullname.as_mut_ptr(),
                        cname.as_ptr(),
                        regtype.as_ptr(),
                        domain.as_ptr(),
                    )
                };
                if err != ERR_NO_ERROR {
                    warn!(err, %name, "lan: DNSServiceConstructFullName failed");
                    continue;
                }
                let mut r = st.conn;
                // SAFETY: r starts as the main ref (ShareConnection); fullname
                // is NUL-terminated by the call above.
                let err = unsafe {
                    DNSServiceQueryRecord(
                        &mut r,
                        flags,
                        0,
                        fullname.as_ptr(),
                        TYPE_TXT,
                        CLASS_IN,
                        on_txt,
                        ctx,
                    )
                };
                if err == ERR_NO_ERROR {
                    seen.query = Some(r);
                } else {
                    warn!(err, %name, "lan: DNSServiceQueryRecord failed");
                }
            }
            Pending::StopQuery(name) => {
                if let Some(seen) = st.seen.remove(&name) {
                    if let Some(r) = seen.query {
                        // SAFETY: live subordinate ref.
                        unsafe { DNSServiceRefDeallocate(r) };
                    }
                }
                if let Some(id) = parse_instance(&name) {
                    st.book.lost(id);
                }
            }
        }
    }
}

/// # Safety
/// `ctx` is the `State` pointer handed to the API by [`run`]; callbacks
/// only fire inside `DNSServiceProcessResult` on that thread.
unsafe fn state<'a>(ctx: *mut c_void) -> &'a mut State {
    &mut *ctx.cast::<State>()
}

unsafe fn cstr(p: *const c_char) -> Option<String> {
    (!p.is_null()).then(|| CStr::from_ptr(p).to_string_lossy().into_owned())
}

extern "C" fn on_register(
    _sd: DNSServiceRef,
    _flags: DNSServiceFlags,
    err: DNSServiceErrorType,
    name: *const c_char,
    _regtype: *const c_char,
    _domain: *const c_char,
    _ctx: *mut c_void,
) {
    // SAFETY: mDNSResponder-supplied C string or NULL.
    let name = unsafe { cstr(name) };
    match err {
        ERR_NO_ERROR => debug!(?name, "lan: registration confirmed"),
        ERR_POLICY_DENIED => warn!("lan: Bonjour registration denied — add `{SERVICE_TYPE}` to NSBonjourServices and set NSLocalNetworkUsageDescription in Info.plist"),
        ERR_NAME_CONFLICT => warn!(?name, "lan: another responder already advertises this endpoint id"),
        err => warn!(err, ?name, "lan: registration error"),
    }
}

extern "C" fn on_browse(
    _sd: DNSServiceRef,
    flags: DNSServiceFlags,
    interface: u32,
    err: DNSServiceErrorType,
    name: *const c_char,
    _regtype: *const c_char,
    _domain: *const c_char,
    ctx: *mut c_void,
) {
    // SAFETY: see `state`.
    let st = unsafe { state(ctx) };
    if err != ERR_NO_ERROR {
        if err == ERR_POLICY_DENIED {
            warn!("lan: Bonjour browse denied — add `{SERVICE_TYPE}` to NSBonjourServices and set NSLocalNetworkUsageDescription in Info.plist");
        } else {
            warn!(err, "lan: browse error");
        }
        return;
    }
    // SAFETY: mDNSResponder-supplied C string or NULL.
    let Some(name) = (unsafe { cstr(name) }) else { return };
    // Strangers on our service type, and our own registration echoing back.
    match parse_instance(&name) {
        Some(id) if !st.book.is_own(&id) => {}
        _ => return,
    }
    if flags & FLAGS_ADD != 0 {
        let seen = st.seen.entry(name.clone()).or_default();
        seen.interfaces.insert(interface);
        if seen.query.is_none() {
            st.pending.push(Pending::StartQuery(name));
        }
    } else if let Some(seen) = st.seen.get_mut(&name) {
        seen.interfaces.remove(&interface);
        // Still reachable elsewhere, nothing to do here: the TXT query
        // reports the removal of whatever this interface held.
        if seen.interfaces.is_empty() {
            st.pending.push(Pending::StopQuery(name));
        }
    }
}

extern "C" fn on_txt(
    sd: DNSServiceRef,
    flags: DNSServiceFlags,
    interface: u32,
    err: DNSServiceErrorType,
    _fullname: *const c_char,
    rrtype: u16,
    _rrclass: u16,
    rdlen: u16,
    rdata: *const u8,
    _ttl: u32,
    ctx: *mut c_void,
) {
    if err != ERR_NO_ERROR {
        warn!(err, "lan: TXT query error");
        return;
    }
    if rrtype != TYPE_TXT {
        return;
    }
    // SAFETY: see `state`.
    let st = unsafe { state(ctx) };
    // The browse name this query was started for (`fullname` is escaped and
    // domain-qualified, so match by ref instead).
    let Some(name) = st
        .seen
        .iter()
        .find_map(|(name, seen)| (seen.query == Some(sd)).then(|| name.clone()))
    else {
        return;
    };
    let bytes = if rdata.is_null() {
        &[][..]
    } else {
        // SAFETY: mDNSResponder guarantees rdlen readable bytes.
        unsafe { std::slice::from_raw_parts(rdata, rdlen as usize) }
    };
    let seen = st.seen.get_mut(&name).expect("found above");
    let changed = if flags & FLAGS_ADD != 0 {
        seen.txt.add(interface, bytes)
    } else {
        seen.txt.remove(interface, bytes)
    };
    if changed {
        st.report(&name);
    }
}

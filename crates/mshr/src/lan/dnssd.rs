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
//! Flow: Browse `_mshr._udp` → per new instance, Resolve (kept open so TXT
//! changes stream in) → decode TXT into the [`Book`]. Browse removal on the
//! instance's last interface stops the Resolve and drops the peer.
//!
//! Peer-to-peer links (AWDL) are excluded from `kDNSServiceInterfaceIndexAny`
//! unless a call sets `kDNSServiceFlagsIncludeP2P`, and AWDL specifically
//! also `kDNSServiceFlagsIncludeAWDL` (dns_sd.h). Every call sets both or
//! neither, per [`super::LanSightings::set_peer_to_peer`]; a switch tears the
//! connection down and rebuilds it under the new flags.
//!
//! A Resolve answers once per interface it hears the peer on, and each answer
//! is kept separately ([`Seen::records`]), its link-local addresses re-scoped
//! to that interface ([`super::Record::heard_on`]); the Book gets their
//! union. Browse reports anything found over a peer-to-peer link under the
//! pseudo index `kDNSServiceInterfaceIndexP2P`, while the Resolve reports
//! the real `awdl0` index, so the two are reconciled by interface kind
//! ([`is_peer_to_peer`]) rather than by index.
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
type ResolveReply = extern "C" fn(
    DNSServiceRef,
    DNSServiceFlags,
    u32,
    DNSServiceErrorType,
    *const c_char,
    *const c_char,
    u16,
    u16,
    *const u8,
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
    fn DNSServiceResolve(
        sd_ref: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        callback: ResolveReply,
        context: *mut c_void,
    ) -> DNSServiceErrorType;
}

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
    StartResolve(String),
    StopResolve(String),
}

#[derive(Default)]
struct Seen {
    /// Interfaces browse currently reports the instance on: real indices,
    /// plus [`IF_INDEX_P2P`] for anything found over a peer-to-peer link.
    interfaces: BTreeSet<u32>,
    resolve: Option<DNSServiceRef>,
    /// The record as resolved on each interface (the Resolve's index, always
    /// a real one), its link-local addresses scoped to that interface.
    records: BTreeMap<u32, Record>,
    /// Interface of the most recent Resolve answer, whose relay, user data
    /// and scope the merged record carries.
    latest: u32,
}

impl Seen {
    /// Forget answers from interfaces browse no longer reports. Browse names
    /// a peer-to-peer link only by [`IF_INDEX_P2P`], so while that is live
    /// every peer-to-peer answer stays.
    fn prune(&mut self) {
        let p2p = self.interfaces.contains(&IF_INDEX_P2P);
        let interfaces = &self.interfaces;
        self.records
            .retain(|i, _| interfaces.contains(i) || (p2p && is_peer_to_peer(*i)));
    }

    /// What the Book should hold: every interface's answer, unioned.
    fn merged(&self) -> Option<Record> {
        let latest = self.records.get(&self.latest).or_else(|| self.records.values().next())?;
        Some(Record::merge(latest, self.records.values()))
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
        match self.seen.get(name).map(Seen::merged) {
            Some(Some(record)) => self.book.found(id, record),
            Some(None) => {} // Browse sees it; no Resolve answer yet.
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
            seen.prune();
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
            Pending::StartResolve(name) => {
                let Some(seen) = st.seen.get_mut(&name) else { continue };
                if seen.resolve.is_some() {
                    continue;
                }
                let (Ok(cname), Ok(regtype), Ok(domain)) = (
                    CString::new(name.clone()),
                    CString::new(SERVICE_TYPE),
                    CString::new("local."),
                ) else {
                    continue;
                };
                let mut r = st.conn;
                // SAFETY: r starts as the main ref (ShareConnection).
                let err = unsafe {
                    DNSServiceResolve(
                        &mut r,
                        flags,
                        0,
                        cname.as_ptr(),
                        regtype.as_ptr(),
                        domain.as_ptr(),
                        on_resolve,
                        ctx,
                    )
                };
                if err == ERR_NO_ERROR {
                    seen.resolve = Some(r);
                } else {
                    warn!(err, %name, "lan: DNSServiceResolve failed");
                }
            }
            Pending::StopResolve(name) => {
                if let Some(seen) = st.seen.remove(&name) {
                    if let Some(r) = seen.resolve {
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
        if seen.resolve.is_none() {
            st.pending.push(Pending::StartResolve(name));
        }
    } else if let Some(seen) = st.seen.get_mut(&name) {
        seen.interfaces.remove(&interface);
        if seen.interfaces.is_empty() {
            st.pending.push(Pending::StopResolve(name));
        } else {
            // Still reachable elsewhere: drop only what this interface heard.
            seen.prune();
            st.report(&name);
        }
    }
}

extern "C" fn on_resolve(
    sd: DNSServiceRef,
    _flags: DNSServiceFlags,
    interface: u32,
    err: DNSServiceErrorType,
    fullname: *const c_char,
    _host: *const c_char,
    _port_be: u16,
    txt_len: u16,
    txt: *const u8,
    ctx: *mut c_void,
) {
    if err != ERR_NO_ERROR {
        warn!(err, "lan: resolve error");
        return;
    }
    // SAFETY: see `state`.
    let st = unsafe { state(ctx) };
    // SAFETY: mDNSResponder-supplied C string or NULL.
    let Some(fullname) = (unsafe { cstr(fullname) }) else { return };
    if parse_instance(&fullname).is_none() {
        return;
    }
    // The browse name this Resolve was started for (`fullname` is escaped
    // and domain-qualified, so match by ref instead).
    let Some(name) = st
        .seen
        .iter()
        .find_map(|(name, seen)| (seen.resolve == Some(sd)).then(|| name.clone()))
    else {
        return;
    };
    let bytes = if txt.is_null() {
        &[][..]
    } else {
        // SAFETY: mDNSResponder guarantees txt_len readable bytes.
        unsafe { std::slice::from_raw_parts(txt, txt_len as usize) }
    };
    let pairs = decode_txt_wire(bytes);
    let Some(record) = decode_txt(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str()))) else {
        return;
    };
    // A pseudo index (LocalOnly: a peer on this same host) names no link, and
    // on this host the advertiser's own scope ids are already the right ones.
    let record = if interface == 0 || interface >= IF_INDEX_PSEUDO_MIN {
        record
    } else {
        record.heard_on(interface)
    };
    let seen = st.seen.get_mut(&name).expect("found above");
    seen.records.insert(interface, record);
    seen.latest = interface;
    st.report(&name);
}

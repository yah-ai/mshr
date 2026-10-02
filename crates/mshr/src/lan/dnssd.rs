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

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use super::{decode_txt, parse_instance, Advert, Book, SERVICE_TYPE};

type DNSServiceRef = *mut c_void;
type DNSServiceFlags = u32;
type DNSServiceErrorType = i32;

const FLAGS_ADD: DNSServiceFlags = 0x2;
const FLAGS_NO_AUTO_RENAME: DNSServiceFlags = 0x8;
const FLAGS_SHARE_CONNECTION: DNSServiceFlags = 0x4000;

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
    tx: Mutex<mpsc::Sender<Option<Advert>>>,
}

impl Backend {
    pub(crate) fn spawn(book: Arc<Book>) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("mshr-lan-dnssd".into())
            .spawn(move || run(book, rx))?;
        Ok(Self { tx: Mutex::new(tx) })
    }

    /// Replace what we advertise; `None` withdraws it.
    pub(crate) fn advertise(&self, advert: Option<Advert>) {
        let _ = self.tx.lock().expect("dnssd tx poisoned").send(advert);
    }
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
    /// Interfaces browse currently reports the instance on.
    interfaces: u32,
    resolve: Option<DNSServiceRef>,
}

/// Thread-owned state; callbacks reach it through the context pointer.
struct State {
    book: Arc<Book>,
    conn: DNSServiceRef,
    registered: Option<(DNSServiceRef, Advert)>,
    want: Option<Advert>,
    seen: HashMap<String, Seen>,
    pending: Vec<Pending>,
}

fn run(book: Arc<Book>, rx: mpsc::Receiver<Option<Advert>>) {
    let state = Box::into_raw(Box::new(State {
        book,
        conn: ptr::null_mut(),
        registered: None,
        want: None,
        seen: HashMap::new(),
        pending: Vec::new(),
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
                Ok(advert) => {
                    changed |= st.want != advert;
                    st.want = advert;
                }
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
            FLAGS_SHARE_CONNECTION,
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
            FLAGS_SHARE_CONNECTION | FLAGS_NO_AUTO_RENAME,
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
                        FLAGS_SHARE_CONNECTION,
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
    _interface: u32,
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
        seen.interfaces += 1;
        if seen.interfaces == 1 {
            st.pending.push(Pending::StartResolve(name));
        }
    } else if let Some(seen) = st.seen.get_mut(&name) {
        seen.interfaces = seen.interfaces.saturating_sub(1);
        if seen.interfaces == 0 {
            st.pending.push(Pending::StopResolve(name));
        }
    }
}

extern "C" fn on_resolve(
    _sd: DNSServiceRef,
    _flags: DNSServiceFlags,
    _interface: u32,
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
    let Some(id) = parse_instance(&fullname) else { return };
    let bytes = if txt.is_null() {
        &[][..]
    } else {
        // SAFETY: mDNSResponder guarantees txt_len readable bytes.
        unsafe { std::slice::from_raw_parts(txt, txt_len as usize) }
    };
    let pairs = decode_txt_wire(bytes);
    if let Some(record) = decode_txt(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str()))) {
        st.book.found(id, record);
    }
}

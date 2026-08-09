//! @arch:layer(core)
//! @arch:role(net)
//!
//! `mshr` — shared iroh-based transport substrate for the yah/xlb crate
//! family. Wraps `iroh` so consumers (`xlb`, `yubaba`, noisetable's
//! `society`) import `mshr::Endpoint` rather than `iroh::Endpoint`,
//! giving us a single upgrade point for the pre-1.0 substrate and a
//! transparent fork escape hatch.
//!
//! Phase 1 (R105-F1) ships:
//! - [`Keypair`]: per-machine Ed25519 secret loaded from
//!   `<data-local>/yah/identity.ed25519`.
//! - [`Endpoint`]: thin wrapper around `iroh::Endpoint`, built via
//!   [`EndpointBuilder`] with a configured keypair + ALPN list, exposing a
//!   simple [`Endpoint::accept`] loop that dispatches incoming connections
//!   by ALPN to a caller-supplied async handler.
//! - Re-exports of `iroh::NodeId` and `iroh::SecretKey` for ergonomics.
//!
//! Discovery aggregation (mDNS / swarm / static / external roster) and the
//! embeddable `relay::Server` land in subsequent sub-tickets (R105-F2..F4).

pub mod discovery;
pub mod endpoint;
pub mod keypair;
pub mod relay;
pub mod seeds;

pub use discovery::{default_relays, Discovery, PeerHint, PeerHintStream, PeerSource};
pub use endpoint::{
    AcceptDecision, Acceptor, Endpoint, EndpointBuilder, ACCEPTOR_DENY_ERROR_CODE,
    ACCEPTOR_DENY_REASON,
};
pub use seeds::{RelayChoice, Seed, Seeds};
// `ApplicationClose`/`ConnectionError` complete the accept-path surface: mshr
// itself closes connections with an application error code
// (`ACCEPTOR_DENY_ERROR_CODE`) and consumers do the same for their own
// protocol-level refusals, so a consumer that cannot name `ConnectionError`
// cannot tell its own close code from a deny, a timeout or a reset. Without
// this the only way to read a close is a direct `iroh` dependency, which is
// exactly what this crate exists to make unnecessary.
//
// The datagram half (R609-F6) is here for the same reason and it is the whole
// of the ask: `Connection` already carries `send_datagram` / `read_datagram` /
// `max_datagram_size`, but their argument, their error and their futures were
// all unnameable from mshr, so the only way to *call* them was the `iroh`
// dependency this crate exists to remove. `Bytes` is re-exported rather than
// left to the caller for the same reason — `send_datagram` takes one, and a
// consumer picking its own `bytes` version would be a silent type mismatch.
pub use bytes::Bytes;
pub use iroh::endpoint::{
    ApplicationClose, Connection, ConnectionError, Incoming, ReadDatagram, RecvStream,
    SendDatagram, SendDatagramError, SendStream,
};
pub use keypair::Keypair;

// Re-export iroh's `RelayMap`/`RelayMode` so consumers can build custom
// relay configurations without taking a direct iroh dep. `RelayUrl` for
// constructing `RelayMap` from a known URL.
pub use iroh::{RelayMap, RelayMode, RelayUrl};

// iroh 1.0 renamed `NodeId`/`NodeAddr` to `EndpointId`/`EndpointAddr`. The
// xlb-net arch doc still speaks of `NodeId` (and society/yubaba's design
// notes do too), so we expose both spellings as aliases. New code should
// prefer `NodeId`/`NodeAddr` for cross-consumer consistency; either is fine
// inside the crate boundary.
pub use iroh::{EndpointAddr, EndpointId, SecretKey};
pub type NodeId = EndpointId;
pub type NodeAddr = EndpointAddr;

/// `Result` alias for fallible `mshr` operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error for the crate. Most public APIs return [`Result`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("identity dir unavailable: no platform data-local dir")]
    NoDataDir,

    #[error("malformed keypair file: {0}")]
    Keypair(String),

    #[error("endpoint: {0}")]
    Endpoint(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

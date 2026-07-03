# Changelog

## [0.8.18] - 2026-07-02

First public release on crates.io. Promoted out of `xlb-net` into its own
crate + workspace; versioned in lockstep with the yah release train.

### Added

- `Keypair` — per-machine Ed25519 identity; `load_or_create()` reads or atomically creates a key at the platform data dir; persists `identity.pub` alongside for inspection
- `Endpoint` — ALPN-multiplexed QUIC endpoint wrapping `iroh::Endpoint`; builder API with `discovery()` and `bind()`; `node_id()`, `connect_alpn()`, `accept_dispatch()`
- `Discovery` — composed peer discovery: `with_lan()` (mDNS), `with_relays()` (iroh-relay swarm), `with_static()` (pinned NodeIds), `with_external_roster()` (custom `PeerSource`)
- `PeerSource` trait — implement to feed peer hints from any membership protocol into mshr's discovery pool
- `relay::Server` — embeddable iroh relay; builder with `https_bind()`, `quic_bind()`, `tls_self_signed()`, `tls_letsencrypt()`, `tls_manual()`
- Re-exports: `NodeId`, `NodeAddr`, `SecretKey`, `RelayMap`, `RelayMode`, `RelayUrl`
- `default_relays()` — returns the public iroh relay set

# Changelog

## [Unreleased]

### Added — LAN discovery scopes (`LanScope`)

- `LanScope` partitions one LAN into private discovery groups: the LAN lane
  advertises a `scope` TXT key and keeps only sightings whose scope matches
  its own exactly (unscoped endpoints are the public group). A peer outside
  the scope never enters the lane's book, so neither `LanSightings` nor
  iroh's resolve sees it; a peer that re-announces under another scope is
  reported `Lost`. Noise control, not access control — the scope is
  cleartext multicast. The scope lives on the `LanSightings` handle:
  `LanSightings::set_scope` before the endpoint is built sets the scope it
  starts in, and afterwards changes it live — the lane re-advertises and
  re-filters everything already heard (a `Lost` for each peer left behind,
  a `Found` for each one already in the new scope) with no rebind and no
  connection touched. Validated at construction (non-empty, <= 64 bytes, no
  control characters) so a scope can never be silently dropped from the
  TXT record.
- Internal: `decode_txt` returns a `Record { data, scope }`; the book keeps
  every record it hears (any scope) and advertises through a weak handle on
  the backend so a scope change can re-advertise.

### Changed — `Endpoint::close` is bounded and releases its sockets

- `Endpoint::close()` now returns a `CloseOutcome` and forces the endpoint
  down if it has not drained within `DEFAULT_CLOSE_DEADLINE` (5 s);
  `Endpoint::close_within(Duration)` takes the deadline explicitly. It used to
  wait as long as noq did, and noq 1.0.0-rc.0 gives a server connection whose
  first packet was the dialer's handshake-time CONNECTION_CLOSE no drain
  timer, so the close waited out the whole 30 s idle timeout with the UDP
  sockets held, and nothing a caller did could release them sooner
  (R945-B1).
- Each endpoint now runs its iroh/noq tasks on its own single-worker tokio
  runtime (thread `mshr-endpoint`). That is what lets a forced close drop
  the drivers holding the sockets. Connections created through
  `Endpoint::inner()` or by awaiting a raw `Endpoint::accept()` `Incoming`
  still spawn their driver on the caller's runtime, out of the forced
  close's reach.

### Added — `EndpointBuilder::segmentation_offload`

- `EndpointBuilder::segmentation_offload(bool)` turns UDP GSO off for every
  connection on the endpoint (iroh `QuicTransportConfig::enable_segmentation_offload`).
  For hosts whose NIC rejects GSO: iroh 1.0.0-rc.0 caches the socket's segment
  limit when the endpoint is created, so noq-udp's EIO fallback never reaches the
  connection, and every multi-datagram flight is dropped for the endpoint's
  lifetime. Measured on the Android emulator (noisetable R743-F27).

### Added — `EndpointBuilder::bind_addr` and `TransportAddr` re-export

- `EndpointBuilder::bind_addr(addr, prefix_len)` binds the endpoint to one
  named socket instead of iroh's wildcard defaults, pinning it to one local
  interface. The prefix feeds iroh's source-socket routing table, so it picks a
  socket by subnet, not by interface. Pinning applies per endpoint, not per
  connection. An invalid prefix, or a second address of the same family, is
  reported by `bind()` (noisetable R743-F26).
- `mshr::TransportAddr` (re-exported from iroh) lets a consumer name the
  address a `Connection::paths()` entry runs over.

### Added — LAN sightings

- `LanSightings`: a handle, created before the endpoint, on who is
  advertising `_mshr._udp`. `Discovery::with_lan_sightings(handle)` enables
  the LAN lane and reports into it; `handle.peers()` lists current peers and
  `handle.subscribe()` yields `LanSighting::Found(EndpointInfo)` /
  `LanSighting::Lost(EndpointId)` (current peers first, then changes; a
  lagged receiver is resynced, never silently skips a departure).
  Lower-level: `LanLookupBuilder::with_sightings`, `LanLookup::spawn_with`.
  `LanLookupBuilder` is no longer `Copy` (use `LanLookupBuilder::default()`).

### Changed — LAN lane wire (breaking on the LAN only)

- `Discovery::with_lan()` now speaks standards-conformant DNS-SD under
  service type `_mshr._udp` instead of `iroh-mdns-address-lookup`'s
  `_irohv1._udp`. Apple platforms (iOS, macOS, tvOS, visionOS) go through
  the system `dns_sd` API (mDNSResponder), so iOS no longer needs the
  Apple-gated multicast entitlement — only `NSLocalNetworkUsageDescription`
  plus `_mshr._udp` in `NSBonjourServices`. Other platforms use `mdns-sd`.
  The two backends interoperate. `swarm-discovery`, the wire under
  iroh-mdns, is not DNS-SD-conformant (no PTR, TTL 0 on every record), so
  no Bonjour stack could interoperate with it. mshr peers on older versions
  no longer find new ones over the LAN lane; the relay, static and roster
  lanes are unaffected.
- New `mshr::lan` module: `LanLookup` / `LanLookupBuilder`.
- Dropped dependency: `iroh-mdns-address-lookup`, and with it
  `swarm-discovery`, `portmapper`, `igd-next`.

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

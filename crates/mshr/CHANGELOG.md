# Changelog

## [Unreleased]

### Fixed — LAN lane on Apple keeps a stale record once one of a peer's links goes (R961-B1)

- The dns_sd backend reads a peer's TXT with a kept-open
  `DNSServiceQueryRecord` instead of `DNSServiceResolve`. A Resolve keeps one
  TXT for every interface, labels each reply with whichever interface's record
  triggered it, and never reports a removal, so a peer met over USB and AWDL
  could be left with an old TXT filed under `awdl0` once the cable was pulled,
  and with no later update ever delivered (noisetable R803-B20: an iPad held a
  desk's registration-time TXT, without its `awdl0` address, for 11+ minutes).
  The record query reports every TXT record with the interface it was heard on,
  and every removal; the sighting is the union of what is currently held.

### Changed — iroh and iroh-relay 1.0.0-rc.0 → 1.3

- No mshr API change. Internally `CaRootsConfig`/`ca_roots_config` became
  iroh 1.3's `CaTlsConfig`/`ca_tls_config`.
- noq 1.3 now drains a server connection whose first packet was the dialer's
  handshake-time CONNECTION_CLOSE (R945-B1), so that close is graceful again.
  `close_within`'s forced path stays: iroh still cannot abandon a close it
  has started, and a peer that vanishes without answering still holds a drain
  for 3×PTO. Its test now uses such a peer.

### Added — LAN lane over AWDL (`LanSightings::set_peer_to_peer`)

- `LanSightings::set_peer_to_peer(bool)` / `peer_to_peer()`: on Apple, the
  LAN lane also registers, browses and resolves over peer-to-peer links
  (`kDNSServiceFlagsIncludeP2P | kDNSServiceFlagsIncludeAWDL`), so a nearby
  Apple device with no shared Wi-Fi network is sighted over `awdl0`. Off by
  default, matching Apple's `includePeerToPeer`: while on, the Wi-Fi radio
  time-shares with the infrastructure network. Live; switching re-registers
  the advert. No effect on the `mdns-sd` backend.

### Fixed — link-local LAN addresses carried the advertiser's scope id

- A `[fe80::x%N]:p` TXT address kept the advertiser's interface index `N`,
  which on the receiver names another interface or none. Each link-local
  address is now re-scoped to the interface the record was heard on (the
  dns_sd Resolve's interface; on `mdns-sd`, the interfaces the peer's
  link-local AAAA records arrived on). A peer heard on several interfaces
  gets one address per interface.

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

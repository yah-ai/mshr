//! Seed / discovery configuration — **the one place** the defaults live.
//!
//! R609-F4 (W197 §"Open questions" 2). A freshly-bootstrapped BYO node has
//! no idea where anything is: it knows its own keypair and nothing else. To
//! become dialable *by NodeId alone* — which is the whole promise of the yah
//! control plane (A032 §"yah-aware control plane") — it needs three things
//! configured on its [`crate::Endpoint`], and this module is where all three
//! get their defaults, their override, and their precedence rule.
//!
//! ## Three lanes, three knobs — they are not interchangeable
//!
//! It is tempting to call all of this "the seed list" and give it one flag.
//! That would be wrong, because the lanes answer different questions:
//!
//! | Knob | Answers | Without it |
//! |---|---|---|
//! | [`Seeds::pkarr`] | "what addresses does NodeId X have?" | a bare NodeId is unresolvable ("No addressing information available") |
//! | [`Seeds::relays`] | "how do I reach X when punching fails?" | symmetric-NAT peers never connect |
//! | [`Seeds::pinned`] | "I already know where X is" | nothing — it is additive |
//!
//! In particular an `iroh-relay` server (what [`crate::relay::Server`] hosts)
//! does **not** serve pkarr: it is a NAT-traversal proxy plus QUIC address
//! discovery, and nothing else. Grep `iroh-relay` for "pkarr" and you get
//! nothing. So an operator hosting their own relay still resolves NodeIds
//! against *some* pkarr relay, and pointing [`Seeds::relays`] at their own
//! box while silently repointing pkarr too would be a lie about where their
//! lookups go. Hence two URL knobs rather than one.
//!
//! ## Defaults, and why they are n0's
//!
//! [`Seeds::defaults`] is n0's public infrastructure: their production relay
//! map for NAT traversal, their production pkarr relay for resolution. yah
//! hosts none of its own today — no `relay.yah.dev` exists — and shipping a
//! default that points at nothing would be worse than shipping one that
//! points at somebody. When yah's own relays deploy, the two `default_*`
//! functions below are the only edit, and every binary picks it up.
//!
//! An operator who does not want their traffic touching n0 sets each knob to
//! [`RelayChoice::Disabled`] (spelled `none` on the command line and in the
//! environment) and pins their peers with [`Seeds::pinned`], or points the
//! knobs at their own hosts. Both are first-class, both are tested.
//!
//! ## Precedence
//!
//! Explicit argument **>** environment **>** baked-in default. Each knob
//! resolves independently, so `--xlb-relay` on the command line and
//! `YAH_XLB_PKARR` in the unit file compose rather than fight.
//!
//! URL overrides **replace** the default rather than extending it: an
//! operator who names their own relay does not want a silent fallback to n0
//! carrying their traffic. Pinned seeds are the opposite — purely additive,
//! since there are no default pins to displace.
//!
//! ```no_run
//! # fn main() -> Result<(), mshr::Error> {
//! // yubaba serve / the desktop / any dialer, all reading the same source.
//! let seeds = mshr::Seeds::from_env()?;
//! let builder = seeds.apply(mshr::Endpoint::builder());
//! # Ok(()) }
//! ```
//!
//! Part of R609-F4 — canonical annotation in
//! `.yah/docs/working/W242-yubaba-mesh-raft-roadmap.md`.

use std::str::FromStr;

use url::Url;

use crate::discovery::{default_relays, Discovery};
use crate::{EndpointAddr, EndpointBuilder, Error, NodeId, RelayMap, RelayMode, RelayUrl, Result};

/// Environment variable naming pinned peers (see [`Seed`]). Repeatable via
/// comma or whitespace separation.
pub const ENV_SEED: &str = "YAH_XLB_SEED";

/// Environment variable naming NAT-traversal relay servers. `none` disables
/// the lane entirely.
pub const ENV_RELAY: &str = "YAH_XLB_RELAY";

/// Environment variable naming pkarr relays used to resolve a bare NodeId.
/// `none` disables the lane entirely.
pub const ENV_PKARR: &str = "YAH_XLB_PKARR";

/// The value that spells "turn this lane off" in [`RelayChoice::parse_list`],
/// on the command line and in the environment alike.
pub const DISABLED_SPELLING: &str = "none";

/// URL scheme for the seed / connect spelling. Matches the desktop's
/// `mshr://<node-id>/<workspace>` connect URL (`classifyConnectUrl` in
/// `packages/yah/ui/src/components/shell/CampSelector.tsx`) so one string
/// pasted from a node's `GET /identity` works in both places.
pub const SEED_SCHEME: &str = "mshr";

/// A pinned peer: a `NodeId` plus whatever is known about how to reach it.
///
/// Parsed from one string so it survives a command line, an environment
/// variable and a systemd `Environment=` line without any escaping:
///
/// ```text
/// 33019bfb…883f                                  bare NodeId (needs a resolver lane)
/// mshr://33019bfb…883f                           same thing, explicit
/// mshr://33019bfb…883f?addr=203.0.113.9:7444     direct address, repeatable
/// mshr://33019bfb…883f?addr=…&relay=https://r.example   direct + relay home
/// mshr://33019bfb…883f/srv/code                  path is ignored here (it is
///                                                the desktop's workspace half)
/// ```
///
/// A bare NodeId is a legitimate seed — it is exactly what the pkarr lane
/// exists to resolve — but it is only useful when some resolver lane is on.
/// [`Seed::is_resolvable_alone`] reports which kind you have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed {
    addr: EndpointAddr,
}

impl Seed {
    /// Wrap an already-built [`EndpointAddr`].
    pub fn new(addr: EndpointAddr) -> Self {
        Self { addr }
    }

    /// The peer's identity.
    pub fn node_id(&self) -> NodeId {
        self.addr.id
    }

    /// The address as mshr's discovery lane wants it.
    pub fn endpoint_addr(&self) -> &EndpointAddr {
        &self.addr
    }

    /// Consume into the underlying [`EndpointAddr`].
    pub fn into_endpoint_addr(self) -> EndpointAddr {
        self.addr
    }

    /// Whether this seed carries a path of its own (a direct address or a
    /// relay home), and so can be dialed with no resolver lane configured.
    ///
    /// The distinction is worth a method because the failure it separates is
    /// uninformative rather than loud: a bare NodeId with no resolver fails
    /// with `"No addressing information available"`, which tells an operator
    /// nothing about a missing pkarr relay.
    pub fn is_resolvable_alone(&self) -> bool {
        !self.addr.is_empty()
    }
}

impl From<EndpointAddr> for Seed {
    fn from(addr: EndpointAddr) -> Self {
        Self::new(addr)
    }
}

impl FromStr for Seed {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(Error::Endpoint("empty seed".into()));
        }
        let Some(rest) = s.strip_prefix(&format!("{SEED_SCHEME}://")) else {
            // Bare NodeId. No `Url::parse` — a 64-hex string is not a URL and
            // routing it through one produces a parse error that names the
            // wrong problem.
            let node_id = parse_node_id(s)?;
            return Ok(Self::new(EndpointAddr::new(node_id)));
        };

        // `Url` will not parse `mshr://` reliably across scheme-specific
        // rules, and the query is all we want anyway, so split by hand.
        let (host_and_path, query) = match rest.split_once('?') {
            Some((h, q)) => (h, Some(q)),
            None => (rest, None),
        };
        // Trailing `/…` is the desktop connect URL's workspace path; a seed
        // names a *machine*, so it is accepted and dropped rather than
        // rejected — the same string should work in both places.
        let host = host_and_path.split('/').next().unwrap_or("");
        let mut addr = EndpointAddr::new(parse_node_id(host)?);

        for (key, value) in query.into_iter().flat_map(parse_query) {
            match key.as_str() {
                "addr" => {
                    let socket = value.parse().map_err(|e| {
                        Error::Endpoint(format!("seed addr {value:?} is not host:port — {e}"))
                    })?;
                    addr = addr.with_ip_addr(socket);
                }
                "relay" => {
                    let relay: RelayUrl = value.parse().map_err(|e| {
                        Error::Endpoint(format!("seed relay url {value:?} is malformed — {e}"))
                    })?;
                    addr = addr.with_relay_url(relay);
                }
                other => {
                    return Err(Error::Endpoint(format!(
                        "unknown seed parameter {other:?} in {s:?} (expected `addr` or `relay`)"
                    )));
                }
            }
        }
        Ok(Self::new(addr))
    }
}

impl std::fmt::Display for Seed {
    /// Round-trips through [`FromStr`]: what this prints is a valid seed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{SEED_SCHEME}://{}", self.addr.id)?;
        let mut sep = '?';
        for a in self.addr.ip_addrs() {
            write!(f, "{sep}addr={a}")?;
            sep = '&';
        }
        for relay in self.addr.relay_urls() {
            write!(f, "{sep}relay={relay}")?;
            sep = '&';
        }
        Ok(())
    }
}

fn parse_node_id(s: &str) -> Result<NodeId> {
    NodeId::from_str(s.trim())
        .map_err(|e| Error::Endpoint(format!("malformed NodeId {s:?} in seed — {e}")))
}

/// Minimal `key=value&…` split. `url::form_urlencoded` would want a whole
/// `Url`, which is what we just decided not to build.
fn parse_query(q: &str) -> impl Iterator<Item = (String, String)> + '_ {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
            None => (pair.trim().to_string(), String::new()),
        })
}

/// Where one URL-shaped lane points: the shipped default, off, or an
/// operator's own hosts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RelayChoice {
    /// The list this binary ships. See the module docs for what that is and
    /// why it is n0's.
    #[default]
    Default,
    /// Lane off. No traffic leaves for this purpose at all.
    Disabled,
    /// Operator-supplied hosts, **replacing** the default rather than
    /// extending it.
    Custom(Vec<Url>),
}

impl RelayChoice {
    /// Resolve a repeated command-line flag (or a comma/whitespace-separated
    /// environment variable) into a choice.
    ///
    /// An empty input is [`RelayChoice::Default`] — "the operator said
    /// nothing" — and the literal [`DISABLED_SPELLING`] anywhere in the list
    /// is [`RelayChoice::Disabled`]. `none` wins over sibling URLs on
    /// purpose: the mix is a mistake, and the safe reading of "off" plus "on"
    /// is off.
    pub fn parse_list<I, S>(values: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut urls = Vec::new();
        for raw in values {
            for token in raw
                .as_ref()
                .split([',', ' ', '\t', '\n'])
                .map(str::trim)
                .filter(|t| !t.is_empty())
            {
                if token.eq_ignore_ascii_case(DISABLED_SPELLING) {
                    return Ok(Self::Disabled);
                }
                let url = Url::parse(token).map_err(|e| {
                    Error::Endpoint(format!("relay url {token:?} is malformed — {e}"))
                })?;
                urls.push(url);
            }
        }
        Ok(if urls.is_empty() {
            Self::Default
        } else {
            Self::Custom(urls)
        })
    }

    /// Resolve to concrete URLs, with `default` supplying the shipped list.
    fn resolve(&self, default: impl FnOnce() -> Vec<Url>) -> Vec<Url> {
        match self {
            Self::Default => default(),
            Self::Disabled => Vec::new(),
            Self::Custom(urls) => urls.clone(),
        }
    }
}

/// The shipped NAT-traversal relay servers: n0's production relay map.
///
/// Returned as a [`RelayMap`] rather than URLs because that is what iroh's
/// own `RelayMode::Default` resolves to, and re-deriving it from a URL list
/// would drift from whatever n0 ships next.
pub fn default_relay_map() -> RelayMap {
    RelayMode::Default.relay_map()
}

/// The shipped pkarr relays — n0's production pkarr relay, via
/// [`crate::default_relays`].
pub fn default_pkarr_relays() -> Vec<Url> {
    default_relays()
}

/// Resolved seed/discovery configuration for one [`crate::Endpoint`].
///
/// Build with [`Seeds::defaults`] / [`Seeds::from_env`] / [`Seeds::resolve`]
/// and hand to [`Seeds::apply`]. See the module docs for the lane table and
/// the precedence rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seeds {
    pinned: Vec<Seed>,
    relays: RelayChoice,
    pkarr: RelayChoice,
    lan: bool,
}

impl Default for Seeds {
    fn default() -> Self {
        Self::defaults()
    }
}

impl Seeds {
    /// The baked-in configuration: n0's relay map, n0's pkarr relay, LAN
    /// discovery on, nothing pinned.
    ///
    /// LAN is on because it costs nothing where it does not apply — on a
    /// host with multicast blocked (every cloud VPS) the lookup simply finds
    /// nothing — and on a laptop it is the difference between reaching the
    /// camp on the desk next to you instantly and round-tripping through a
    /// relay in another country. Turn it off with [`Seeds::with_lan`].
    pub fn defaults() -> Self {
        Self {
            pinned: Vec::new(),
            relays: RelayChoice::Default,
            pkarr: RelayChoice::Default,
            lan: true,
        }
    }

    /// Nothing configured at all: no pins, no relays, no pkarr, no LAN.
    ///
    /// The posture the control plane bound with before this ticket — a peer
    /// must be handed a fully-formed [`EndpointAddr`]. Kept nameable because
    /// tests want two in-process endpoints that talk to nobody else.
    pub fn none() -> Self {
        Self {
            pinned: Vec::new(),
            relays: RelayChoice::Disabled,
            pkarr: RelayChoice::Disabled,
            lan: false,
        }
    }

    /// Read every knob from the environment ([`ENV_SEED`], [`ENV_RELAY`],
    /// [`ENV_PKARR`]), falling back to [`Seeds::defaults`] per knob.
    ///
    /// This is the layer a systemd `Environment=` line or a launchd
    /// `EnvironmentVariables` dict reaches, and so the one a process with no
    /// command line of its own (the desktop) uses.
    pub fn from_env() -> Result<Self> {
        Self::resolve::<&str, &str, &str>([], [], [])
    }

    /// Resolve all three knobs at once with explicit-over-environment
    /// precedence. Empty iterators mean "the operator passed no flag", which
    /// is what lets the environment speak.
    pub fn resolve<A, B, C>(
        pinned: impl IntoIterator<Item = A>,
        relays: impl IntoIterator<Item = B>,
        pkarr: impl IntoIterator<Item = C>,
    ) -> Result<Self>
    where
        A: AsRef<str>,
        B: AsRef<str>,
        C: AsRef<str>,
    {
        let pinned: Vec<String> = split_all(pinned);
        let pinned = if pinned.is_empty() {
            env_tokens(ENV_SEED)
        } else {
            pinned
        };
        let pinned = pinned
            .iter()
            .map(|s| s.parse::<Seed>())
            .collect::<Result<Vec<_>>>()?;

        let relays: Vec<String> = split_all(relays);
        let relays = if relays.is_empty() {
            RelayChoice::parse_list(env_tokens(ENV_RELAY))?
        } else {
            RelayChoice::parse_list(relays)?
        };

        let pkarr: Vec<String> = split_all(pkarr);
        let pkarr = if pkarr.is_empty() {
            RelayChoice::parse_list(env_tokens(ENV_PKARR))?
        } else {
            RelayChoice::parse_list(pkarr)?
        };

        Ok(Self {
            pinned,
            relays,
            pkarr,
            lan: true,
        })
    }

    /// Add pinned peers (additive — see the module docs on why URLs replace
    /// and pins do not).
    pub fn with_pinned<I: IntoIterator<Item = Seed>>(mut self, seeds: I) -> Self {
        self.pinned.extend(seeds);
        self
    }

    /// Point the NAT-traversal relay lane somewhere else (or turn it off).
    pub fn with_relays(mut self, choice: RelayChoice) -> Self {
        self.relays = choice;
        self
    }

    /// Point the pkarr resolution lane somewhere else (or turn it off).
    pub fn with_pkarr(mut self, choice: RelayChoice) -> Self {
        self.pkarr = choice;
        self
    }

    /// Turn the LAN (mDNS) lane on or off.
    pub fn with_lan(mut self, on: bool) -> Self {
        self.lan = on;
        self
    }

    /// Pinned peers.
    pub fn pinned(&self) -> &[Seed] {
        &self.pinned
    }

    /// The NAT-traversal relay knob as configured.
    pub fn relays(&self) -> &RelayChoice {
        &self.relays
    }

    /// The pkarr knob as configured.
    pub fn pkarr(&self) -> &RelayChoice {
        &self.pkarr
    }

    /// LAN lane on?
    pub fn lan_enabled(&self) -> bool {
        self.lan
    }

    /// Whether a *bare* NodeId can be turned into a path under this
    /// configuration — i.e. whether some lane resolves addresses.
    ///
    /// Callers use this to fail a bare-NodeId dial with a reason instead of
    /// letting it hang to timeout. Delegates to
    /// [`Discovery::resolves_bare_node_ids`] rather than re-deciding, so the
    /// answer cannot differ from what the bound endpoint reports.
    pub fn resolves_bare_node_ids(&self) -> bool {
        self.discovery().resolves_bare_node_ids()
    }

    /// The [`Discovery`] composition these seeds describe.
    pub fn discovery(&self) -> Discovery {
        Discovery::new()
            .with_lan_if(self.lan)
            .with_static(
                self.pinned
                    .iter()
                    .map(|s| s.endpoint_addr().clone())
                    .collect::<Vec<_>>(),
            )
            .with_relays(self.pkarr.resolve(default_pkarr_relays))
    }

    /// The [`RelayMap`] these seeds describe, or `None` when the lane is off
    /// (which leaves the endpoint on `RelayMode::Disabled`).
    pub fn relay_map(&self) -> Option<RelayMap> {
        match &self.relays {
            RelayChoice::Default => Some(default_relay_map()),
            RelayChoice::Disabled => None,
            RelayChoice::Custom(urls) => Some(RelayMap::from_iter(
                urls.iter().cloned().map(RelayUrl::from),
            )),
        }
    }

    /// Apply both lanes to an endpoint builder. The single call site every
    /// binary should use, so no binary can configure half of this.
    pub fn apply(&self, builder: EndpointBuilder) -> EndpointBuilder {
        let builder = builder.discovery(self.discovery());
        match self.relay_map() {
            Some(map) => builder.relay_map(map),
            None => builder,
        }
    }

    /// One-line summary for a startup log — an operator staring at a node
    /// that will not dial needs to see which lanes are actually on.
    pub fn describe(&self) -> String {
        let lane = |c: &RelayChoice| match c {
            RelayChoice::Default => "default".to_string(),
            RelayChoice::Disabled => "off".to_string(),
            RelayChoice::Custom(urls) => urls
                .iter()
                .map(|u| u.as_str())
                .collect::<Vec<_>>()
                .join(","),
        };
        format!(
            "relays={} pkarr={} lan={} pinned={}",
            lane(&self.relays),
            lane(&self.pkarr),
            self.lan,
            self.pinned.len()
        )
    }
}

/// Split every input on the same separators a single value accepts, so one
/// repeated flag and one comma-joined flag mean the same thing.
fn split_all<S: AsRef<str>>(values: impl IntoIterator<Item = S>) -> Vec<String> {
    values
        .into_iter()
        .flat_map(|v| {
            v.as_ref()
                .split([',', ' ', '\t', '\n'])
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn env_tokens(key: &str) -> Vec<String> {
    match std::env::var(key) {
        Ok(v) => split_all([v]),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keypair;

    fn node_id() -> NodeId {
        Keypair::generate().node_id()
    }

    #[test]
    fn a_bare_node_id_parses_as_a_seed_with_no_path_of_its_own() {
        let id = node_id();
        let seed: Seed = id.to_string().parse().unwrap();
        assert_eq!(seed.node_id(), id);
        assert!(!seed.is_resolvable_alone());
    }

    #[test]
    fn the_mshr_scheme_parses_the_same_as_bare() {
        let id = node_id();
        let bare: Seed = id.to_string().parse().unwrap();
        let scheme: Seed = format!("mshr://{id}").parse().unwrap();
        assert_eq!(bare, scheme);
    }

    /// The desktop's connect URL carries the workspace as a path. The same
    /// string has to work as a seed, so the path is dropped rather than
    /// rejected — a seed names a machine, not a workspace.
    #[test]
    fn a_workspace_path_is_accepted_and_ignored() {
        let id = node_id();
        let seed: Seed = format!("mshr://{id}/srv/code").parse().unwrap();
        assert_eq!(seed.node_id(), id);
    }

    #[test]
    fn addrs_and_relay_come_off_the_query() {
        let id = node_id();
        let seed: Seed = format!(
            "mshr://{id}?addr=203.0.113.9:7444&addr=198.51.100.2:7444&relay=https://relay.example/"
        )
        .parse()
        .unwrap();
        assert_eq!(seed.endpoint_addr().ip_addrs().count(), 2);
        assert_eq!(seed.endpoint_addr().relay_urls().count(), 1);
        assert!(seed.is_resolvable_alone());
    }

    #[test]
    fn display_round_trips_through_parse() {
        let id = node_id();
        let seed: Seed = format!("mshr://{id}?addr=203.0.113.9:7444&relay=https://relay.example/")
            .parse()
            .unwrap();
        let reparsed: Seed = seed.to_string().parse().unwrap();
        assert_eq!(seed, reparsed);
    }

    #[test]
    fn a_malformed_node_id_names_the_node_id() {
        let err = "not-a-node-id".parse::<Seed>().unwrap_err();
        assert!(
            err.to_string().contains("malformed NodeId"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn an_unknown_query_parameter_is_refused_rather_than_ignored() {
        let id = node_id();
        let err = format!("mshr://{id}?port=7444")
            .parse::<Seed>()
            .unwrap_err();
        assert!(err.to_string().contains("unknown seed parameter"), "{err}");
    }

    #[test]
    fn a_malformed_seed_addr_names_the_addr() {
        let id = node_id();
        let err = format!("mshr://{id}?addr=203.0.113.9")
            .parse::<Seed>()
            .unwrap_err();
        assert!(err.to_string().contains("not host:port"), "{err}");
    }

    // ── RelayChoice ──────────────────────────────────────────────────────

    #[test]
    fn no_values_is_the_shipped_default() {
        assert_eq!(
            RelayChoice::parse_list(Vec::<&str>::new()).unwrap(),
            RelayChoice::Default
        );
    }

    #[test]
    fn none_disables_the_lane() {
        assert_eq!(
            RelayChoice::parse_list(["none"]).unwrap(),
            RelayChoice::Disabled
        );
        assert_eq!(
            RelayChoice::parse_list(["NONE"]).unwrap(),
            RelayChoice::Disabled
        );
    }

    /// `none` alongside a URL is a mistake either way; the safe reading of
    /// "off" plus "on" is off.
    #[test]
    fn none_wins_over_a_sibling_url() {
        assert_eq!(
            RelayChoice::parse_list(["https://relay.example", "none"]).unwrap(),
            RelayChoice::Disabled
        );
    }

    #[test]
    fn a_repeated_flag_and_a_comma_list_mean_the_same_thing() {
        let repeated =
            RelayChoice::parse_list(["https://a.example/", "https://b.example/"]).unwrap();
        let joined = RelayChoice::parse_list(["https://a.example/,https://b.example/"]).unwrap();
        assert_eq!(repeated, joined);
        assert!(matches!(repeated, RelayChoice::Custom(ref u) if u.len() == 2));
    }

    #[test]
    fn a_malformed_relay_url_fails_the_parse() {
        let err = RelayChoice::parse_list(["not a url"]).unwrap_err();
        assert!(err.to_string().contains("malformed"), "{err}");
    }

    // ── Seeds ────────────────────────────────────────────────────────────

    #[test]
    fn the_shipped_default_resolves_bare_node_ids() {
        let s = Seeds::defaults();
        assert!(s.resolves_bare_node_ids());
        assert!(s.relay_map().is_some());
        assert_eq!(s.discovery().relay_urls().len(), 1);
        assert!(s.discovery().lan_enabled());
    }

    /// The pre-F4 posture must stay reachable: an endpoint that talks to
    /// nobody it was not explicitly handed.
    #[test]
    fn none_configures_nothing() {
        let s = Seeds::none();
        assert!(!s.resolves_bare_node_ids());
        assert!(s.relay_map().is_none());
        assert!(s.discovery().relay_urls().is_empty());
        assert!(!s.discovery().lan_enabled());
    }

    #[test]
    fn a_custom_relay_replaces_the_default_rather_than_extending_it() {
        let s = Seeds::defaults()
            .with_relays(RelayChoice::parse_list(["https://relay.example/"]).unwrap());
        let map = s.relay_map().unwrap();
        let urls: Vec<_> = map.urls::<Vec<_>>();
        assert_eq!(
            urls.len(),
            1,
            "default n0 relays must not survive: {urls:?}"
        );
        assert!(urls[0].to_string().contains("relay.example"));
    }

    #[test]
    fn a_custom_pkarr_replaces_the_default_rather_than_extending_it() {
        let s = Seeds::defaults()
            .with_pkarr(RelayChoice::parse_list(["https://pkarr.example/"]).unwrap());
        let urls = s.discovery().relay_urls().to_vec();
        assert_eq!(urls.len(), 1);
        assert!(urls[0].as_str().contains("pkarr.example"));
    }

    /// Disabling pkarr while leaving LAN on still resolves bare NodeIds on
    /// the local subnet — the lanes are independent, and reporting otherwise
    /// would make a working local dial refuse itself.
    #[test]
    fn lan_alone_still_resolves_bare_node_ids() {
        let s = Seeds::defaults().with_pkarr(RelayChoice::Disabled);
        assert!(s.resolves_bare_node_ids());
        assert!(!s.with_lan(false).resolves_bare_node_ids());
    }

    /// A pin without addresses resolves nothing — it is the thing that needs
    /// resolving.
    #[test]
    fn a_bare_pin_does_not_count_as_a_resolver() {
        let bare: Seed = node_id().to_string().parse().unwrap();
        let s = Seeds::none().with_pinned([bare]);
        assert!(!s.resolves_bare_node_ids());

        let addressed: Seed = format!("mshr://{}?addr=203.0.113.9:7444", node_id())
            .parse()
            .unwrap();
        assert!(Seeds::none()
            .with_pinned([addressed])
            .resolves_bare_node_ids());
    }

    #[test]
    fn pinned_seeds_reach_the_discovery_static_lane() {
        let a: Seed = node_id().to_string().parse().unwrap();
        let b: Seed = node_id().to_string().parse().unwrap();
        let s = Seeds::none().with_pinned([a, b]);
        assert_eq!(s.discovery().static_seeds().len(), 2);
    }

    /// The precedence rule, both directions. Serialized rather than
    /// parallel because it mutates process environment.
    #[test]
    fn explicit_arguments_beat_the_environment_which_beats_the_default() {
        let id = node_id();
        // SAFETY: single-threaded test body; no other thread reads the env
        // between the set and the unset.
        unsafe {
            std::env::set_var(ENV_RELAY, "https://from-env.example/");
            std::env::set_var(ENV_SEED, format!("mshr://{id}?addr=203.0.113.9:7444"));
        }

        // Environment beats the baked-in default.
        let from_env = Seeds::from_env().unwrap();
        assert!(
            matches!(from_env.relays(), RelayChoice::Custom(u) if u[0].as_str().contains("from-env")),
            "{:?}",
            from_env.relays()
        );
        assert_eq!(from_env.pinned().len(), 1);
        // An unset knob still takes the default.
        assert_eq!(from_env.pkarr(), &RelayChoice::Default);

        // An explicit argument beats the environment.
        let explicit =
            Seeds::resolve::<&str, _, &str>([], ["https://from-arg.example/"], []).unwrap();
        assert!(
            matches!(explicit.relays(), RelayChoice::Custom(u) if u[0].as_str().contains("from-arg")),
            "{:?}",
            explicit.relays()
        );

        unsafe {
            std::env::remove_var(ENV_RELAY);
            std::env::remove_var(ENV_SEED);
        }
    }

    #[test]
    fn describe_names_every_lane() {
        let d = Seeds::defaults().describe();
        assert!(d.contains("relays=default"), "{d}");
        assert!(d.contains("pkarr=default"), "{d}");
        assert!(d.contains("lan=true"), "{d}");
        assert!(Seeds::none().describe().contains("relays=off"));
    }
}

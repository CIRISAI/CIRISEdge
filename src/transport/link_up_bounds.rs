//! CIRISEdge#856 — the responder's per-peer link-up rate, on two axes.
//!
//! A peer that re-dials on every round costs the responder a link handshake,
//! a bundle and announce push, a link-table slot and a reaper pass per dial —
//! whatever build it runs and whatever its reason. The bound keys on what the
//! responder OBSERVES: link-ups per proven transport identity, and link-ups per
//! source address, so M identities on one host cannot multiply through it.
//!
//! Both axes are [`RateLimiter`]s (`docs/FSD_RATE_LIMIT.md`): bounded maps,
//! fair eviction, the caller's clock. Nothing here closes a link; the verdict
//! is advisory (D6) and the transport acts on it.
//!
//! ## Why "right after identification"
//!
//! leviculum auto-accepts an inbound link request and exposes no accept hook
//! (`TransportConfig::max_links` is the only refusal, and it is global). A
//! LINKREQUEST does not carry the dialer's identity either: the identity
//! arrives in LINKIDENTIFY on the established link. So the earliest point at
//! which a per-identity verdict exists is `LinkIdentified`, and that is where
//! the transport closes a refused link — before it is attributed, so it never
//! carries a frame anywhere.
//!
//! ## The source axis
//!
//! The source is the IP address of the connection the link arrived on: a TCP
//! server spawns one interface per accepted connection, named
//! `tcp_server/<ip>:<port>` (leviculum `interfaces/tcp.rs`). The port is
//! dropped (a reconnect gets a new one) and an IPv4-mapped IPv6 address is
//! folded to IPv4. An interface whose name carries no address (UDP, Auto,
//! serial, a local shared-instance client) yields no source, and the source
//! axis is skipped for it: a broadcast medium is not one host.
//!
//! The address is the IMMEDIATE hop. Peers reaching this node through one
//! transport relay share that relay's address, and peers behind one NAT share
//! the NAT's; the default leaves room for several honest identities per source.

use crate::observability::{LINK_UP_REFUSED_RATE_IDENTITY, LINK_UP_REFUSED_RATE_SOURCE};
use crate::rate_limit::{Decision, Policy, Quota, RateLimiter, Ts};

/// The link-up quotas, per axis a BURST quota and an optional SUSTAINED one.
///
/// The burst quota is the limiter's: `permits` link-ups, refilled
/// `window_secs` after the last permitted one — so a peer that dials now and
/// then is never refused, and a peer that never pauses gets `permits` before
/// it must. The sustained quota is a fixed window (the limiter's slow-drain
/// ceiling): a peer that dials just under the burst quota forever is held to
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkUpRatePolicy {
    /// Per proven transport identity, burst.
    pub identity: Quota,
    /// Per proven transport identity, sustained (`None`: burst only).
    pub identity_sustained: Option<Quota>,
    /// Per source address, all identities on it together, burst.
    pub source: Quota,
    /// Per source address, sustained (`None`: burst only).
    pub source_sustained: Option<Quota>,
    /// Identities tracked at once.
    pub max_identities: usize,
    /// Source addresses tracked at once.
    pub max_sources: usize,
}

impl LinkUpRatePolicy {
    /// A healthy edge dials a burst of parallel lanes when its coordinators
    /// fan out at once — one Resource per link, so every busy lane is a dial
    /// (CIRISEdge#531/#819: fourteen concurrent sends is the Datum trace's
    /// coordinator count, nineteen kinds the ceiling). Thirty-two covers the
    /// burst with room for its retries.
    pub const DEFAULT_IDENTITY: Quota = Quota::new(32, 60);
    /// Sustained: eight link-ups a minute averaged over an hour. A healthy
    /// peer's pooled lanes are reaped idle after two minutes (#853) and
    /// re-dialled on its next round; the field storm (#856) was ~23 a minute
    /// per identity.
    pub const DEFAULT_IDENTITY_SUSTAINED: Quota = Quota::new(480, 3_600);
    /// Four identities' worth per source address.
    pub const DEFAULT_SOURCE: Quota = Quota::new(128, 60);
    /// Four identities' worth, sustained.
    pub const DEFAULT_SOURCE_SUSTAINED: Quota = Quota::new(1_920, 3_600);
    /// Keys tracked per axis.
    pub const DEFAULT_MAX_KEYS: usize = 4_096;
}

impl Default for LinkUpRatePolicy {
    fn default() -> Self {
        Self {
            identity: Self::DEFAULT_IDENTITY,
            identity_sustained: Some(Self::DEFAULT_IDENTITY_SUSTAINED),
            source: Self::DEFAULT_SOURCE,
            source_sustained: Some(Self::DEFAULT_SOURCE_SUSTAINED),
            max_identities: Self::DEFAULT_MAX_KEYS,
            max_sources: Self::DEFAULT_MAX_KEYS,
        }
    }
}

/// Why a link-up was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkUpRefusal {
    /// The identity is over its quota.
    RateIdentity,
    /// The identity is within its quota; its source address is not.
    RateSource,
}

impl LinkUpRefusal {
    /// The `link_ups_refused_total` reason token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RateIdentity => LINK_UP_REFUSED_RATE_IDENTITY,
            Self::RateSource => LINK_UP_REFUSED_RATE_SOURCE,
        }
    }
}

/// The two limiters plus the interface → source cache.
#[derive(Debug)]
pub struct LinkUpBounds {
    identity: RateLimiter<[u8; 16]>,
    source: RateLimiter<String>,
    /// Interface id → its source address (`None`: no address). leviculum
    /// never reuses an interface id, so an entry never goes stale; the map is
    /// cleared past [`Self::IFACE_CACHE_MAX`] rather than grown.
    iface_source: std::collections::HashMap<usize, Option<String>>,
}

impl LinkUpBounds {
    /// Interface ids cached before the cache is cleared.
    pub const IFACE_CACHE_MAX: usize = 4_096;

    #[must_use]
    pub fn new(policy: LinkUpRatePolicy) -> Self {
        Self {
            identity: RateLimiter::new(
                Policy::quota(
                    policy.identity.permits,
                    policy.identity.window_secs,
                    policy.max_identities,
                )
                .with_long_windows([policy.identity_sustained, None]),
            ),
            source: RateLimiter::new(
                Policy::quota(
                    policy.source.permits,
                    policy.source.window_secs,
                    policy.max_sources,
                )
                .with_long_windows([policy.source_sustained, None]),
            ),
            iface_source: std::collections::HashMap::new(),
        }
    }

    /// One link-up by `identity` from `source`. The identity is judged first;
    /// the source is charged only for a link-up its identity was allowed, so
    /// one storming identity spends its own budget and not its neighbours'.
    ///
    /// # Errors
    ///
    /// The axis that refused.
    pub fn admit(
        &mut self,
        identity: [u8; 16],
        source: Option<&str>,
        now: Ts,
    ) -> Result<(), LinkUpRefusal> {
        if !self
            .identity
            .check_from(&identity, source, now)
            .is_allowed()
        {
            return Err(LinkUpRefusal::RateIdentity);
        }
        if let Some(src) = source {
            if let Decision::Deny { .. } = self.source.check(&src.to_owned(), now) {
                return Err(LinkUpRefusal::RateSource);
            }
        }
        Ok(())
    }

    /// The cached source for interface `iface`, if this interface was seen.
    #[must_use]
    pub fn cached_source(&self, iface: usize) -> Option<Option<String>> {
        self.iface_source.get(&iface).cloned()
    }

    /// Cache every `(interface id, interface name)` pair's source.
    pub fn cache_sources<'a>(&mut self, interfaces: impl IntoIterator<Item = (usize, &'a str)>) {
        if self.iface_source.len() >= Self::IFACE_CACHE_MAX {
            self.iface_source.clear();
        }
        for (id, name) in interfaces {
            self.iface_source
                .entry(id)
                .or_insert_with(|| source_from_interface_name(name));
        }
    }
}

/// The source address an interface name carries: the IP of
/// `<prefix>/<ip>:<port>` (leviculum's per-connection TCP child), with the
/// port dropped and an IPv4-mapped address folded to IPv4. `None` for a name
/// that carries no socket address.
#[must_use]
pub fn source_from_interface_name(name: &str) -> Option<String> {
    let (_, addr) = name.rsplit_once('/')?;
    let addr: std::net::SocketAddr = addr.parse().ok()?;
    Some(addr.ip().to_canonical().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 16] = [0xa; 16];
    const B: [u8; 16] = [0xb; 16];
    const C: [u8; 16] = [0xc; 16];

    fn policy(identity: u32, source: u32) -> LinkUpRatePolicy {
        LinkUpRatePolicy {
            identity: Quota::new(identity, 60),
            identity_sustained: None,
            source: Quota::new(source, 60),
            source_sustained: None,
            ..LinkUpRatePolicy::default()
        }
    }

    #[test]
    fn the_sustained_quota_holds_a_peer_that_never_spends_its_burst() {
        let mut b = LinkUpBounds::new(LinkUpRatePolicy {
            identity_sustained: Some(Quota::new(5, 3_600)),
            ..policy(3, 100)
        });
        // Two link-ups a minute and a quiet minute between pairs: the burst
        // quota refills every time, the sustained one does not.
        let mut refused = 0;
        for minute in 0..10u64 {
            for s in 0..2 {
                if b.admit(A, None, 1_000 + minute * 120 + s).is_err() {
                    refused += 1;
                }
            }
        }
        assert_eq!(refused, 15, "five of twenty inside the hour");
    }

    #[test]
    fn the_default_admits_a_healthy_fan_out_burst() {
        let mut b = LinkUpBounds::new(LinkUpRatePolicy::default());
        for _ in 0..19 {
            assert_eq!(b.admit(A, Some("10.0.0.1"), 1000), Ok(()));
        }
    }

    #[test]
    fn one_identity_past_its_quota_is_refused_on_the_identity_axis() {
        let mut b = LinkUpBounds::new(policy(3, 100));
        for _ in 0..3 {
            assert_eq!(b.admit(A, Some("10.0.0.1"), 1000), Ok(()));
        }
        assert_eq!(
            b.admit(A, Some("10.0.0.1"), 1000),
            Err(LinkUpRefusal::RateIdentity)
        );
        // Another identity on the same source is untouched.
        assert_eq!(b.admit(B, Some("10.0.0.1"), 1000), Ok(()));
    }

    #[test]
    fn identities_each_under_quota_are_refused_on_the_source_axis() {
        let mut b = LinkUpBounds::new(policy(3, 6));
        let mut refused = 0;
        for _ in 0..3 {
            for id in [A, B, C] {
                if b.admit(id, Some("10.0.0.1"), 1000) == Err(LinkUpRefusal::RateSource) {
                    refused += 1;
                }
            }
        }
        assert_eq!(refused, 3, "nine link-ups, six permitted by the source");
        // A different source is untouched.
        assert_eq!(
            b.admit(A, Some("10.0.0.2"), 1000),
            Err(LinkUpRefusal::RateIdentity)
        );
        let mut fresh = LinkUpBounds::new(policy(3, 6));
        assert_eq!(fresh.admit(A, Some("10.0.0.2"), 1000), Ok(()));
    }

    #[test]
    fn a_refused_identity_does_not_spend_its_sources_budget() {
        let mut b = LinkUpBounds::new(policy(1, 2));
        assert_eq!(b.admit(A, Some("s"), 1000), Ok(()));
        for _ in 0..10 {
            assert_eq!(
                b.admit(A, Some("s"), 1000),
                Err(LinkUpRefusal::RateIdentity)
            );
        }
        assert_eq!(b.admit(B, Some("s"), 1000), Ok(()));
    }

    #[test]
    fn a_quiet_identity_refills() {
        let mut b = LinkUpBounds::new(policy(1, 100));
        assert_eq!(b.admit(A, None, 1000), Ok(()));
        assert_eq!(b.admit(A, None, 1001), Err(LinkUpRefusal::RateIdentity));
        assert_eq!(b.admit(A, None, 1060), Ok(()));
    }

    #[test]
    fn no_source_skips_the_source_axis() {
        let mut b = LinkUpBounds::new(policy(100, 1));
        for id in [A, B, C] {
            assert_eq!(b.admit(id, None, 1000), Ok(()));
        }
    }

    #[test]
    fn source_is_the_ip_of_a_tcp_child_without_its_port() {
        assert_eq!(
            source_from_interface_name("tcp_server/45.76.231.182:51234").as_deref(),
            Some("45.76.231.182")
        );
        assert_eq!(
            source_from_interface_name("tcp_server/[::1]:4242").as_deref(),
            Some("::1")
        );
        assert_eq!(
            source_from_interface_name("tcp_server/[::ffff:127.0.0.1]:4242").as_deref(),
            Some("127.0.0.1"),
            "an IPv4-mapped address is the IPv4 host"
        );
        assert_eq!(source_from_interface_name("UDPInterface[udp]"), None);
        assert_eq!(source_from_interface_name("tcp_server"), None);
    }

    #[test]
    fn the_interface_cache_is_bounded() {
        let mut b = LinkUpBounds::new(LinkUpRatePolicy::default());
        let names: Vec<String> = (0..LinkUpBounds::IFACE_CACHE_MAX + 10)
            .map(|i| format!("tcp_server/10.0.0.1:{}", 1000 + i))
            .collect();
        for (i, n) in names.iter().enumerate() {
            b.cache_sources([(i, n.as_str())]);
        }
        assert!(b.iface_source.len() <= LinkUpBounds::IFACE_CACHE_MAX);
        let last = names.len() - 1;
        assert_eq!(b.cached_source(last), Some(Some("10.0.0.1".to_owned())));
    }
}

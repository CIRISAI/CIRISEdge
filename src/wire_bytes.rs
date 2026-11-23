//! CIRISEdge#1025 item 3 — **bytes on the wire, by transport and plane.**
//!
//! canonical-1 moved 27 GB in and 63 GB out of its network namespace in 41 h
//! while `transport_bytes_{in,out}_total` read `{}` and `replication_io`
//! explained ~9 GB. Those two counters only ever saw the application
//! envelope (`Edge::send`, `dispatch_inbound`); nothing counted replication,
//! Reticulum resources, link control, shaping, relayed frames or A/V. This
//! module is the ledger that makes every byte that crosses an edge interface
//! land in exactly one `(transport, plane)` cell.
//!
//! # Two sources, one ledger
//!
//! - **Interface truth.** leviculum's I/O tasks count every byte they read
//!   from or write to a socket (`InterfaceCounters::rx_bytes`/`tx_bytes`,
//!   leviculum-std `interfaces/tcp.rs:1277,1336`, `interfaces/direct_udp.rs:250,270`),
//!   HDLC framing and IFAC included. The node tick folds those per-interface
//!   totals into [`WireBytes::add_interface`] as deltas, banked per interface
//!   id so a TCP client that disconnects keeps the bytes it carried
//!   ([`InterfaceFold`]). That is the per-transport total: what the interfaces
//!   carried.
//! - **Edge's attribution.** Every frame edge hands to a Reticulum link, or
//!   takes from one, passes the E1 transit seal
//!   ([`crate::transport::link_seal`]); edge counts it there, classified by its
//!   own frame tag ([`classify_link_frame`]) and its lane, in one atomic add.
//!   HTTP's application bytes are counted where the envelope crosses
//!   (`Edge::send`, `dispatch_inbound`).
//!
//! A snapshot reports, per transport, each attributed plane as counted and
//! `other` as **interface truth minus everything attributed** (never below the
//! frames explicitly counted `other`). So the planes of a transport sum to the
//! bytes its interfaces carried, every byte is in some plane, and a large
//! `other` is a finding, not noise: it is the bytes leviculum moved that edge
//! never handed it (relay, RNS announces and path requests, link keepalives,
//! requests and proofs, resource control and retransmits, packet and HDLC
//! framing) until leviculum exposes a per-packet hook (CIRISAI/leviculum#111)
//! — see [`classify_rns_packet`] for the classifier that hook would feed.
//!
//! # Cost and bounds
//!
//! One relaxed `fetch_add` per frame on a fixed array; no lock, no map, no
//! allocation. The label sets are closed ([`WireTransport::ALL`] ×
//! [`WirePlane::ALL`] = 11 × 11 cells a direction). No address, IP, port, link
//! or peer identifier is ever a key.

use std::sync::atomic::{AtomicU64, Ordering};

/// Which way a byte crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WireDir {
    /// Received.
    In = 0,
    /// Sent.
    Out = 1,
}

/// The medium a byte crossed. Closed: a new interface kind maps to `other`
/// until it is named here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WireTransport {
    /// Reticulum over TCP (client and server interfaces, spawned peers).
    Tcp = 0,
    /// Reticulum over a configured UDP interface.
    Udp = 1,
    /// A punched direct link (leviculum `DirectPeer/*` UDP interfaces).
    UdpDirect = 2,
    /// Reticulum over I2P.
    I2p = 3,
    /// Reticulum over an RNode or KISS radio.
    Lora = 4,
    /// Reticulum over a serial line.
    Serial = 5,
    /// Reticulum over BLE.
    Ble = 6,
    /// Reticulum AutoInterface (link-local multicast discovery).
    Auto = 7,
    /// A shared-instance local client.
    Local = 8,
    /// Edge's HTTP transport.
    Http = 9,
    /// Any other medium (pipe, host channel, unknown).
    Other = 10,
}

impl WireTransport {
    /// Every transport, in index order.
    pub const ALL: [Self; 11] = [
        Self::Tcp,
        Self::Udp,
        Self::UdpDirect,
        Self::I2p,
        Self::Lora,
        Self::Serial,
        Self::Ble,
        Self::Auto,
        Self::Local,
        Self::Http,
        Self::Other,
    ];
    /// How many transports.
    pub const COUNT: usize = Self::ALL.len();

    /// The stable label token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::UdpDirect => "udp-direct",
            Self::I2p => "i2p",
            Self::Lora => "lora",
            Self::Serial => "serial",
            Self::Ble => "ble",
            Self::Auto => "auto",
            Self::Local => "local",
            Self::Http => "http",
            Self::Other => "other",
        }
    }

    /// The transport of a leviculum interface, from its kind token
    /// (`InterfaceKind::as_str`) and name. A UDP interface named
    /// `DirectPeer/…` is a punched direct link (leviculum-std
    /// `interfaces/direct_udp.rs:107`); every other UDP interface is
    /// configured UDP. The name is read for that prefix only and never kept.
    #[must_use]
    pub fn of_interface(kind: &str, name: &str) -> Self {
        match kind {
            "tcp" => Self::Tcp,
            "udp" if name.starts_with("DirectPeer/") => Self::UdpDirect,
            "udp" => Self::Udp,
            "i2p" => Self::I2p,
            "rnode" | "kiss" => Self::Lora,
            "serial" => Self::Serial,
            "ble" => Self::Ble,
            "auto" => Self::Auto,
            "local" => Self::Local,
            _ => Self::Other,
        }
    }
}

/// What a byte was for. Closed; `other` must stay small, and when it does not
/// that is the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WirePlane {
    /// Federation envelopes (`Edge::send` / `dispatch_inbound`), link
    /// requests and responses, and any edge link frame with no tag of its own.
    Application = 0,
    /// Replication frames (`CRPL`), on any lane, and the `CFRG` fragments
    /// that carry them.
    Replication = 1,
    /// Reticulum Resource transfers of untagged payloads (envelopes, files).
    /// A Resource carrying a tagged frame (a `CRPL` Deliver) is counted under
    /// that frame's plane.
    Resource = 2,
    /// A/V: link datagrams, frames on an A/V link, and the A/V control tags
    /// (`CHLO`, `CSKB`, `CALM`).
    Av = 3,
    /// A node's identity advertisement: RNS announces (hook) and the
    /// announce and build-bundle link frames (`CANN`, `CBND`).
    Announce = 4,
    /// Path requests and path responses (hook).
    Path = 5,
    /// Link setup and upkeep: the transit KEX (`CTKX`), pre-seal route fetch
    /// (`CTKR`/`CTKA`), the shaping offer and referrals (`SHAP`, `SHRF`),
    /// fragment NAKs (`CNAK`), and — with the hook — link requests, proofs,
    /// keepalives, identify and close.
    LinkControl = 6,
    /// Frames this node forwards for others: onion layers (`CONP`) and — with
    /// the hook — transport-relayed packets.
    Relay = 7,
    /// NAT punch, probe and knock datagrams (hook).
    DirectLink = 8,
    /// Shaped-link frames (`SHPF`), real and cover alike. Not split further on
    /// purpose: real against cover is the activity shaping hides
    /// (`docs/TELEMETRY_CATALOGUE.md`, "Shaping's numbers"), and the sum is
    /// load-independent by construction.
    Shaped = 9,
    /// Everything else, and in a snapshot the interface bytes nothing above
    /// accounts for.
    Other = 10,
}

impl WirePlane {
    /// Every plane, in index order.
    pub const ALL: [Self; 11] = [
        Self::Application,
        Self::Replication,
        Self::Resource,
        Self::Av,
        Self::Announce,
        Self::Path,
        Self::LinkControl,
        Self::Relay,
        Self::DirectLink,
        Self::Shaped,
        Self::Other,
    ];
    /// How many planes.
    pub const COUNT: usize = Self::ALL.len();

    /// The stable label token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Replication => "replication",
            Self::Resource => "resource",
            Self::Av => "av",
            Self::Announce => "announce",
            Self::Path => "path",
            Self::LinkControl => "link_control",
            Self::Relay => "relay",
            Self::DirectLink => "direct_link",
            Self::Shaped => "shaped",
            Self::Other => "other",
        }
    }
}

type Cells = [[AtomicU64; WirePlane::COUNT]; WireTransport::COUNT];
type Row = [AtomicU64; WireTransport::COUNT];

/// The ledger: `[direction][transport][plane]` attributed bytes and
/// `[direction][transport]` interface truth, all atomics.
#[derive(Debug, Default)]
pub struct WireBytes {
    cells: [Cells; 2],
    interface: [Row; 2],
}

impl WireBytes {
    /// Count `bytes` edge attributed to `plane` on `transport`. One relaxed
    /// atomic add.
    pub fn add(&self, dir: WireDir, transport: WireTransport, plane: WirePlane, bytes: u64) {
        self.cells[dir as usize][transport as usize][plane as usize]
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Count `bytes` an interface of `transport` carried (interface truth).
    pub fn add_interface(&self, dir: WireDir, transport: WireTransport, bytes: u64) {
        self.interface[dir as usize][transport as usize].fetch_add(bytes, Ordering::Relaxed);
    }

    /// The attributed count of one cell, as counted (no residual).
    #[must_use]
    pub fn attributed(&self, dir: WireDir, transport: WireTransport, plane: WirePlane) -> u64 {
        self.cells[dir as usize][transport as usize][plane as usize].load(Ordering::Relaxed)
    }

    /// The interface truth of one transport.
    #[must_use]
    pub fn interface_total(&self, dir: WireDir, transport: WireTransport) -> u64 {
        self.interface[dir as usize][transport as usize].load(Ordering::Relaxed)
    }

    /// A reading, with each transport's `other` resolved against its
    /// interface truth (module docs).
    #[must_use]
    pub fn snapshot(&self) -> WireBytesSnapshot {
        let mut out = WireBytesSnapshot::default();
        for dir in [WireDir::In, WireDir::Out] {
            for t in WireTransport::ALL {
                let mut attributed = 0u64;
                for p in WirePlane::ALL {
                    let v = self.attributed(dir, t, p);
                    out.cells[dir as usize][t as usize][p as usize] = v;
                    if p != WirePlane::Other {
                        attributed = attributed.saturating_add(v);
                    }
                }
                let truth = self.interface_total(dir, t);
                out.interface[dir as usize][t as usize] = truth;
                let explicit = out.cells[dir as usize][t as usize][WirePlane::Other as usize];
                let residual = truth.saturating_sub(attributed);
                out.cells[dir as usize][t as usize][WirePlane::Other as usize] =
                    residual.max(explicit);
                out.overrun[dir as usize][t as usize] = if truth == 0 {
                    0
                } else {
                    attributed.saturating_add(explicit).saturating_sub(truth)
                };
            }
        }
        out
    }
}

/// One reading of [`WireBytes`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WireBytesSnapshot {
    /// `[direction][transport][plane]`, `other` resolved.
    pub cells: [[[u64; WirePlane::COUNT]; WireTransport::COUNT]; 2],
    /// `[direction][transport]` interface truth.
    pub interface: [[u64; WireTransport::COUNT]; 2],
    /// `[direction][transport]` bytes attributed past the interface truth
    /// (a sealed frame counted before its interface wrote it, or a frame on a
    /// link whose medium the seal guessed wrong). Zero for a transport with no
    /// interface truth.
    pub overrun: [[u64; WireTransport::COUNT]; 2],
}

impl WireBytesSnapshot {
    /// One cell.
    #[must_use]
    pub fn get(&self, dir: WireDir, transport: WireTransport, plane: WirePlane) -> u64 {
        self.cells[dir as usize][transport as usize][plane as usize]
    }

    /// The bundle family for `dir`: keys `transport:plane`. A transport that
    /// carried and was attributed nothing is left out; one that did lists
    /// every plane, so a 0 there is a plane that moved nothing.
    #[must_use]
    pub fn family(&self, dir: WireDir) -> std::collections::BTreeMap<String, u64> {
        let mut out = std::collections::BTreeMap::new();
        for t in WireTransport::ALL {
            let row = &self.cells[dir as usize][t as usize];
            if row.iter().all(|v| *v == 0) && self.interface[dir as usize][t as usize] == 0 {
                continue;
            }
            for p in WirePlane::ALL {
                out.insert(format!("{}:{}", t.as_str(), p.as_str()), row[p as usize]);
            }
        }
        out
    }
}

/// Folds leviculum's per-interface byte totals into interface truth as
/// deltas. Runs on the node tick, never per packet. Each interface's last
/// reading is kept by id, so an interface that disappears (a TCP client gone)
/// keeps every byte up to the last fold; what it carried after that fold and
/// before it went is not seen (leviculum drops the counters with the
/// interface and banks them in its private inventory, `driver/mod.rs`
/// `retire_from_inventory`). At the one-second node tick that is at most a
/// second of one departing connection.
#[derive(Debug, Default)]
pub struct InterfaceFold {
    last: std::sync::Mutex<std::collections::HashMap<usize, (u64, u64)>>,
}

impl InterfaceFold {
    /// Fold one reading: `(interface id, transport, rx_bytes, tx_bytes)` for
    /// every live interface. A counter that went backwards (an id reused)
    /// folds its whole value as new.
    pub fn fold(
        &self,
        wire: &WireBytes,
        now: impl IntoIterator<Item = (usize, WireTransport, u64, u64)>,
    ) {
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut next = std::collections::HashMap::with_capacity(last.len());
        for (id, transport, rx, tx) in now {
            let (was_rx, was_tx) = last.get(&id).copied().unwrap_or((0, 0));
            let d_rx = if rx >= was_rx { rx - was_rx } else { rx };
            let d_tx = if tx >= was_tx { tx - was_tx } else { tx };
            if d_rx > 0 {
                wire.add_interface(WireDir::In, transport, d_rx);
            }
            if d_tx > 0 {
                wire.add_interface(WireDir::Out, transport, d_tx);
            }
            next.insert(id, (rx, tx));
        }
        *last = next;
    }
}

/// Edge's link-frame tags (pinned against their owning modules in the tests).
mod tag {
    pub const REPLICATION: [u8; 4] = *b"CRPL";
    pub const FRAGMENT: [u8; 4] = *b"CFRG";
    pub const NAK: [u8; 4] = *b"CNAK";
    pub const HANDSHAKE: [u8; 4] = *b"CTKX";
    pub const ROUTE_REQUEST: [u8; 4] = *b"CTKR";
    pub const ROUTE_ANSWER: [u8; 4] = *b"CTKA";
    pub const SHAPING_OFFER: [u8; 4] = *b"SHAP";
    pub const SHAPED_FRAME: [u8; 4] = *b"SHPF";
    pub const SHAPING_CAP: [u8; 4] = *b"SHCP";
    pub const REFERRAL: [u8; 4] = *b"SHRF";
    pub const ANNOUNCE: [u8; 4] = *b"CANN";
    pub const PEER_BUNDLE: [u8; 4] = *b"CBND";
    pub const ONION: [u8; 4] = *b"CONP";
    pub const AV_HELLO: [u8; 4] = *b"CHLO";
    pub const AV_BINDING: [u8; 4] = *b"CSKB";
    pub const AV_CONTROL: [u8; 4] = *b"CALM";
    /// `magic[4] ‖ msg_id[8] ‖ total u16 ‖ index u16`.
    pub const FRAGMENT_HEADER_LEN: usize = 16;
}

/// The plane of one edge link frame's PLAINTEXT (after the seal opens, or
/// before it seals), by its tag. A frame with no tag of its own is an
/// envelope: `application`. A `CFRG` fragment is resolved through
/// [`FragmentPlanes`]: its first piece carries the frame's own tag, and the
/// rest follow it.
#[must_use]
pub fn classify_link_frame(plain: &[u8], fragments: &FragmentPlanes) -> WirePlane {
    let Some(head) = plain.get(..4) else {
        return WirePlane::Application;
    };
    let head: [u8; 4] = [head[0], head[1], head[2], head[3]];
    match head {
        tag::REPLICATION => WirePlane::Replication,
        tag::FRAGMENT => fragments.classify(plain),
        tag::NAK
        | tag::HANDSHAKE
        | tag::ROUTE_REQUEST
        | tag::ROUTE_ANSWER
        | tag::SHAPING_OFFER
        | tag::SHAPING_CAP
        | tag::REFERRAL => WirePlane::LinkControl,
        tag::SHAPED_FRAME => WirePlane::Shaped,
        tag::ANNOUNCE | tag::PEER_BUNDLE => WirePlane::Announce,
        tag::ONION => WirePlane::Relay,
        tag::AV_HELLO | tag::AV_BINDING | tag::AV_CONTROL => WirePlane::Av,
        _ => WirePlane::Application,
    }
}

/// The unsealed link frames (the transit KEX parts and the pre-seal route
/// fetch): `link_control` when tagged so, else `None`.
#[must_use]
pub fn unsealed_control(frame: &[u8]) -> Option<WirePlane> {
    match frame.get(..4)? {
        b"CTKX" | b"CTKR" | b"CTKA" => Some(WirePlane::LinkControl),
        _ => None,
    }
}

/// Slots in [`FragmentPlanes`].
const FRAGMENT_SLOTS: usize = 256;

/// Which plane each in-flight `CFRG` frame belongs to, so a fragment after the
/// first is counted where its frame is. A direct-mapped table of atomics,
/// keyed by the fragment's 8-byte msg id: slot = id byte 0, value = the other
/// seven id bytes and the plane. Lock-free; a collision or a fragment whose
/// first piece was never seen reads `other` (counted, never guessed). 256
/// slots of 8 bytes, fixed.
#[derive(Debug)]
pub struct FragmentPlanes {
    slots: [AtomicU64; FRAGMENT_SLOTS],
}

impl Default for FragmentPlanes {
    fn default() -> Self {
        Self {
            slots: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl FragmentPlanes {
    fn key(id: &[u8]) -> (usize, u64) {
        let mut tag = 0u64;
        for b in &id[1..8] {
            tag = (tag << 8) | u64::from(*b);
        }
        (usize::from(id[0]), tag << 8)
    }

    /// The plane of a `CFRG` fragment: its first piece (index 0) is
    /// classified by the frame tag it starts with and remembered; later
    /// pieces read what the first stored.
    pub fn classify(&self, frag: &[u8]) -> WirePlane {
        if frag.len() < tag::FRAGMENT_HEADER_LEN {
            return WirePlane::Other;
        }
        let (slot, tag) = Self::key(&frag[4..12]);
        let index = u16::from_be_bytes([frag[14], frag[15]]);
        if index == 0 {
            let body = &frag[tag::FRAGMENT_HEADER_LEN..];
            // A fragment never nests a fragment; a body that claims to is not
            // a frame this table can name.
            let plane = if body.starts_with(&tag::FRAGMENT) {
                WirePlane::Other
            } else {
                classify_link_frame(body, self)
            };
            self.slots[slot].store(tag | plane as u64, Ordering::Relaxed);
            return plane;
        }
        let v = self.slots[slot].load(Ordering::Relaxed);
        if v & !0xff == tag {
            plane_of_index(usize::try_from(v & 0xff).unwrap_or(usize::MAX))
        } else {
            WirePlane::Other
        }
    }
}

fn plane_of_index(i: usize) -> WirePlane {
    WirePlane::ALL.get(i).copied().unwrap_or(WirePlane::Other)
}

/// What a raw Reticulum packet is, read from its header alone — the
/// classifier a per-packet leviculum hook would feed. leviculum exposes no
/// such hook at v0.34.0+ciris.3; the hook, and byte totals that survive an
/// interface's retirement, are CIRISAI/leviculum#111.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RnsClass {
    /// A plane the header decides.
    Plane(WirePlane),
    /// Link payload whose plane only edge knows (a Channel message, link
    /// data, a request or response, a datagram): the bytes edge's seal-level
    /// attribution already put in a plane, plus this packet's framing.
    LinkPayload,
}

/// Classify one raw Reticulum packet (IFAC already removed) from its header.
/// `forwarded` is the driver's own knowledge that the packet is being relayed
/// for someone else (a header cannot say that on the receive side). Rules:
///
/// - forwarded, and not an announce → `relay`;
/// - an announce whose context is PATH_RESPONSE (`0x0B`) → `path`; any other
///   announce → `announce`;
/// - a link request, and any proof that is not a resource proof → `link_control`;
/// - DATA to a PLAIN destination (path requests and the other
///   `rnstransport.*` control destinations) → `path`;
/// - DATA on a link: resource contexts `0x01..=0x07` (and a resource proof,
///   `0x05`) → `resource`; keepalive, identify, close, link proof and RTT
///   (`0xFA..=0xFE`) → `link_control`; the datagram context `0xF0` → `av`;
///   anything else (Channel `0x0E`, request `0x09`, response `0x0A`, plain
///   link data) → [`RnsClass::LinkPayload`];
/// - anything shorter than a header → `other`.
#[must_use]
pub fn classify_rns_packet(packet: &[u8], forwarded: bool) -> RnsClass {
    const PT_ANNOUNCE: u8 = 1;
    const PT_LINKREQUEST: u8 = 2;
    const PT_PROOF: u8 = 3;
    const DT_PLAIN: u8 = 2;
    const DT_LINK: u8 = 3;
    let Some(&flags) = packet.first() else {
        return RnsClass::Plane(WirePlane::Other);
    };
    let header2 = flags & 0b0100_0000 != 0;
    let context_at = if header2 { 2 + 16 + 16 } else { 2 + 16 };
    let Some(&context) = packet.get(context_at) else {
        return RnsClass::Plane(WirePlane::Other);
    };
    let packet_type = flags & 0b11;
    let dest_type = (flags >> 2) & 0b11;
    if forwarded && packet_type != PT_ANNOUNCE {
        return RnsClass::Plane(WirePlane::Relay);
    }
    let plane = match packet_type {
        PT_ANNOUNCE if context == 0x0B => WirePlane::Path,
        PT_ANNOUNCE => WirePlane::Announce,
        PT_PROOF if context == 0x05 => WirePlane::Resource,
        PT_LINKREQUEST | PT_PROOF => WirePlane::LinkControl,
        _ if dest_type == DT_PLAIN => WirePlane::Path,
        _ if dest_type == DT_LINK => match context {
            0x01..=0x07 => WirePlane::Resource,
            0xFA..=0xFE => WirePlane::LinkControl,
            0xF0 => WirePlane::Av,
            _ => return RnsClass::LinkPayload,
        },
        _ => return RnsClass::LinkPayload,
    };
    RnsClass::Plane(plane)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frag(id: [u8; 8], total: u16, index: u16, body: &[u8]) -> Vec<u8> {
        let mut f = b"CFRG".to_vec();
        f.extend_from_slice(&id);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&index.to_be_bytes());
        f.extend_from_slice(body);
        f
    }

    #[test]
    fn link_frame_tags_name_their_planes() {
        let t = FragmentPlanes::default();
        let cases: [(&[u8], WirePlane); 18] = [
            (b"CRPL\x01{}", WirePlane::Replication),
            (b"CNAK........", WirePlane::LinkControl),
            (b"CTKX\x01", WirePlane::LinkControl),
            (b"CTKR\x01", WirePlane::LinkControl),
            (b"CTKA\x01", WirePlane::LinkControl),
            (b"SHAP\x01", WirePlane::LinkControl),
            (b"SHCP\x01", WirePlane::LinkControl),
            (b"SHRF\x01", WirePlane::LinkControl),
            (b"SHPF\x01\x00\x00\x00", WirePlane::Shaped),
            (b"SHPF\x01\x01\x00\x04CRPL", WirePlane::Shaped),
            (b"CANN\x01", WirePlane::Announce),
            (b"CBND\x01", WirePlane::Announce),
            (b"CONP\x01", WirePlane::Relay),
            (b"CHLO\x01", WirePlane::Av),
            (b"CSKB\x01", WirePlane::Av),
            (b"CALM\x01", WirePlane::Av),
            (b"{\"message_type\":\"X\"}", WirePlane::Application),
            (b"ab", WirePlane::Application),
        ];
        for (frame, want) in cases {
            assert_eq!(classify_link_frame(frame, &t), want, "{frame:?}");
        }
    }

    #[test]
    fn fragments_follow_their_first_piece() {
        let t = FragmentPlanes::default();
        let a = [7, 1, 2, 3, 4, 5, 6, 7];
        let b = [7, 9, 9, 9, 9, 9, 9, 9];
        assert_eq!(
            classify_link_frame(&frag(a, 3, 0, b"CRPL\x01{"), &t),
            WirePlane::Replication
        );
        assert_eq!(
            classify_link_frame(&frag(a, 3, 1, b"xx"), &t),
            WirePlane::Replication
        );
        assert_eq!(
            classify_link_frame(&frag(a, 3, 2, b"xx"), &t),
            WirePlane::Replication
        );
        // Same slot, other id: never borrows a's plane.
        assert_eq!(
            classify_link_frame(&frag(b, 2, 1, b"xx"), &t),
            WirePlane::Other
        );
        // An envelope's fragments are application.
        assert_eq!(
            classify_link_frame(&frag(b, 2, 0, b"{\"a\":1}"), &t),
            WirePlane::Application
        );
        assert_eq!(
            classify_link_frame(&frag(b, 2, 1, b"}"), &t),
            WirePlane::Application
        );
        // a's slot was taken by b: a's late piece is other, not b's plane.
        assert_eq!(
            classify_link_frame(&frag(a, 3, 2, b"xx"), &t),
            WirePlane::Other
        );
        // A truncated header is other.
        assert_eq!(classify_link_frame(b"CFRG\x00\x01", &t), WirePlane::Other);
    }

    #[test]
    fn unsealed_control_is_the_kex_and_route_fetch_only() {
        assert_eq!(unsealed_control(b"CTKX.."), Some(WirePlane::LinkControl));
        assert_eq!(unsealed_control(b"CTKR.."), Some(WirePlane::LinkControl));
        assert_eq!(unsealed_control(b"CTKA.."), Some(WirePlane::LinkControl));
        assert_eq!(unsealed_control(b"CRPL.."), None);
        assert_eq!(unsealed_control(b"CT"), None);
    }

    fn rns(flags: u8, header2: bool, context: u8) -> Vec<u8> {
        let mut p = vec![flags | if header2 { 0x40 } else { 0 }, 0];
        p.extend_from_slice(&[0u8; 16]);
        if header2 {
            p.extend_from_slice(&[0u8; 16]);
        }
        p.push(context);
        p.extend_from_slice(b"payload");
        p
    }

    #[test]
    fn rns_header_classifier_covers_every_plane_it_can_see() {
        use RnsClass::{LinkPayload, Plane};
        use WirePlane as P;
        let data_link = 0b11 << 2;
        let data_plain = 0b10 << 2;
        let cases = [
            (rns(1, false, 0x00), false, Plane(P::Announce)),
            (rns(1, true, 0x00), true, Plane(P::Announce)),
            (rns(1, false, 0x0B), false, Plane(P::Path)),
            (rns(2, false, 0x00), false, Plane(P::LinkControl)),
            (
                rns(3 | data_link, false, 0xFF),
                false,
                Plane(P::LinkControl),
            ),
            (
                rns(3 | data_link, false, 0x00),
                false,
                Plane(P::LinkControl),
            ),
            (rns(3 | data_link, false, 0x05), false, Plane(P::Resource)),
            (rns(data_plain, false, 0x00), false, Plane(P::Path)),
            (rns(data_link, false, 0x01), false, Plane(P::Resource)),
            (rns(data_link, false, 0x02), false, Plane(P::Resource)),
            (rns(data_link, false, 0x07), false, Plane(P::Resource)),
            (rns(data_link, false, 0xFA), false, Plane(P::LinkControl)),
            (rns(data_link, false, 0xFB), false, Plane(P::LinkControl)),
            (rns(data_link, false, 0xFC), false, Plane(P::LinkControl)),
            (rns(data_link, false, 0xFE), false, Plane(P::LinkControl)),
            (rns(data_link, false, 0xF0), false, Plane(P::Av)),
            (rns(data_link, false, 0x0E), false, LinkPayload),
            (rns(data_link, false, 0x09), false, LinkPayload),
            (rns(data_link, true, 0x0E), false, LinkPayload),
            (rns(data_link, true, 0x0E), true, Plane(P::Relay)),
            (rns(0, false, 0x00), false, LinkPayload),
        ];
        for (packet, forwarded, want) in cases {
            assert_eq!(
                classify_rns_packet(&packet, forwarded),
                want,
                "flags {:#04x} forwarded {forwarded}",
                packet[0]
            );
        }
        assert_eq!(classify_rns_packet(&[], false), Plane(P::Other));
        assert_eq!(
            classify_rns_packet(&[0x0C, 0, 1, 2], false),
            Plane(P::Other)
        );
    }

    #[test]
    fn interface_names_map_to_closed_transports() {
        use WireTransport as T;
        assert_eq!(T::of_interface("tcp", "TCPServer/peer"), T::Tcp);
        assert_eq!(T::of_interface("udp", "DirectPeer/0a0b0c0d"), T::UdpDirect);
        assert_eq!(T::of_interface("udp", "UDPInterface"), T::Udp);
        assert_eq!(T::of_interface("rnode", "x"), T::Lora);
        assert_eq!(T::of_interface("kiss", "x"), T::Lora);
        assert_eq!(T::of_interface("local", "x"), T::Local);
        assert_eq!(T::of_interface("pipe", "x"), T::Other);
        assert_eq!(T::of_interface("unknown", "x"), T::Other);
    }

    #[test]
    fn snapshot_other_is_the_residual_and_planes_sum_to_the_interfaces() {
        let w = WireBytes::default();
        w.add(
            WireDir::Out,
            WireTransport::Tcp,
            WirePlane::Replication,
            600,
        );
        w.add(WireDir::Out, WireTransport::Tcp, WirePlane::Shaped, 300);
        w.add_interface(WireDir::Out, WireTransport::Tcp, 1_000);
        let s = w.snapshot();
        assert_eq!(
            s.get(WireDir::Out, WireTransport::Tcp, WirePlane::Other),
            100
        );
        let sum: u64 = WirePlane::ALL
            .iter()
            .map(|p| s.get(WireDir::Out, WireTransport::Tcp, *p))
            .sum();
        assert_eq!(sum, 1_000);
        assert_eq!(
            s.overrun[WireDir::Out as usize][WireTransport::Tcp as usize],
            0
        );
        // HTTP has no interface truth: its planes are what was counted.
        w.add(WireDir::In, WireTransport::Http, WirePlane::Application, 42);
        let s = w.snapshot();
        assert_eq!(
            s.get(WireDir::In, WireTransport::Http, WirePlane::Application),
            42
        );
        assert_eq!(s.get(WireDir::In, WireTransport::Http, WirePlane::Other), 0);
        let fam = s.family(WireDir::In);
        assert_eq!(fam.len(), WirePlane::COUNT, "only http carried anything in");
        assert_eq!(fam["http:application"], 42);
        assert_eq!(fam["http:relay"], 0);
    }

    #[test]
    fn snapshot_reports_overrun_and_never_a_negative_other() {
        let w = WireBytes::default();
        w.add(WireDir::In, WireTransport::Tcp, WirePlane::Application, 500);
        w.add(WireDir::In, WireTransport::Tcp, WirePlane::Other, 20);
        w.add_interface(WireDir::In, WireTransport::Tcp, 400);
        let s = w.snapshot();
        assert_eq!(s.get(WireDir::In, WireTransport::Tcp, WirePlane::Other), 20);
        assert_eq!(
            s.overrun[WireDir::In as usize][WireTransport::Tcp as usize],
            120
        );
    }

    #[test]
    fn interface_fold_banks_departed_interfaces_and_takes_deltas() {
        let w = WireBytes::default();
        let f = InterfaceFold::default();
        f.fold(
            &w,
            [
                (1, WireTransport::Tcp, 100, 10),
                (2, WireTransport::UdpDirect, 5, 5),
            ],
        );
        f.fold(&w, [(1, WireTransport::Tcp, 150, 30)]);
        // Interface 2 went away: its 5/5 stay; a new id 3 counts from zero.
        f.fold(
            &w,
            [
                (1, WireTransport::Tcp, 150, 30),
                (3, WireTransport::Tcp, 7, 0),
            ],
        );
        assert_eq!(w.interface_total(WireDir::In, WireTransport::Tcp), 157);
        assert_eq!(w.interface_total(WireDir::Out, WireTransport::Tcp), 30);
        assert_eq!(w.interface_total(WireDir::In, WireTransport::UdpDirect), 5);
        // A counter that went backwards is a reused id: its value is new.
        f.fold(&w, [(1, WireTransport::Tcp, 4, 30)]);
        assert_eq!(w.interface_total(WireDir::In, WireTransport::Tcp), 161);
    }

    #[cfg(feature = "_reticulum-module")]
    #[test]
    fn tags_match_their_owning_modules() {
        use crate::transport as t;
        assert_eq!(
            tag::REPLICATION,
            crate::replication::wire_frame::REPLICATION_FRAME_MAGIC
        );
        assert_eq!(tag::FRAGMENT, t::frame_fragment::FRAGMENT_MAGIC);
        assert_eq!(tag::NAK, t::frame_fragment::NAK_MAGIC);
        assert_eq!(
            tag::FRAGMENT_HEADER_LEN,
            t::frame_fragment::FRAGMENT_HEADER_LEN
        );
        assert_eq!(tag::HANDSHAKE, t::av_transit_handshake::HANDSHAKE_MAGIC);
        assert_eq!(tag::ROUTE_REQUEST, t::route_fetch::ROUTE_REQUEST_MAGIC);
        assert_eq!(tag::ROUTE_ANSWER, t::route_fetch::ROUTE_ANSWER_MAGIC);
        assert_eq!(tag::SHAPING_OFFER, t::link_shaping::OFFER_MAGIC);
        assert_eq!(tag::SHAPED_FRAME, t::link_shaping::FRAME_MAGIC);
        assert_eq!(tag::SHAPING_CAP, t::link_shaping::CAP_MAGIC);
        assert_eq!(tag::REFERRAL, t::shaping_referral::REFERRAL_MAGIC);
        assert_eq!(tag::ANNOUNCE, t::announce_frame::ANNOUNCE_FRAME_MAGIC);
        assert_eq!(tag::PEER_BUNDLE, t::peer_bundle_frame::PEER_BUNDLE_MAGIC);
        assert_eq!(tag::ONION, crate::onion::relay::ONION_FRAME_MAGIC);
        assert_eq!(tag::AV_HELLO, t::av_call::STREAM_HELLO_MAGIC);
        assert_eq!(tag::AV_BINDING, t::av_chunk_auth::BINDING_PART_MAGIC);
        assert_eq!(
            tag::AV_CONTROL,
            t::realtime_av_alm::controller::wire::CONTROL_MAGIC
        );
    }
}

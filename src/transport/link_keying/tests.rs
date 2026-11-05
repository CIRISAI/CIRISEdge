use super::*;
use crate::observability as o;
use crate::transport::link_seal::{Inbound, Lane};
use crate::transport::route_fetch::ROUTE_REQUESTS_PER_WINDOW;
use crate::transport::transit_kex_custody::TransitKexSecret;
use std::time::Duration;

fn stranger(id: &str) -> Sender<'_> {
    Sender {
        identity: Some(id),
        standing: false,
    }
}

fn label(r: Result<(), SealRefusal>) -> &'static str {
    r.expect_err("refused").label()
}

#[test]
fn a_sender_over_its_rate_spends_none_of_the_node_budget_947() {
    let order = ReceiverOrder::default();
    for _ in 0..HANDSHAKES_PER_STRANGER {
        order.admit(stranger("one")).expect("within its rate");
    }
    order.set_stranger_cap(u32::try_from(HANDSHAKES_PER_STRANGER).unwrap() + 1);
    for _ in 0..1000 {
        assert_eq!(
            label(order.admit(stranger("one"))),
            o::LINK_SEAL_REFUSED_HANDSHAKE_SENDER_RATE
        );
    }
    order
        .admit(stranger("two"))
        .expect("the flood left the last node slot");
    assert_eq!(
        label(order.admit(stranger("three"))),
        o::LINK_SEAL_REFUSED_HANDSHAKE_NODE_RATE
    );
}

#[test]
fn unidentified_links_share_one_slot_947() {
    let order = ReceiverOrder::default();
    let none = Sender {
        identity: None,
        standing: false,
    };
    for _ in 0..HANDSHAKES_UNIDENTIFIED {
        order.admit(none).expect("within the shared slot");
    }
    assert_eq!(
        label(order.admit(none)),
        o::LINK_SEAL_REFUSED_HANDSHAKE_SENDER_RATE
    );
    order
        .admit(stranger("identified"))
        .expect("an identified stranger is not in that slot");
}

#[test]
fn a_stranger_flood_leaves_standing_its_own_budget_947() {
    let order = ReceiverOrder::default();
    order.set_stranger_cap(1);
    order.admit(stranger("a")).expect("the one slot");
    assert_eq!(
        label(order.admit(stranger("b"))),
        o::LINK_SEAL_REFUSED_HANDSHAKE_NODE_RATE
    );
    order
        .admit(Sender {
            identity: Some("known"),
            standing: true,
        })
        .expect("standing draws on its own budget");
}

#[test]
fn a_fresh_identity_flood_stays_bounded_past_the_sender_table_947() {
    let order = ReceiverOrder::default();
    let mut admitted = 0_u32;
    for i in 0..(crate::transport::route_fetch::ROUTE_SENDERS_TRACKED * 2) {
        if order.admit(stranger(&format!("sybil-{i}"))).is_ok() {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, HANDSHAKES_STRANGER_NODE,
        "the node-wide rate is what bounds fresh identities"
    );
}

// Every stranger a route fetch lets through can also key.
const _: () = assert!(HANDSHAKES_STRANGER_NODE >= ROUTE_REQUESTS_PER_WINDOW);

fn seals() -> Arc<LinkSeals> {
    Arc::new(LinkSeals::new(
        TransitKexSecret::from_root_seed(&[0x22; 64]).expect("transit secret"),
        "dialled-key",
    ))
}

/// A real handshake's job on `link`.
fn job(s: &LinkSeals, link: [u8; 16]) -> HandshakeJob {
    let dialler = LinkSeals::new(
        TransitKexSecret::from_root_seed(&[0x11; 64]).expect("transit secret"),
        "dialler-key",
    );
    let (frames, _) = dialler
        .initiate(link, "dialler-key", "dialled-key", s.secret().pair(), 400)
        .expect("initiate");
    assert!(s.begin_responder(link));
    let mut out = None;
    for f in frames {
        if let Inbound::Handshake(j) = s.inbound(link, Lane::Channel, &f, false, None) {
            out = Some(j);
        }
    }
    out.expect("a whole handshake")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_queue_never_grows_past_its_bound_947() {
    let s = seals();
    s.set_decap_delay(Duration::from_millis(50));
    let (keyer, mut done) = Keyer::new(Arc::clone(&s));
    let mut admitted = 0_usize;
    let mut saturated = 0_usize;
    for i in 0..(DECAP_QUEUE_STRANGER + keyer.workers() + 20) {
        let link = [u8::try_from(i).unwrap(); 16];
        match keyer.submit(job(&s, link), false) {
            Ok(()) => admitted += 1,
            Err(r) => {
                assert_eq!(r.label(), o::LINK_SEAL_REFUSED_DECAP_SATURATED);
                saturated += 1;
            }
        }
        assert!(keyer.depth() <= DECAP_QUEUE_STRANGER);
    }
    assert!(saturated > 0, "a stated refusal, not a growing queue");
    for _ in 0..admitted {
        let d = done.recv().await.expect("every admitted job answers");
        assert!(d.outcome.is_ok());
    }
    assert_eq!(keyer.depth(), 0);
    s.set_decap_delay(Duration::ZERO);
    // The pool came back down and still takes work.
    keyer.submit(job(&s, [0xfe; 16]), false).expect("room");
    assert!(done.recv().await.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standing_is_drained_first_and_has_room_in_a_full_stranger_queue_947() {
    let s = seals();
    let (keyer, mut done) = Keyer::new(Arc::clone(&s));
    // Built first: a job's own KEX must not run out the clock below.
    let jobs: Vec<HandshakeJob> = (0..(DECAP_QUEUE_STRANGER + keyer.workers()))
        .map(|i| job(&s, [u8::try_from(i).unwrap(); 16]))
        .collect();
    let known = job(&s, [0xfd; 16]);
    s.set_decap_delay(Duration::from_millis(200));
    let mut jobs = jobs.into_iter();
    for j in jobs.by_ref().take(keyer.workers()) {
        keyer.submit(j, false).expect("room");
    }
    // Every worker holds a job before the queue is filled behind them.
    while keyer.depth() > 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    for j in jobs {
        keyer.submit(j, false).expect("the queue holds them");
    }
    assert_eq!(
        keyer.depth(),
        DECAP_QUEUE_STRANGER,
        "the stranger queue is full"
    );
    keyer.submit(known, true).expect("a separate queue");
    // The jobs already running finish; the very next is standing's.
    let mut seen = Vec::new();
    for _ in 0..=keyer.workers() {
        seen.push(done.recv().await.expect("an outcome").link);
    }
    s.set_decap_delay(Duration::ZERO);
    assert_eq!(seen.last(), Some(&[0xfd; 16]), "order {seen:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dead_link_in_the_queue_costs_no_decapsulation_947() {
    let s = seals();
    let (keyer, mut done) = Keyer::new(Arc::clone(&s));
    let dead = job(&s, [1; 16]);
    let live = job(&s, [2; 16]);
    s.forget(&[1; 16]);
    keyer.submit(dead, false).expect("room");
    keyer.submit(live, false).expect("room");
    let d = done.recv().await.expect("the live job");
    assert_eq!(d.link, [2; 16]);
    assert_eq!(s.decapsulations(), 1);
}

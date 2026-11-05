use super::*;
use crate::observability as o;
use crate::transport::link_seal::{Inbound, Lane, SealRefusal};
use crate::transport::route_fetch::ROUTE_REQUESTS_PER_WINDOW;
use crate::transport::transit_kex_custody::TransitKexSecret;

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

/// A pool that starts no worker of its own: what is queued stays queued until
/// the test runs a worker, so nothing here depends on a clock.
fn stopped_pool(s: &Arc<LinkSeals>) -> (Arc<Keyer>, mpsc::UnboundedReceiver<KeyingDone>) {
    Keyer::with_workers(Arc::clone(s), 0)
}

/// Run one worker until the queues are empty.
fn run_worker(keyer: &Keyer) {
    keyer.queues().running += 1;
    keyer.drain();
}

#[test]
fn the_queue_never_grows_past_its_bound_947() {
    let s = seals();
    let (keyer, mut done) = stopped_pool(&s);
    let mut admitted = 0_usize;
    for i in 0..(DECAP_QUEUE_STRANGER + 20) {
        match keyer.submit(job(&s, [u8::try_from(i).unwrap(); 16]), false) {
            Ok(()) => admitted += 1,
            Err(r) => assert_eq!(r.label(), o::LINK_SEAL_REFUSED_DECAP_SATURATED),
        }
    }
    assert_eq!(
        admitted, DECAP_QUEUE_STRANGER,
        "refused by name past the bound"
    );
    assert_eq!(keyer.depth(), DECAP_QUEUE_STRANGER);
    run_worker(&keyer);
    assert_eq!(keyer.depth(), 0);
    for _ in 0..admitted {
        let d = done.try_recv().expect("every admitted job answers");
        assert!(d.outcome.is_ok());
    }
    keyer
        .submit(job(&s, [0xfe; 16]), false)
        .expect("room again");
    assert_eq!(keyer.queues().running, 0, "the worker came back down");
}

#[test]
fn standing_is_drained_first_and_has_room_in_a_full_stranger_queue_947() {
    let s = seals();
    let (keyer, mut done) = stopped_pool(&s);
    for i in 0..DECAP_QUEUE_STRANGER {
        keyer
            .submit(job(&s, [u8::try_from(i).unwrap(); 16]), false)
            .expect("the queue holds them");
    }
    assert!(keyer
        .submit(job(&s, [0xfc; 16]), false)
        .is_err_and(|r| matches!(r, SealRefusal::DecapSaturated { standing: false })));
    let known = [0xfd; 16];
    keyer
        .submit(job(&s, known), true)
        .expect("standing has a queue of its own");
    run_worker(&keyer);
    assert_eq!(
        done.try_recv().expect("an outcome").link,
        known,
        "the last in is the first out"
    );
    assert_eq!(done.try_recv().expect("then the strangers").link, [0; 16]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pool_starts_its_own_workers_and_lets_them_end_947() {
    let s = seals();
    let (keyer, mut done) = Keyer::new(Arc::clone(&s));
    for i in 0..8 {
        keyer
            .submit(job(&s, [i; 16]), false)
            .expect("the queue has room");
    }
    for _ in 0..8 {
        let d = done.recv().await.expect("every admitted job answers");
        assert!(d.outcome.is_ok());
    }
    assert_eq!(keyer.depth(), 0);
    while keyer.queues().running > 0 {
        tokio::task::yield_now().await;
    }
    keyer.submit(job(&s, [0xfe; 16]), false).expect("room");
    assert!(
        done.recv().await.is_some(),
        "a later job starts a worker again"
    );
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

fn bag(keyer: &Keyer) -> crate::observability::EdgeMetrics {
    let m = crate::observability::EdgeMetrics::new();
    keyer.attach_metrics(m.clone());
    m
}

/// v44 — `panicked` had no reader: the catch kept the worker and the count
/// went nowhere. It reaches the bag the host reads now.
#[test]
fn a_keyer_panic_reaches_the_bag_and_the_worker_lives() {
    let s = seals();
    let (keyer, mut done) = stopped_pool(&s);
    let m = bag(&keyer);
    let key = o::LINK_SEAL_KEYER_PANICKED;
    assert_eq!(m.snapshot().link_seal[key], 0, "a series before it happens");
    s.decap_panics
        .store(true, std::sync::atomic::Ordering::Relaxed);
    keyer.submit(job(&s, [1; 16]), false).expect("room");
    keyer.submit(job(&s, [2; 16]), false).expect("room");
    run_worker(&keyer);
    assert_eq!(m.snapshot().link_seal[key], 1);
    assert!(done.try_recv().expect("refused").outcome.is_err());
    assert!(done.try_recv().expect("the worker lived").outcome.is_ok());
}

#[test]
fn a_stale_job_is_counted_and_never_reaches_the_event_loop() {
    let s = seals();
    let (keyer, mut done) = stopped_pool(&s);
    let m = bag(&keyer);
    let dead = job(&s, [1; 16]);
    s.forget(&[1; 16]);
    keyer.submit(dead, false).expect("room");
    run_worker(&keyer);
    assert_eq!(m.snapshot().link_seal[o::LINK_SEAL_KEYING_SKIPPED_STALE], 1);
    assert!(done.try_recv().is_err());
}

/// The gauges read the queues as they are, by budget, and fall with them.
#[test]
fn the_keyer_gauges_follow_the_queues() {
    let s = seals();
    let (keyer, mut done) = stopped_pool(&s);
    let m = bag(&keyer);
    keyer.submit(job(&s, [1; 16]), true).expect("room");
    keyer.submit(job(&s, [2; 16]), false).expect("room");
    keyer.submit(job(&s, [3; 16]), false).expect("room");
    let q = m.snapshot().seal_keyer_queued;
    assert_eq!((q["standing"], q["stranger"]), (1, 2));
    run_worker(&keyer);
    let q = m.snapshot().seal_keyer_queued;
    assert_eq!((q["standing"], q["stranger"]), (0, 0));
    assert_eq!(m.snapshot().seal_keyer_workers["busy"], 0);
    assert_eq!(
        (
            done.try_recv().expect("standing").standing,
            done.try_recv().expect("a stranger").standing
        ),
        (true, false),
        "an outcome says which budget it came through"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pool_reports_its_size_and_is_never_zero_once_attached() {
    let s = seals();
    let (keyer, mut done) = Keyer::new(Arc::clone(&s));
    let m = bag(&keyer);
    assert!(m.snapshot().seal_keyer_workers["configured"] >= 1);
    keyer.submit(job(&s, [1; 16]), false).expect("room");
    assert!(done.recv().await.is_some());
}

/// The label keeps what the error knew and the old ledger dropped.
#[test]
fn a_refusal_names_who_it_refused() {
    let refused = |order: &ReceiverOrder, s: Sender<'_>| {
        order
            .admit(s)
            .expect_err("over")
            .refined_label()
            .expect("refined")
    };
    let order = ReceiverOrder::default();
    let none = Sender {
        identity: None,
        standing: false,
    };
    for _ in 0..HANDSHAKES_UNIDENTIFIED {
        order.admit(none).expect("within the slot");
    }
    assert_eq!(
        refused(&order, none),
        o::LINK_SEAL_REFUSED_HANDSHAKE_SENDER_RATE_UNIDENTIFIED
    );
    let one = stranger("one");
    for _ in 0..HANDSHAKES_PER_STRANGER {
        order.admit(one).expect("within its rate");
    }
    assert_eq!(
        refused(&order, one),
        o::LINK_SEAL_REFUSED_HANDSHAKE_SENDER_RATE_STRANGER
    );
    let known = Sender {
        identity: Some("known"),
        standing: true,
    };
    for _ in 0..HANDSHAKES_PER_STANDING {
        order.admit(known).expect("within its rate");
    }
    assert_eq!(
        refused(&order, known),
        o::LINK_SEAL_REFUSED_HANDSHAKE_SENDER_RATE_STANDING
    );
    order.set_stranger_cap(0);
    assert_eq!(
        refused(&order, stranger("two")),
        o::LINK_SEAL_REFUSED_HANDSHAKE_NODE_RATE_STRANGER
    );
    assert_eq!(
        SealRefusal::DecapSaturated { standing: true }.refined_label(),
        Some(o::LINK_SEAL_REFUSED_DECAP_SATURATED_STANDING)
    );
}

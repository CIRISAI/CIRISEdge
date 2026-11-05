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
        match keyer.submit(job(&s, nth_link(i)), false) {
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

/// A distinct link per `i`.
fn nth_link(i: usize) -> [u8; 16] {
    let mut link = [0u8; 16];
    link[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
    link
}

/// `FSD/EVENT_PATH_MODEL.md` §2.5 — a queue smaller than the budget in front of
/// it refuses what the budget admitted, after the slot is spent; and a
/// canonical's 500 peers re-dialling at once fit the standing queue.
#[test]
fn the_queues_hold_what_the_budgets_let_through() {
    let s = seals();
    let (keyer, _done) = stopped_pool(&s);
    for i in 0..HANDSHAKES_STRANGER_NODE as usize {
        keyer
            .submit(job(&s, nth_link(i)), false)
            .unwrap_or_else(|r| panic!("stranger {i} was admitted and refused: {r}"));
    }
    for i in 0..500 {
        keyer
            .submit(job(&s, nth_link(10_000 + i)), true)
            .unwrap_or_else(|r| panic!("peer {i} refused: {r}"));
    }
}

#[test]
fn standing_is_drained_first_and_has_room_in_a_full_stranger_queue_947() {
    let s = seals();
    let (keyer, mut done) = stopped_pool(&s);
    for i in 0..DECAP_QUEUE_STRANGER {
        keyer
            .submit(job(&s, nth_link(i)), false)
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
    assert_eq!(
        done.try_recv().expect("then the strangers").link,
        nth_link(0)
    );
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

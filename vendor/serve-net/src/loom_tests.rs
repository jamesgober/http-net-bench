//! loom models of serve-net's concurrency primitives. Run with
//! `RUSTFLAGS="--cfg serve_net_loom" cargo test --lib --release loom_tests`.

use std::sync::Arc;

use loom::thread;

use crate::config::{Budget, KeepAlive, Limits, Profile, ProfileId, ProfileTable};
use crate::engine::Family;
use crate::hooks::{Admit, InFlightCap};
use crate::http::{HttpFamily, HttpReply};
use crate::net::ConnectionId;
use crate::reply::{DeferSlot, Link, PostFail, SlotState, Waker};
use crate::snapshot::Snapshot;

#[test]
fn loom_snapshot_reader_sees_whole_values() {
    loom::model(|| {
        let s = Arc::new(Snapshot::new((1u32, 1u32)));
        let writer = {
            let s = Arc::clone(&s);
            thread::spawn(move || s.publish((2, 2)))
        };
        let mut r = s.reader();
        let v = *r.get(&s);
        assert!(v == (1, 1) || v == (2, 2), "a mixed value {v:?}");
        writer.join().unwrap();
        assert_eq!(*r.get(&s), (2, 2));
    });
}

struct Quiet;

impl Waker for Quiet {
    fn post(&self, _c: ConnectionId, _t: u32, _v: u64) -> Result<(), PostFail> {
        Ok(())
    }
}

fn token() -> (
    Arc<DeferSlot<<HttpFamily as Family>::Parts>>,
    crate::ReplyToken,
) {
    let id = ConnectionId::new(1).unwrap();
    let slot = Arc::new(DeferSlot::new(Arc::new(Quiet), id));
    let mut reply = HttpReply::new(Default::default());
    reply.link = Some(Link {
        slot: Arc::clone(&slot),
        generation: 7,
    });
    let token = reply.defer();
    (slot, token)
}

#[test]
fn loom_complete_races_cancel() {
    // A completion on another thread against the connection cancelling (a
    // deadline, the peer leaving): either the reply lands or it expires;
    // never both, never a lost reply the slot still claims to wait for.
    loom::model(|| {
        let (slot, mut token) = token();
        let completer = thread::spawn(move || {
            token.reply().text(200, "x");
            token.complete().is_ok()
        });
        // The connection gives up.
        *slot.lock() = SlotState::Idle;
        let completed = completer.join().unwrap();
        let state = slot.lock();
        match &*state {
            SlotState::Idle => {}
            SlotState::Completed(7, _) => assert!(completed),
            SlotState::Waiting(_) | SlotState::Dropped(_) | SlotState::Completed(..) => {
                panic!("unexpected slot state")
            }
        }
    });
}

#[test]
fn loom_drop_without_complete_marks_dropped() {
    loom::model(|| {
        let (slot, token) = token();
        let dropper = thread::spawn(move || drop(token));
        dropper.join().unwrap();
        assert!(matches!(&*slot.lock(), SlotState::Dropped(7)));
    });
}

#[test]
fn loom_in_flight_shared_cap_is_exact() {
    // Two workers race for the last slot of a small shared profile cap:
    // exactly one wins, and the counter returns to zero after release.
    loom::model(|| {
        let profiles = ProfileTable::compile(
            &[Profile::new(ProfileId(0)).budget(Budget::new().max_in_flight(1))],
            Limits::new(),
            KeepAlive::new(),
        );
        let mut cap = InFlightCap::new();
        cap.prepare(2, &profiles);
        let cap = Arc::new(cap);
        let env = crate::envelope::tests::sample();
        let other = {
            let cap = Arc::clone(&cap);
            let env = env.clone();
            thread::spawn(move || cap.admit_at(1, &env).ok().map(|a| (a, env)))
        };
        let mine = cap.admit_at(0, &env).ok();
        let theirs = other.join().unwrap();
        assert!(mine.is_some() != theirs.is_some(), "exactly one admission");
        if let Some(a) = mine {
            cap.release_at(0, &env, a);
        }
        if let Some((a, e)) = theirs {
            cap.release_at(1, &e, a);
        }
        assert!(cap.admit_at(0, &env).is_ok(), "the slot came back");
    });
}

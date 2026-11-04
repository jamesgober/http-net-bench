//! The facts serve-net keeps about one request.

use std::time::Instant;

use crate::client::ClientInfo;
use crate::config::ProfileId;
use crate::net::{ConnectionId, Lane, WorkerId};

/// A request's number on its connection: 1 for the first, then counting up.
/// With the connection id it identifies a request within the process. Not a
/// security token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestSeq(pub(crate) u32);

impl RequestSeq {
    /// The number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// The facts serve-net keeps about one request, passed to every hook and
/// service call. Lives in the connection record: no allocation.
#[derive(Clone, Debug)]
pub struct Envelope {
    pub(crate) connection: ConnectionId,
    pub(crate) seq: RequestSeq,
    pub(crate) profile: ProfileId,
    pub(crate) tag: u8,
    pub(crate) lane: Lane,
    pub(crate) lane_open: bool,
    pub(crate) lane_late: bool,
    pub(crate) client: ClientInfo,
    pub(crate) arrived: Instant,
    pub(crate) deadline: Instant,
    pub(crate) worker: WorkerId,
    pub(crate) user_word: u64,
}

impl Envelope {
    /// The connection's id.
    #[must_use]
    pub fn connection(&self) -> ConnectionId {
        self.connection
    }

    /// The request's number on its connection.
    #[must_use]
    pub fn seq(&self) -> RequestSeq {
        self.seq
    }

    /// The profile of the listener the request arrived on.
    #[must_use]
    pub fn profile(&self) -> ProfileId {
        self.profile
    }

    /// The profile's opaque tag.
    #[must_use]
    pub fn tag(&self) -> u8 {
        self.tag
    }

    /// The request's lane.
    #[must_use]
    pub fn lane(&self) -> Lane {
        self.lane
    }

    /// Sets the lane. Honoured in `head` only; a later call is ignored and
    /// reported.
    pub fn set_lane(&mut self, lane: Lane) {
        if self.lane_open {
            self.lane = lane;
        } else {
            self.lane_late = true;
        }
    }

    /// The request's client.
    #[must_use]
    pub fn client(&self) -> &ClientInfo {
        &self.client
    }

    /// When the first byte of the head arrived.
    #[must_use]
    pub fn arrived(&self) -> Instant {
        self.arrived
    }

    /// The request deadline.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// The worker that owns the connection.
    #[must_use]
    pub fn worker(&self) -> WorkerId {
        self.worker
    }

    /// The word a wrapper stored in `head`.
    #[must_use]
    pub fn user_word(&self) -> u64 {
        self.user_word
    }

    /// Stores one word, for example the index of a slot taken in `Admit`.
    pub fn set_user_word(&mut self, word: u64) {
        self.user_word = word;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn sample() -> Envelope {
        let now = Instant::now();
        Envelope {
            connection: ConnectionId::new(7).unwrap(),
            seq: RequestSeq(1),
            profile: ProfileId(0),
            tag: 0,
            lane: Lane(4),
            lane_open: true,
            lane_late: false,
            client: ClientInfo::direct("127.0.0.1:1".parse().unwrap(), false),
            arrived: now,
            deadline: now,
            worker: WorkerId::first(),
            user_word: 0,
        }
    }

    #[test]
    fn test_envelope_lane_only_in_head() {
        let mut e = sample();
        e.set_lane(Lane(0));
        assert_eq!(e.lane(), Lane(0));
        e.lane_open = false;
        e.set_lane(Lane(9));
        assert_eq!(e.lane(), Lane(0));
        assert!(e.lane_late);
    }

    #[test]
    fn test_envelope_is_send_sync_and_small() {
        fn check<T: Send + Sync>() {}
        check::<Envelope>();
        assert!(core::mem::size_of::<Envelope>() <= 160);
    }
}

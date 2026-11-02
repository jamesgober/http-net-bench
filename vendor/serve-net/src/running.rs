//! A bound and a running server: the door, drain, and stop.

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::client::IngressKind;
use crate::config::ProfileId;
use crate::conn::session::Runtime;
use crate::error::ServeError;
use crate::health::{Health, HealthState, ListenerInfo, ListenerState};
use crate::net::{ControlLine, ControlState};
use crate::stats::{Counters, Stats};

/// The control line net-io reads: the owner's line merged with serve-net's
/// own drain request (D-032). A drain asked for through a [`DrainHandle`]
/// shows as `Draining` with its deadline; the owner's `Stopping` still wins.
pub(crate) struct Merged<C: ControlLine> {
    owner: Arc<C>,
    epoch: AtomicU64,
    drain: Mutex<Option<Instant>>,
}

impl<C: ControlLine> Merged<C> {
    pub(crate) fn new(owner: Arc<C>) -> Self {
        Merged {
            owner,
            epoch: AtomicU64::new(0),
            drain: Mutex::new(None),
        }
    }

    fn own(&self) -> Option<Instant> {
        *self.drain.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<C: ControlLine> ControlLine for Merged<C> {
    fn epoch(&self) -> u64 {
        // Both parts only grow, so the sum moves whenever either does.
        self.owner
            .epoch()
            .wrapping_add(self.epoch.load(Ordering::Acquire))
    }

    fn state(&self) -> ControlState {
        let owner = self.owner.state();
        match (self.own(), owner) {
            (Some(_), ControlState::Stopping) | (None, _) => owner,
            (Some(_), _) => ControlState::Draining,
        }
    }

    fn deadline(&self) -> Option<Instant> {
        let owner = match self.owner.state() {
            ControlState::Draining => self.owner.deadline(),
            _ => None,
        };
        match (self.own(), owner) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// serve-net's half of the merged line, without the owner's line type.
pub(crate) trait DrainSwitch: Send + Sync + 'static {
    /// Asks for a drain ending at `deadline`; a shorter deadline wins.
    fn request(&self, deadline: Instant);
    /// Whether a drain was asked for, here or on the owner's line.
    fn is_draining(&self) -> bool;
}

impl<C: ControlLine> DrainSwitch for Merged<C> {
    fn request(&self, deadline: Instant) {
        let mut own = self.drain.lock().unwrap_or_else(PoisonError::into_inner);
        let next = match *own {
            Some(d) if d <= deadline => return,
            _ => deadline,
        };
        *own = Some(next);
        drop(own);
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }

    fn is_draining(&self) -> bool {
        matches!(
            self.state(),
            ControlState::Draining | ControlState::Stopping
        )
    }
}

/// What a drain did.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrainReport {
    /// Connections that finished and closed normally.
    pub graceful: u32,
    /// Connections closed at the deadline.
    pub killed: u32,
    /// Requests that completed during the drain.
    pub requests_finished: u64,
    /// Requests refused while the server was draining.
    pub refused_while_draining: u64,
    /// How long the drain took.
    pub elapsed: Duration,
    /// Whether the deadline passed with connections still open.
    pub deadline_hit: bool,
}

impl DrainReport {
    fn from_net(r: net_io::DrainReport, counters: &Counters) -> Self {
        let (requests_finished, refused_while_draining) = counters.draining();
        DrainReport {
            graceful: r.graceful,
            killed: r.killed,
            requests_finished,
            refused_while_draining,
            elapsed: r.took,
            deadline_hit: r.killed > 0,
        }
    }
}

/// Starts a drain from any thread.
#[derive(Clone)]
pub struct DrainHandle {
    switch: Arc<dyn DrainSwitch>,
    handle: net_io::ServerHandle,
}

impl DrainHandle {
    /// Starts a drain that ends at most `deadline` from now, and returns at
    /// once; [`Running::wait`] returns its report.
    pub fn drain(&self, deadline: Duration) {
        self.switch.request(Instant::now() + deadline);
        // net-io's accept thread runs the drain; wake every thread waiting in
        // the kernel so the line is read now (D-043).
        self.handle.wake_all();
    }

    /// Whether a drain was asked for.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.switch.is_draining()
    }
}

impl fmt::Debug for DrainHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DrainHandle")
            .field("draining", &self.is_draining())
            .finish()
    }
}

/// One listener's facts for `listeners()`.
pub(crate) struct ListenerMeta {
    pub(crate) name: String,
    pub(crate) ingress: IngressKind,
    pub(crate) profile: ProfileId,
    pub(crate) public_bind: Option<&'static str>,
}

/// Everything `bind` hands to [`Bound`].
pub(crate) struct Parts {
    pub(crate) server: net_io::Server,
    pub(crate) listeners: Vec<ListenerMeta>,
    pub(crate) switch: Arc<dyn DrainSwitch>,
    pub(crate) rt: Arc<Runtime>,
    pub(crate) counters: Arc<Counters>,
    pub(crate) health: Arc<HealthState>,
}

/// What a bound and a running server hold.
struct Inner {
    server: net_io::Server,
    listeners: Vec<ListenerMeta>,
    names: Vec<String>,
    switch: Arc<dyn DrainSwitch>,
    /// The soft-cap seats; kept alive with the server.
    _rt: Arc<Runtime>,
    counters: Arc<Counters>,
    health: Arc<HealthState>,
}

impl Inner {
    fn listener_infos(&self, opened: bool) -> Vec<ListenerInfo> {
        let door = self.server.door();
        self.server
            .listeners()
            .iter()
            .filter_map(|l| {
                let i = usize::from(l.id.get());
                let meta = self.listeners.get(i)?;
                let state = if self.health.listener_failing(i) {
                    ListenerState::Failing
                } else if !opened {
                    ListenerState::Bound
                } else if door == net_io::DoorState::Open {
                    ListenerState::Accepting
                } else {
                    ListenerState::DoorClosed
                };
                Some(ListenerInfo {
                    name: meta.name.clone(),
                    local: l.local.clone(),
                    ingress: meta.ingress,
                    profile: meta.profile,
                    state,
                    public_bind_reason: meta.public_bind,
                })
            })
            .collect()
    }

    fn local_addrs(&self) -> impl Iterator<Item = (&str, SocketAddr)> + '_ {
        self.server.listeners().iter().filter_map(|l| {
            let name = self
                .names
                .get(usize::from(l.id.get()))
                .map_or("", String::as_str);
            l.local.socket_addr().map(|a| (name, a))
        })
    }
}

/// A server with every listener bound and the door closed.
#[must_use = "a Bound server accepts nothing until open() is called"]
pub struct Bound {
    inner: Inner,
}

impl Bound {
    pub(crate) fn new(parts: Parts) -> Self {
        let names = parts.listeners.iter().map(|l| l.name.clone()).collect();
        Bound {
            inner: Inner {
                server: parts.server,
                listeners: parts.listeners,
                names,
                switch: parts.switch,
                _rt: parts.rt,
                counters: parts.counters,
                health: parts.health,
            },
        }
    }

    /// Each TCP listener's name and bound address.
    pub fn local_addrs(&self) -> impl Iterator<Item = (&str, SocketAddr)> + '_ {
        self.inner.local_addrs()
    }

    /// Name, address, ingress, profile, and state per listener.
    #[must_use]
    pub fn listeners(&self) -> Vec<ListenerInfo> {
        self.inner.listener_infos(false)
    }

    /// Opens the door on every listener.
    ///
    /// # Errors
    ///
    /// [`ServeError::Start`] when net-io refuses to open the door.
    pub fn open(self) -> Result<Running, ServeError> {
        self.inner.server.open_door().map_err(ServeError::Start)?;
        Ok(Running {
            inner: Some(self.inner),
        })
    }
}

impl fmt::Debug for Bound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bound")
            .field("listeners", &self.local_addrs().collect::<Vec<_>>())
            .finish()
    }
}

/// A running server.
#[must_use = "dropping Running closes every connection at once; call wait() or drain()"]
pub struct Running {
    inner: Option<Inner>,
}

impl Running {
    fn inner(&self) -> &Inner {
        // Present until `drain`, `wait`, or drop takes it.
        self.inner.as_ref().unwrap_or_else(|| unreachable!())
    }

    /// The first TCP listener's address (useful with port 0).
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner().local_addrs().next().map(|(_, a)| a)
    }

    /// Name, address, ingress, profile, and state per listener (allocates;
    /// not a hot path).
    #[must_use]
    pub fn listeners(&self) -> Vec<ListenerInfo> {
        self.inner().listener_infos(true)
    }

    /// Stops accepting on every listener; idempotent.
    pub fn close_door(&self) {
        self.inner().server.close_door();
    }

    /// Request counters summed over the workers, with net-io's transport
    /// counters.
    #[must_use]
    pub fn stats(&self) -> Stats {
        let inner = self.inner();
        let mut s = inner.counters.sum();
        s.transport = inner.server.stats();
        s
    }

    /// Health, computed on call: listeners accepting, workers making
    /// progress, the share of busy refusals since the last call, the drain.
    #[must_use]
    pub fn health(&self) -> Health {
        let inner = self.inner();
        inner
            .health
            .compute(&inner.names, &inner.counters, inner.switch.is_draining())
    }

    /// Drains with `deadline` and shuts the server down.
    pub fn drain(mut self, deadline: Duration) -> DrainReport {
        let inner = self.inner.take().unwrap_or_else(|| unreachable!());
        let deadline = Instant::now() + deadline;
        // Replies in flight read the line live and carry the close signal.
        inner.switch.request(deadline);
        let report = inner.server.shutdown(deadline);
        DrainReport::from_net(report, &inner.counters)
    }

    /// A handle that starts a drain from any thread.
    #[must_use]
    pub fn drain_handle(&self) -> DrainHandle {
        let inner = self.inner();
        DrainHandle {
            switch: Arc::clone(&inner.switch),
            handle: inner.server.handle(),
        }
    }

    /// Parks until a drain is asked for, then drains and shuts down.
    pub fn wait(mut self) -> DrainReport {
        let inner = self.inner.take().unwrap_or_else(|| unreachable!());
        let report = inner.server.wait_for_stop();
        DrainReport::from_net(report, &inner.counters)
    }

    /// net-io's handle.
    #[must_use]
    pub fn server_handle(&self) -> net_io::ServerHandle {
        self.inner().server.handle()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            // A drop must not block for seconds: close everything now.
            let _ = inner.server.shutdown(Instant::now());
        }
    }
}

impl fmt::Debug for Running {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Running");
        if let Some(inner) = &self.inner {
            d.field("listeners", &inner.local_addrs().collect::<Vec<_>>());
        }
        d.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::SimpleControl;

    #[test]
    fn test_merged_line_drain_and_owner_stop() {
        let owner = Arc::new(SimpleControl::new());
        let line = Merged::new(Arc::clone(&owner));
        let e0 = line.epoch();
        assert_eq!(line.state(), ControlState::Normal);
        let soon = Instant::now() + Duration::from_secs(5);
        line.request(soon);
        assert!(line.epoch() > e0);
        assert_eq!(line.state(), ControlState::Draining);
        assert_eq!(line.deadline(), Some(soon));
        // A longer deadline is ignored; a shorter one wins.
        let e1 = line.epoch();
        line.request(soon + Duration::from_secs(10));
        assert_eq!(line.epoch(), e1);
        line.request(soon - Duration::from_secs(1));
        assert_eq!(line.deadline(), Some(soon - Duration::from_secs(1)));
        owner.set(ControlState::Stopping, None);
        assert_eq!(line.state(), ControlState::Stopping);
    }
}

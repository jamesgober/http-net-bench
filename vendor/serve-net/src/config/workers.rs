//! Which net-io driver runs connections, and how many workers.

use crate::net::DriverKind;

/// Which net-io driver runs the connections, and how many workers.
///
/// ```
/// use serve_net::Workers;
/// let small = Workers::blocking(32);
/// assert_eq!(small.count(), Some(32));
/// assert_eq!(Workers::auto().count(), None);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Workers {
    pub(crate) kind: DriverKind,
    pub(crate) count: Option<u16>,
}

/// The blocking pool's default thread count.
pub(crate) const BLOCKING_DEFAULT: u16 = 256;

impl Workers {
    /// The reactor where net-io provides it, else the blocking pool.
    #[must_use]
    pub fn auto() -> Self {
        Workers {
            kind: DriverKind::Auto,
            count: None,
        }
    }

    /// A bounded pool of connection threads (default 256).
    #[must_use]
    pub fn blocking(threads: u16) -> Self {
        Workers {
            kind: DriverKind::Blocking,
            count: Some(threads),
        }
    }

    /// The driver kind.
    #[must_use]
    pub fn kind(&self) -> DriverKind {
        self.kind
    }

    /// The worker count; `None` for the driver's default.
    #[must_use]
    pub fn count(&self) -> Option<u16> {
        self.count
    }

    /// The thread count the blocking pool runs with.
    pub(crate) fn blocking_threads(&self) -> u16 {
        self.count.unwrap_or(BLOCKING_DEFAULT)
    }
}

impl Default for Workers {
    fn default() -> Self {
        Workers::auto()
    }
}

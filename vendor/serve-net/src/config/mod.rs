//! Configuration: listeners, ingress, profiles, limits, workers, and the
//! validation that refuses insecure or inconsistent configurations.

mod ingress;
mod limits;
mod listener;
mod profile;
pub(crate) mod validate;
mod workers;

pub(crate) use ingress::ProxyKind;
pub use ingress::{ForwardedSource, Ingress, MissingHeader, ProxySource, UnknownClient};
pub(crate) use limits::range;
pub use limits::{KeepAlive, Limits};
pub use listener::{ListenerSource, ListenerSpec};
pub use profile::{Budget, EngineChoice, Profile, ProfileId, ProfileTable};
pub(crate) use profile::{Compiled, DEFAULT_LANE};
pub use workers::Workers;

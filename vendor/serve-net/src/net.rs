//! The net-io items serve-net names in its own API (D-037): re-exported, so a
//! program that uses both crates sees one type for each.

pub use net_io::{
    AddrError, AllowAll, Cidr, CloseReason, ConnectionId, ControlLine, ControlState, DriverKind,
    EventSink, Gate, Lane, NoControl, NoopSink, ProxyVersions, SimpleControl, TrustedProxies,
    WorkerId, normalize,
};

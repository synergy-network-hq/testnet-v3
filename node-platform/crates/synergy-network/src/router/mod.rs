//! Bounded fair routing of opaque authenticated frames.

mod backpressure;
mod handler;
mod mailbox;
mod queue;
mod retransmit;
mod router;

pub use backpressure::{BackpressureState, BackpressureThresholds};
pub use handler::ProtocolFrameHandler;
pub use mailbox::{BoundedPeerRouter, RouterAdmissionError, RouterTelemetry};
pub use queue::{BoundedQueue, QueueError};
pub use retransmit::{OutboundRetransmission, RetransmissionBuffer};
pub use router::{dispatch_next, DispatchError};

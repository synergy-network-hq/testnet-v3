#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    Counter,
    Gauge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricDescriptor {
    pub name: &'static str,
    pub kind: MetricKind,
    pub help: &'static str,
}

pub const NODE_METRICS: &[MetricDescriptor] = &[
    MetricDescriptor {
        name: "node_ready",
        kind: MetricKind::Gauge,
        help: "Node readiness state",
    },
    MetricDescriptor {
        name: "node_service_failures_total",
        kind: MetricKind::Counter,
        help: "Supervised service failures",
    },
];

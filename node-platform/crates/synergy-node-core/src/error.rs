use std::fmt;

use crate::supervisor::ServiceId;

/// Failures produced while constructing or operating the node service graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorError {
    DuplicateService(ServiceId),
    UnknownDependency {
        service: ServiceId,
        dependency: ServiceId,
    },
    DependencyCycle(Vec<ServiceId>),
    ServiceUnavailable(ServiceId),
    DependencyNotRunning {
        service: ServiceId,
        dependency: ServiceId,
    },
    StartFailed {
        service: ServiceId,
        message: String,
    },
    StopFailed {
        service: ServiceId,
        message: String,
    },
    RestartExhausted(ServiceId),
    InvalidState {
        service: ServiceId,
        operation: &'static str,
    },
    Cancelled,
    PollFailed {
        service: ServiceId,
        message: String,
    },
    StartupCleanup {
        cause: Box<SupervisorError>,
        failures: Vec<(ServiceId, String)>,
    },
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState { service, operation } => write!(
                formatter,
                "cannot {operation} service {service} in its current state"
            ),
            Self::Cancelled => formatter.write_str("service supervisor has been cancelled"),
            Self::PollFailed { service, message } => write!(
                formatter,
                "service {service} failed during polling: {message}"
            ),
            Self::StartupCleanup { cause, failures } => write!(
                formatter,
                "{cause}; {} service(s) also failed startup cleanup: {failures:?}",
                failures.len()
            ),
            Self::DuplicateService(service) => write!(formatter, "duplicate service {service}"),
            Self::UnknownDependency {
                service,
                dependency,
            } => write!(
                formatter,
                "service {service} depends on unknown service {dependency}"
            ),
            Self::DependencyCycle(services) => {
                write!(formatter, "service dependency cycle involving")?;
                for service in services {
                    write!(formatter, " {service}")?;
                }
                Ok(())
            }
            Self::ServiceUnavailable(service) => {
                write!(formatter, "service {service} is unavailable")
            }
            Self::DependencyNotRunning {
                service,
                dependency,
            } => write!(
                formatter,
                "service {service} requires running dependency {dependency}"
            ),
            Self::StartFailed { service, message } => {
                write!(formatter, "service {service} failed to start: {message}")
            }
            Self::StopFailed { service, message } => {
                write!(formatter, "service {service} failed to stop: {message}")
            }
            Self::RestartExhausted(service) => {
                write!(formatter, "service {service} exhausted its restart policy")
            }
        }
    }
}

impl std::error::Error for SupervisorError {}

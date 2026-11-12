//! One mutable subsystem owner per thread; supervisor methods only copy snapshots.
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use synergy_node_core::{CancellationToken, ManagedService, ServiceHealth, ServiceReadiness};

const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(10);
const OWNER_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Clone)]
struct Snapshot {
    started: bool,
    finished: bool,
    failure: Option<String>,
    health: ServiceHealth,
    readiness: ServiceReadiness,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            started: false,
            finished: false,
            failure: None,
            health: ServiceHealth::Degraded {
                reason: "owner is not started".into(),
            },
            readiness: ServiceReadiness::Pending {
                reason: "owner is not started".into(),
            },
        }
    }
}

/// Production registration wrapper. Native deterministic fixtures retain caller polling.
pub fn production(service: Box<dyn ManagedService>, name: &'static str) -> Box<dyn ManagedService> {
    #[cfg(test)]
    {
        let _ = name;
        service
    }
    #[cfg(not(test))]
    {
        Box::new(OwnedService::new(service, name))
    }
}

pub fn production_with_interval(
    service: Box<dyn ManagedService>,
    name: &'static str,
    interval: Duration,
) -> Box<dyn ManagedService> {
    #[cfg(test)]
    {
        let _ = (name, interval);
        service
    }
    #[cfg(not(test))]
    {
        Box::new(OwnedService::with_poll_interval(service, name, interval))
    }
}

type OwnerOutcome = (Box<dyn ManagedService>, Option<String>);

pub struct OwnedService {
    name: &'static str,
    service: Option<Box<dyn ManagedService>>,
    worker: Option<JoinHandle<OwnerOutcome>>,
    snapshot: Arc<Mutex<Snapshot>>,
    cancellation: CancellationToken,
    failed: bool,
    interval: Duration,
}
impl OwnedService {
    pub fn new(service: Box<dyn ManagedService>, name: &'static str) -> Self {
        Self::with_poll_interval(service, name, OWNER_POLL_INTERVAL)
    }
    pub fn with_poll_interval(
        service: Box<dyn ManagedService>,
        name: &'static str,
        interval: Duration,
    ) -> Self {
        assert!(interval >= Duration::from_millis(1) && interval <= Duration::from_millis(50));
        Self {
            name,
            service: Some(service),
            worker: None,
            snapshot: Arc::new(Mutex::new(Snapshot::default())),
            cancellation: CancellationToken::default(),
            failed: false,
            interval,
        }
    }
    fn view(&self) -> Result<Snapshot, String> {
        self.snapshot
            .lock()
            .map(|v| v.clone())
            .map_err(|_| "owner snapshot poisoned".into())
    }
    fn finish(&mut self) -> Result<(), String> {
        self.cancellation.cancel();
        if let Some(worker) = &self.worker {
            worker.thread().unpark();
        }
        let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            if Instant::now() >= deadline {
                self.failed = true;
                return Err(format!(
                    "{} owner shutdown deadline exceeded; replacement prohibited",
                    self.name
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok((service, error)) => {
                    self.service = Some(service);
                    if let Some(error) = error {
                        self.failed = true;
                        return Err(error);
                    }
                }
                Err(_) => {
                    self.failed = true;
                    return Err(format!("{} owner panicked", self.name));
                }
            }
        }
        if self.failed {
            return Err(format!("{} owner failure is latched", self.name));
        }
        Ok(())
    }
}
impl ManagedService for OwnedService {
    fn start(&mut self, parent: &CancellationToken) -> Result<(), String> {
        if self.failed || self.worker.is_some() {
            return Err("owner replacement prohibited while active or failed".into());
        }
        if parent.is_cancelled() {
            return Err("owner startup cancelled".into());
        }
        let mut service = self.service.take().ok_or("owner service unavailable")?;
        self.cancellation = CancellationToken::default();
        let private = self.cancellation.clone();
        let parent = parent.clone();
        let shared = self.snapshot.clone();
        let interval = self.interval;
        *self
            .snapshot
            .lock()
            .map_err(|_| "owner snapshot poisoned")? = Snapshot::default();
        let worker = thread::Builder::new()
            .name(format!("synergy-{}-owner", self.name))
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
                    service.start(&private)?;
                    // Never hold the snapshot lock while querying subsystem state.
                    let health = service.health();
                    let readiness = service.readiness();
                    *shared.lock().map_err(|_| "owner snapshot poisoned")? = Snapshot {
                        started: true,
                        health,
                        readiness,
                        ..Snapshot::default()
                    };
                    while !private.is_cancelled() && !parent.is_cancelled() {
                        service.poll()?;
                        let health = service.health();
                        let readiness = service.readiness();
                        let mut snapshot = shared.lock().map_err(|_| "owner snapshot poisoned")?;
                        snapshot.health = health;
                        snapshot.readiness = readiness;
                        drop(snapshot);
                        thread::park_timeout(interval);
                    }
                    Ok(())
                }));
                let mut error = match result {
                    Ok(result) => result.err(),
                    Err(_) => Some("service owner panicked".into()),
                };
                // Stop stays on the same sole owner even after a failure; no new signer is opened.
                let stopped = catch_unwind(AssertUnwindSafe(|| service.stop()));
                match stopped {
                    Ok(Err(reason)) => {
                        if error.is_none() {
                            error = Some(reason);
                        }
                    }
                    Err(_) => {
                        if error.is_none() {
                            error = Some("service owner stop panicked".into());
                        }
                    }
                    Ok(Ok(())) => {}
                }
                if let Ok(mut snapshot) = shared.lock() {
                    snapshot.finished = true;
                    snapshot.failure = error.clone();
                    snapshot.health = ServiceHealth::Unhealthy {
                        reason: error.clone().unwrap_or_else(|| "owner stopped".into()),
                    };
                    snapshot.readiness = ServiceReadiness::Blocked {
                        reason: error.clone().unwrap_or_else(|| "owner stopped".into()),
                    };
                }
                (service, error)
            })
            .map_err(|error| {
                self.failed = true;
                format!("spawn service owner: {error}")
            })?;
        self.worker = Some(worker);
        let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
        loop {
            let snapshot = self.view()?;
            if snapshot.finished {
                return self
                    .finish()
                    .and_then(|_| Err("owner exited during startup".into()));
            }
            if snapshot.started {
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.failed = true;
                self.cancellation.cancel();
                if let Some(worker) = &self.worker {
                    worker.thread().unpark();
                }
                return Err("owner startup deadline exceeded; replacement prohibited".into());
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
    fn poll(&mut self) -> Result<(), String> {
        let snapshot = self.view()?;
        if let Some(error) = snapshot.failure {
            self.failed = true;
            return Err(error);
        }
        if snapshot.finished {
            return Err("service owner stopped".into());
        }
        if self.failed {
            return Err("service owner failure is latched".into());
        }
        Ok(())
    }
    fn stop(&mut self) -> Result<(), String> {
        self.finish()
    }
    fn health(&self) -> ServiceHealth {
        if self.failed {
            return ServiceHealth::Unhealthy {
                reason: "service owner failure is latched".into(),
            };
        }
        self.view()
            .map(|v| v.health)
            .unwrap_or(ServiceHealth::Unhealthy {
                reason: "owner snapshot poisoned".into(),
            })
    }
    fn readiness(&self) -> ServiceReadiness {
        if self.failed {
            return ServiceReadiness::Blocked {
                reason: "service owner failure is latched".into(),
            };
        }
        self.view()
            .map(|v| v.readiness)
            .unwrap_or(ServiceReadiness::Blocked {
                reason: "owner snapshot poisoned".into(),
            })
    }
}
impl Drop for OwnedService {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Probe {
        starts: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
        polls: Arc<AtomicUsize>,
        panic_poll: bool,
    }
    impl ManagedService for Probe {
        fn start(&mut self, _: &CancellationToken) -> Result<(), String> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn stop(&mut self) -> Result<(), String> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn poll(&mut self) -> Result<(), String> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            if self.panic_poll {
                panic!("injected owner failure");
            }
            Ok(())
        }
        fn health(&self) -> ServiceHealth {
            ServiceHealth::Healthy
        }
        fn readiness(&self) -> ServiceReadiness {
            ServiceReadiness::Ready
        }
    }
    fn probe(
        panic_poll: bool,
    ) -> (
        OwnedService,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) {
        let starts = Arc::new(AtomicUsize::new(0));
        let stops = Arc::new(AtomicUsize::new(0));
        let polls = Arc::new(AtomicUsize::new(0));
        (
            OwnedService::new(
                Box::new(Probe {
                    starts: starts.clone(),
                    stops: stops.clone(),
                    polls: polls.clone(),
                    panic_poll,
                }),
                "probe",
            ),
            starts,
            stops,
            polls,
        )
    }
    #[test]
    fn clean_restart_retains_same_owner_state_and_confirms_stop() {
        let (mut owner, starts, stops, polls) = probe(false);
        owner.start(&CancellationToken::default()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while polls.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(polls.load(Ordering::SeqCst) > 0);
        owner.stop().unwrap();
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        owner.start(&CancellationToken::default()).unwrap();
        owner.stop().unwrap();
        assert_eq!(starts.load(Ordering::SeqCst), 2);
        assert_eq!(stops.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn supervisor_snapshots_do_not_wait_for_owner_work() {
        struct Gated {
            entered: std::sync::mpsc::Sender<()>,
            release: Option<std::sync::mpsc::Receiver<()>>,
        }
        impl ManagedService for Gated {
            fn start(&mut self, _: &CancellationToken) -> Result<(), String> {
                Ok(())
            }
            fn stop(&mut self) -> Result<(), String> {
                Ok(())
            }
            fn poll(&mut self) -> Result<(), String> {
                if let Some(release) = self.release.take() {
                    self.entered.send(()).unwrap();
                    release
                        .recv_timeout(Duration::from_secs(1))
                        .map_err(|e| e.to_string())?;
                }
                Ok(())
            }
            fn health(&self) -> ServiceHealth {
                ServiceHealth::Healthy
            }
            fn readiness(&self) -> ServiceReadiness {
                ServiceReadiness::Ready
            }
        }
        let (entered, observed) = std::sync::mpsc::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let mut owner = OwnedService::new(
            Box::new(Gated {
                entered,
                release: Some(gate),
            }),
            "gated",
        );
        owner.start(&CancellationToken::default()).unwrap();
        observed.recv_timeout(Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        owner.poll().unwrap();
        assert_eq!(owner.health(), ServiceHealth::Healthy);
        assert_eq!(owner.readiness(), ServiceReadiness::Ready);
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(owner.start(&CancellationToken::default()).is_err());
        release.send(()).unwrap();
        owner.stop().unwrap();
    }

    #[test]
    fn cancelled_start_never_enters_native_owner() {
        let (mut owner, starts, _, _) = probe(false);
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(owner.start(&cancelled).is_err());
        assert_eq!(starts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn panic_latches_failure_and_cannot_open_replacement() {
        let (mut owner, starts, stops, _) = probe(true);
        let _ = owner.start(&CancellationToken::default());
        let deadline = Instant::now() + Duration::from_secs(1);
        while !owner.view().unwrap().finished && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(owner.stop().is_err());
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(owner.start(&CancellationToken::default()).is_err());
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }
}

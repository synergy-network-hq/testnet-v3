//! Bounded immutable preparation. Workers never own signers or mutable authority.
//! Byte reservations cover captured input and retained result mailboxes. Native codec
//! scratch allocations remain subject to their own existing limits; these mailbox
//! limits do not claim to cap total worker resident memory.
use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub enum Lane {
    Consensus,
    Admission,
    Background,
}
impl Lane {
    fn index(self) -> usize {
        match self {
            Self::Consensus => 0,
            Self::Admission => 1,
            Self::Background => 2,
        }
    }
}
const COUNTS: [usize; 3] = [64, 16, 8];
const BYTES: [usize; 3] = [8 * 1024 * 1024; 3];
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityTag {
    pub incarnation: String,
    pub epoch: u64,
    pub authority_digest: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobTag {
    pub authority: AuthorityTag,
    pub generation: u64,
    pub height: u64,
    pub round: u64,
    pub target: u64,
    pub input_digest: String,
}
struct State {
    queues: [VecDeque<Job>; 3],
    counts: [usize; 3],
    bytes: [usize; 3],
    stopped: bool,
    failure: Option<String>,
    completed: [u64; 3],
    timings: [VecDeque<(f64, f64)>; 3],
}
struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}
struct Job {
    submitted: Instant,
    run: Box<dyn FnOnce() + Send>,
}
struct Reservation {
    shared: Weak<Shared>,
    lane: usize,
    bytes: usize,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            if let Ok(mut state) = shared.state.lock() {
                state.counts[self.lane] = state.counts[self.lane].saturating_sub(1);
                state.bytes[self.lane] = state.bytes[self.lane].saturating_sub(self.bytes);
                shared.wake.notify_all();
            }
        }
    }
}
pub struct Completion<T> {
    pub tag: JobTag,
    pub result: Result<T, String>,
    pub queue_wait: Duration,
    pub work_time: Duration,
    _reservation: Reservation,
}
#[derive(Clone)]
pub struct Handle {
    shared: Arc<Shared>,
}
pub struct Owner<T> {
    handle: Handle,
    authority: AuthorityTag,
    generation: u64,
    cancelled: Arc<AtomicBool>,
    sender: mpsc::SyncSender<Completion<T>>,
    receiver: mpsc::Receiver<Completion<T>>,
}
impl Handle {
    pub fn owner<T: Send + 'static>(&self, authority: AuthorityTag) -> Result<Owner<T>, String> {
        for field in [&authority.incarnation, &authority.authority_digest] {
            if field.is_empty() || field.len() > 256 || field.chars().any(char::is_control) {
                return Err("preparation authority tag is invalid".into());
            }
        }
        static GENERATION: AtomicU64 = AtomicU64::new(1);
        let generation = GENERATION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .map_err(|_| "preparation generation exhausted")?;
        let (sender, receiver) = mpsc::sync_channel(COUNTS.iter().sum());
        Ok(Owner {
            handle: self.clone(),
            authority,
            generation,
            cancelled: Arc::new(AtomicBool::new(false)),
            sender,
            receiver,
        })
    }
    pub fn observations(&self) -> Result<serde_json::Value, String> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| "preparation state poisoned")?;
        let now = Instant::now();
        let lanes=(0..3).map(|lane| {
            let timings=&state.timings[lane];
            let maxima=timings.iter().fold((0.0_f64,0.0_f64),|(q,w),(a,b)|(q.max(*a),w.max(*b)));
            let distribution=|select_queue:bool| {
                let mut values=timings.iter().map(|(q,w)|if select_queue {*q} else {*w}).collect::<Vec<_>>();
                values.sort_by(f64::total_cmp);
                let percentile=|p:usize| if values.is_empty() {None} else {Some(values[((values.len()*p).div_ceil(100)).saturating_sub(1)])};
                serde_json::json!({"p50_ms":percentile(50),"p95_ms":percentile(95),"p99_ms":percentile(99)})
            };
            serde_json::json!({"lane":(["consensus","admission","background"][lane]),
                "reserved_jobs":state.counts[lane],"reserved_mailbox_bytes":state.bytes[lane],
                "queued_jobs":state.queues[lane].len(),"count_limit":COUNTS[lane],"mailbox_byte_limit":BYTES[lane],
                "oldest_queued_age_ms":state.queues[lane].front().map(|job|now.duration_since(job.submitted).as_secs_f64()*1000.0),
                "completed_jobs":state.completed[lane],"samples":timings.len(),
                "maximum_queue_wait_ms":(!timings.is_empty()).then_some(maxima.0),
                "maximum_worker_time_ms":(!timings.is_empty()).then_some(maxima.1),
                "queue_wait":distribution(true),"worker_time":distribution(false)})
        }).collect::<Vec<_>>();
        Ok(
            serde_json::json!({"authority":false,"scope":"process_lifetime; maxima cover last128 completed jobs per lane",
            "lanes":lanes,"stopped":state.stopped,"failed":state.failure.is_some(),
            "resource_basis":"captured input and retained result mailboxes; native codec scratch has separate limits"}),
        )
    }
    pub fn health(&self) -> Result<(), String> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| "preparation state poisoned")?;
        if let Some(reason) = &state.failure {
            return Err(reason.clone());
        }
        if state.stopped {
            return Err("preparation workers stopped".into());
        }
        Ok(())
    }
}
impl<T: Send + 'static> Owner<T> {
    // Keep every authority coordinate and mailbox byte charge explicit at dispatch.
    #[allow(clippy::too_many_arguments)]
    pub fn submit(
        &self,
        lane: Lane,
        height: u64,
        round: u64,
        target: u64,
        input_digest: String,
        maximum_owned_bytes: usize,
        work: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Result<JobTag, String> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err("preparation incarnation cancelled".into());
        }
        if input_digest.is_empty() || input_digest.len() > 256 || maximum_owned_bytes == 0 {
            return Err("preparation input tag or byte charge is invalid".into());
        }
        let tag = JobTag {
            authority: self.authority.clone(),
            generation: self.generation,
            height,
            round,
            target,
            input_digest,
        };
        let index = lane.index();
        let submitted = Instant::now();
        let mut state = self
            .handle
            .shared
            .state
            .lock()
            .map_err(|_| "preparation state poisoned")?;
        if state.stopped || state.failure.is_some() {
            return Err("preparation workers unavailable".into());
        }
        if state.counts[index] >= COUNTS[index]
            || maximum_owned_bytes > BYTES[index].saturating_sub(state.bytes[index])
        {
            return Err("preparation backpressure".into());
        }
        state.counts[index] += 1;
        state.bytes[index] += maximum_owned_bytes;
        let reservation = Reservation {
            shared: Arc::downgrade(&self.handle.shared),
            lane: index,
            bytes: maximum_owned_bytes,
        };
        let returned = tag.clone();
        let cancelled = self.cancelled.clone();
        let sender = self.sender.clone();
        let job = Job {
            submitted,
            run: Box::new(move || {
                if cancelled.load(Ordering::Acquire) {
                    return;
                }
                let started = Instant::now();
                let result = work();
                let queue_wait = started.duration_since(submitted);
                let work_time = started.elapsed();
                if let Some(shared) = reservation.shared.upgrade() {
                    let mut state = shared
                        .state
                        .lock()
                        .map_err(|_| "preparation state poisoned")
                        .expect("worker observation lock");
                    state.completed[index] = state.completed[index].saturating_add(1);
                    if state.timings[index].len() == 128 {
                        state.timings[index].pop_front();
                    }
                    state.timings[index].push_back((
                        queue_wait.as_secs_f64() * 1000.0,
                        work_time.as_secs_f64() * 1000.0,
                    ));
                }
                if cancelled.load(Ordering::Acquire) {
                    return;
                }
                let completion = Completion {
                    tag,
                    result,
                    queue_wait,
                    work_time,
                    _reservation: reservation,
                };
                // Reservation accounting includes results until the owner consumes or drops them.
                match sender.try_send(completion) {
                    Ok(()) | Err(mpsc::TrySendError::Disconnected(_)) => {}
                    Err(mpsc::TrySendError::Full(completion)) => {
                        // Capacity equals all lane reservations, so overflow indicates an
                        // accounting violation. Fail closed instead of silently losing work.
                        if let Some(shared) = completion._reservation.shared.upgrade() {
                            if let Ok(mut state) = shared.state.lock() {
                                state.failure =
                                    Some("preparation completion accounting overflow".into());
                            }
                            shared.wake.notify_all();
                        }
                        drop(completion);
                    }
                }
            }),
        };
        state.queues[index].push_back(job);
        drop(state);
        self.handle.shared.wake.notify_all();
        Ok(returned)
    }
    pub fn take(&self) -> Result<Option<Completion<T>>, String> {
        self.handle.health()?;
        loop {
            match self.receiver.try_recv() {
                Ok(value)
                    if !self.cancelled.load(Ordering::Acquire)
                        && value.tag.authority == self.authority
                        && value.tag.generation == self.generation =>
                {
                    // Durations are also retained in the bounded pool observation window.
                    let _ = (value.queue_wait, value.work_time);
                    return Ok(Some(value));
                }
                Ok(_) => continue,
                Err(mpsc::TryRecvError::Empty) => return Ok(None),
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err("preparation completion channel disconnected".into())
                }
            }
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.handle.shared.wake.notify_all();
    }
}
impl<T> Drop for Owner<T> {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.handle.shared.wake.notify_all();
    }
}

pub struct Pool {
    handle: Handle,
    workers: Vec<JoinHandle<()>>,
}
impl Pool {
    pub fn new() -> Result<Self, String> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                queues: std::array::from_fn(|_| VecDeque::new()),
                counts: [0; 3],
                bytes: [0; 3],
                stopped: false,
                failure: None,
                completed: [0; 3],
                timings: std::array::from_fn(|_| VecDeque::new()),
            }),
            wake: Condvar::new(),
        });
        let mut pool = Self {
            handle: Handle { shared },
            workers: Vec::new(),
        };
        for lane in 0..3 {
            let shared = pool.handle.shared.clone();
            let worker = thread::Builder::new()
                .name(format!("synergy-preparation-{lane}"))
                .spawn(move || {
                    let outcome = catch_unwind(AssertUnwindSafe(|| loop {
                        let job = {
                            let Ok(mut state) = shared.state.lock() else {
                                return;
                            };
                            loop {
                                if state.stopped || state.failure.is_some() {
                                    return;
                                }
                                // Background dispatch stops when either reserved live lane is pressured.
                                let pressure = state.counts[0] >= 4
                                    || state.counts[1] >= 4
                                    || state.bytes[0] >= BYTES[0] / 2
                                    || state.bytes[1] >= BYTES[1] / 2;
                                if !(lane == 2 && pressure) {
                                    if let Some(job) = state.queues[lane].pop_front() {
                                        break job;
                                    }
                                }
                                state = match shared.wake.wait(state) {
                                    Ok(v) => v,
                                    Err(_) => return,
                                };
                            }
                        };
                        (job.run)();
                    }));
                    if outcome.is_err() {
                        if let Ok(mut state) = shared.state.lock() {
                            state.failure =
                                Some("preparation worker panicked; owner must fail closed".into());
                        }
                        shared.wake.notify_all();
                    }
                })
                .map_err(|e| format!("spawn preparation worker: {e}"))?;
            pool.workers.push(worker);
        }
        Ok(pool)
    }
    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }
    pub fn shutdown(&mut self) -> Result<(), String> {
        let discarded = {
            let mut state = self
                .handle
                .shared
                .state
                .lock()
                .map_err(|_| "preparation state poisoned")?;
            state.stopped = true;
            state
                .queues
                .iter_mut()
                .flat_map(|q| q.drain(..))
                .collect::<Vec<_>>()
        };
        drop(discarded); // Reservation drops must occur outside the queue lock.
        self.handle.shared.wake.notify_all();
        let deadline = Instant::now() + SHUTDOWN_BUDGET;
        while self.workers.iter().any(|w| !w.is_finished()) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(2));
        }
        if self.workers.iter().any(|w| !w.is_finished()) {
            return Err("preparation shutdown deadline exceeded; replacement prohibited".into());
        }
        for worker in self.workers.drain(..) {
            worker
                .join()
                .map_err(|_| "preparation worker join failed")?;
        }
        Ok(())
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tag() -> AuthorityTag {
        AuthorityTag {
            incarnation: "isolated-test".into(),
            epoch: 1,
            authority_digest: "authority-test".into(),
        }
    }
    fn wait_for_result<T: Send + 'static>(owner: &Owner<T>) -> Completion<T> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(result) = owner.take().unwrap() {
                return result;
            }
            assert!(Instant::now() < deadline, "worker did not finish");
            thread::yield_now();
        }
    }
    #[test]
    fn retained_completion_keeps_mailbox_reservation_until_consumed() {
        let mut pool = Pool::new().unwrap();
        let owner = pool.handle().owner::<u64>(tag()).unwrap();
        owner
            .submit(Lane::Admission, 3, 0, 8, "input".into(), BYTES[1], || Ok(7))
            .unwrap();
        let result = wait_for_result(&owner);
        assert_eq!(result.result.as_ref().unwrap(), &7);
        assert_eq!(
            owner
                .submit(Lane::Admission, 3, 0, 8, "next".into(), 1, || Ok(8))
                .unwrap_err(),
            "preparation backpressure"
        );
        drop(result);
        owner
            .submit(Lane::Admission, 3, 0, 8, "next".into(), 1, || Ok(8))
            .unwrap();
        assert_eq!(wait_for_result(&owner).result.unwrap(), 8);
        pool.shutdown().unwrap();
    }
    #[test]
    fn repeated_full_mailbox_backlogs_drain_without_retained_reservations() {
        let mut pool = Pool::new().unwrap();
        let handle = pool.handle();
        let owner = handle.owner::<Vec<u8>>(tag()).unwrap();
        let mut completed = 0;
        for cycle in 0..32 {
            for index in 0..COUNTS[1] {
                owner
                    .submit(
                        Lane::Admission,
                        cycle,
                        0,
                        cycle + 1,
                        format!("queue-{cycle}-{index}"),
                        BYTES[1] / COUNTS[1],
                        move || Ok(vec![index as u8; BYTES[1] / COUNTS[1]]),
                    )
                    .unwrap();
            }
            let full = handle.observations().unwrap();
            let lane = &full["lanes"][1];
            assert_eq!(lane["reserved_jobs"], COUNTS[1]);
            assert_eq!(lane["reserved_mailbox_bytes"], BYTES[1]);
            assert_eq!(
                owner
                    .submit(
                        Lane::Admission,
                        cycle,
                        0,
                        cycle + 1,
                        "overflow".into(),
                        1,
                        || Ok(Vec::new())
                    )
                    .unwrap_err(),
                "preparation backpressure"
            );
            for _ in 0..COUNTS[1] {
                let result = wait_for_result(&owner);
                assert_eq!(result.result.as_ref().unwrap().len(), BYTES[1] / COUNTS[1]);
                completed += 1;
                drop(result);
            }
            let drained = handle.observations().unwrap();
            assert_eq!(drained["lanes"][1]["reserved_jobs"], 0);
            assert_eq!(drained["lanes"][1]["reserved_mailbox_bytes"], 0);
        }
        eprintln!("EINSTEIN_QUEUE_MEASUREMENT {{\"cycles\":32,\"completed_jobs\":{completed},\"maximum_reserved_jobs\":{},\"maximum_reserved_bytes\":{},\"after_drain_jobs\":0,\"after_drain_bytes\":0}}", COUNTS[1], BYTES[1]);
        pool.shutdown().unwrap();
    }

    #[test]
    fn cancelled_owner_cannot_publish_to_replacement_generation() {
        let mut pool = Pool::new().unwrap();
        let old = pool.handle().owner::<u64>(tag()).unwrap();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let old_tag = old
            .submit(Lane::Consensus, 3, 1, 3, "old".into(), 1, move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(1)
            })
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        old.cancel();
        let replacement = pool.handle().owner::<u64>(tag()).unwrap();
        let new_tag = replacement
            .submit(Lane::Consensus, 3, 1, 3, "new".into(), 1, || Ok(2))
            .unwrap();
        assert_ne!(old_tag.generation, new_tag.generation);
        release_tx.send(()).unwrap();
        assert_eq!(wait_for_result(&replacement).result.unwrap(), 2);
        assert!(old.take().unwrap().is_none());
        pool.shutdown().unwrap();
    }
    #[test]
    fn panic_latches_failure_and_prohibits_more_work() {
        let mut pool = Pool::new().unwrap();
        let owner = pool.handle().owner::<()>(tag()).unwrap();
        owner
            .submit(Lane::Consensus, 3, 0, 3, "panic".into(), 1, || {
                panic!("injected worker failure")
            })
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while pool.handle().health().is_ok() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert!(owner
            .submit(Lane::Admission, 3, 0, 8, "after".into(), 1, || Ok(()))
            .is_err());
        pool.shutdown().unwrap();
    }
}

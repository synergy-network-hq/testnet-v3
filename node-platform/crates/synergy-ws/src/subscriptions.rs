use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{WsError, WsEvent, WsTopic};

#[derive(Debug)]
struct Subscriber {
    topics: BTreeSet<WsTopic>,
    queue: VecDeque<WsEvent>,
    dropped: u64,
}

#[derive(Debug)]
pub struct SubscriptionHub {
    max_subscribers: usize,
    queue_capacity: usize,
    subscribers: BTreeMap<String, Subscriber>,
}

impl SubscriptionHub {
    pub fn new(max_subscribers: usize, queue_capacity: usize) -> Result<Self, WsError> {
        if max_subscribers == 0 || queue_capacity == 0 {
            return Err(WsError::InvalidSubscription);
        }
        Ok(Self {
            max_subscribers,
            queue_capacity,
            subscribers: BTreeMap::new(),
        })
    }

    pub fn subscribe(
        &mut self,
        subscriber_id: impl Into<String>,
        topics: BTreeSet<WsTopic>,
    ) -> Result<(), WsError> {
        let subscriber_id = subscriber_id.into();
        if subscriber_id.trim().is_empty() || topics.is_empty() {
            return Err(WsError::InvalidSubscription);
        }
        if !self.subscribers.contains_key(&subscriber_id)
            && self.subscribers.len() >= self.max_subscribers
        {
            return Err(WsError::SubscriberCapacity);
        }
        self.subscribers.insert(
            subscriber_id,
            Subscriber {
                topics,
                queue: VecDeque::new(),
                dropped: 0,
            },
        );
        Ok(())
    }

    pub fn unsubscribe(&mut self, subscriber_id: &str) -> bool {
        self.subscribers.remove(subscriber_id).is_some()
    }

    pub fn publish(&mut self, event: WsEvent) -> usize {
        let mut delivered = 0;
        for subscriber in self.subscribers.values_mut() {
            if !subscriber.topics.contains(&event.topic) {
                continue;
            }
            if subscriber.queue.len() >= self.queue_capacity {
                subscriber.queue.pop_front();
                subscriber.dropped = subscriber.dropped.saturating_add(1);
            }
            subscriber.queue.push_back(event.clone());
            delivered += 1;
        }
        delivered
    }

    pub fn drain(&mut self, subscriber_id: &str, limit: usize) -> Result<Vec<WsEvent>, WsError> {
        if limit == 0 {
            return Err(WsError::InvalidSubscription);
        }
        let subscriber = self
            .subscribers
            .get_mut(subscriber_id)
            .ok_or(WsError::UnknownSubscriber)?;
        Ok((0..limit)
            .filter_map(|_| subscriber.queue.pop_front())
            .collect())
    }

    pub fn dropped(&self, subscriber_id: &str) -> Result<u64, WsError> {
        self.subscribers
            .get(subscriber_id)
            .map(|subscriber| subscriber.dropped)
            .ok_or(WsError::UnknownSubscriber)
    }
}

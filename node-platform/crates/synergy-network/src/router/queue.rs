use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    InvalidCapacity,
    Capacity,
}

#[derive(Debug)]
pub struct BoundedQueue<T> {
    capacity: usize,
    items: VecDeque<T>,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: usize) -> Result<Self, QueueError> {
        if capacity == 0 {
            return Err(QueueError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            items: VecDeque::new(),
        })
    }

    pub fn push(&mut self, item: T) -> Result<(), QueueError> {
        if self.items.len() >= self.capacity {
            return Err(QueueError::Capacity);
        }
        self.items.push_back(item);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

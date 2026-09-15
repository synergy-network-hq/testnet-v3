use crate::FinalizedBlockRecord;

pub trait FinalityObserver {
    fn on_finalized(&mut self, record: &FinalizedBlockRecord);
}

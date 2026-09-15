use crate::{FinalizedBlockRecord, PosyResult};

pub trait FinalizedCommitSink {
    fn commit_verified_finalization(&mut self, record: &FinalizedBlockRecord) -> PosyResult<()>;
}

pub fn commit_finalized(
    sink: &mut impl FinalizedCommitSink,
    record: &FinalizedBlockRecord,
) -> PosyResult<()> {
    sink.commit_verified_finalization(record)
}

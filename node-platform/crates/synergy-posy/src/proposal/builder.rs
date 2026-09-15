use crate::{PosyError, PosyResult, SimplifiedProposal};

pub trait ProposalMaterialSource {
    fn protected_execution_root(&mut self, height: u64) -> PosyResult<String>;
    fn block_id(&mut self, height: u64) -> PosyResult<String>;
}

pub fn build_proposal(
    source: &mut impl ProposalMaterialSource,
    mut template: SimplifiedProposal,
) -> PosyResult<SimplifiedProposal> {
    let block_id = source.block_id(template.context.height)?;
    let protected_execution_root = source.protected_execution_root(template.context.height)?;
    if block_id.trim().is_empty() || protected_execution_root.trim().is_empty() {
        return Err(PosyError::invalid(
            "verified proposal material is incomplete",
        ));
    }
    if (!template.block_id.trim().is_empty() && template.block_id != block_id)
        || (!template.protected_execution_root.trim().is_empty()
            && template.protected_execution_root != protected_execution_root)
    {
        return Err(PosyError::Conflict(
            "proposal template conflicts with verified material".into(),
        ));
    }
    template.block_id = block_id;
    template.protected_execution_root = protected_execution_root;
    template.validate_shape()?;
    Ok(template)
}

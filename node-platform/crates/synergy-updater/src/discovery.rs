use crate::{AutomaticUpdatePolicy, MAXIMUM_CATALOG_RELEASES};

pub trait ReleaseCatalog: Send + Sync {
    fn fetch(&self) -> Result<Vec<crate::SignedReleaseMetadata>, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseDiscovery {
    pub candidate: crate::SignedReleaseMetadata,
}

pub fn discover_release(
    catalog: &dyn ReleaseCatalog,
    policy: &AutomaticUpdatePolicy,
    installed_sequence: u64,
) -> Result<Option<ReleaseDiscovery>, String> {
    policy.validate().map_err(str::to_owned)?;
    let releases = catalog.fetch()?;
    if releases.len() > MAXIMUM_CATALOG_RELEASES {
        return Err("release catalog exceeds bounded capacity".into());
    }
    let candidate = releases
        .into_iter()
        .filter(|entry| entry.release.channel == policy.channel)
        .filter(|entry| entry.release.sequence > installed_sequence)
        .max_by_key(|entry| entry.release.sequence);
    Ok(candidate.map(|candidate| ReleaseDiscovery { candidate }))
}

pub(crate) fn release_is_newer(
    candidate: &crate::ReleaseMetadata,
    installed_sequence: u64,
) -> bool {
    candidate.sequence > installed_sequence
}

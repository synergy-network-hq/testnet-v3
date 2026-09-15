use crate::{coordination::select_provider, AiJob, AiPolicy, ProviderAdvertisement};
pub fn schedule(
    jobs: &[AiJob],
    p: &AiPolicy,
    providers: &[ProviderAdvertisement],
) -> Result<Vec<(String, String)>, String> {
    let mut jobs = jobs.iter().collect::<Vec<_>>();
    jobs.sort_by_key(|j| &j.job_id);
    jobs.into_iter()
        .map(|j| {
            Ok((
                j.job_id.clone(),
                select_provider(j, p, providers)?.provider_id.clone(),
            ))
        })
        .collect()
}

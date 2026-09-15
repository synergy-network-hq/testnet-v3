use crate::{AiJob, AiPolicy, ProviderAdvertisement};
pub fn select_provider<'a>(
    j: &AiJob,
    p: &AiPolicy,
    providers: &'a [ProviderAdvertisement],
) -> Result<&'a ProviderAdvertisement, String> {
    p.authorize(j)?;
    providers
        .iter()
        .filter(|v| v.accepts(j).is_ok())
        .min_by_key(|v| &v.provider_id)
        .ok_or("no eligible AI provider".into())
}

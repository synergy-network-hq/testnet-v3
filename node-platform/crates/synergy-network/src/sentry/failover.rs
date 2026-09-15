use super::ValidatorLink;

pub fn select_validator_link<'a>(
    links: &'a [ValidatorLink],
    validator_id: &str,
) -> Result<&'a ValidatorLink, String> {
    let mut eligible = links
        .iter()
        .filter(|link| link.validator_id == validator_id && link.healthy)
        .collect::<Vec<_>>();
    for link in &eligible {
        link.validate()?;
    }
    eligible.sort_by(|left, right| {
        left.sentry_id
            .cmp(&right.sentry_id)
            .then_with(|| left.overlay_address.cmp(&right.overlay_address))
    });
    eligible
        .into_iter()
        .next()
        .ok_or_else(|| "no healthy validator Sentry link".into())
}

//! Offline certified recovery. These commands never construct a signer/runtime.
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub action: Action,
    pub config: PathBuf,
    pub bundle: PathBuf,
    pub from: Option<(u64, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Export,
    Import,
    RestoreAuthorizationSource,
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Request, String> {
    let mut args = args.into_iter();
    let action = match args.next().as_deref() {
        Some("export") => Action::Export,
        Some("import") => Action::Import,
        Some("restore-authorization-source") => Action::RestoreAuthorizationSource,
        _ => {
            return Err("checkpoint requires export, import or restore-authorization-source".into())
        }
    };
    let mut options = BTreeMap::new();
    while let Some(key) = args.next() {
        if !matches!(
            key.as_str(),
            "--config" | "--bundle" | "--from-height" | "--from-block-id"
        ) {
            return Err(format!("unknown checkpoint option {key}"));
        }
        let value = args
            .next()
            .ok_or_else(|| format!("{key} requires a value"))?;
        if options.insert(key, value).is_some() {
            return Err("checkpoint option supplied twice".into());
        }
    }
    let config = super::absolute_path(
        options
            .get("--config")
            .ok_or("checkpoint requires --config")?,
        "configuration",
    )?;
    let bundle = super::absolute_path(
        options
            .get("--bundle")
            .ok_or("checkpoint requires --bundle")?,
        "bundle",
    )?;
    let from = if action != Action::Export {
        if options.contains_key("--from-height") || options.contains_key("--from-block-id") {
            return Err("only checkpoint export accepts an explicit anchor".into());
        }
        None
    } else {
        let height = super::parse_u64(
            options
                .get("--from-height")
                .ok_or("checkpoint export requires --from-height")?,
            "anchor height",
            false,
        )?;
        let block = options
            .get("--from-block-id")
            .ok_or("checkpoint export requires --from-block-id")?
            .clone();
        if !synergy_posy::is_hash(&block) {
            return Err("invalid checkpoint anchor block ID".into());
        }
        Some((height, block))
    };
    Ok(Request {
        action,
        config,
        bundle,
        from,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checkpoint_cli_requires_explicit_network_config_anchor_and_safe_actions() {
        let parse_args = |args: &[&str]| parse(args.iter().map(|v| (*v).to_string()));
        assert_eq!(
            parse_args(&[
                "import",
                "--config",
                "/node/config",
                "--bundle",
                "/recovery/bundle"
            ])
            .unwrap()
            .action,
            Action::Import
        );
        assert_eq!(
            parse_args(&[
                "restore-authorization-source",
                "--config",
                "/node/config",
                "--bundle",
                "/recovery/candidate.json",
            ])
            .unwrap()
            .action,
            Action::RestoreAuthorizationSource
        );
        assert!(parse_args(&[
            "export",
            "--config",
            "/node/config",
            "--bundle",
            "/recovery/bundle",
            "--from-height",
            "9",
            "--from-block-id",
            &"a".repeat(64)
        ])
        .is_ok());
        for args in [
            vec!["import", "--config", "relative", "--bundle", "/bundle"],
            vec![
                "import",
                "--config",
                "/config",
                "--bundle",
                "/bundle",
                "--from-height",
                "1",
            ],
            vec!["export", "--config", "/config", "--bundle", "/bundle"],
            vec![
                "restore-authorization-source",
                "--config",
                "/config",
                "--bundle",
                "/candidate",
                "--from-height",
                "1",
            ],
            vec!["reset", "--config", "/config", "--bundle", "/bundle"],
        ] {
            assert!(parse_args(&args).is_err());
        }
    }
}

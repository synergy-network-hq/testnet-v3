use std::path::PathBuf;

use super::absolute_path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestRequest {
    Inspect { path: PathBuf },
    Verify { path: PathBuf, public_key: PathBuf },
}

pub fn request(
    action: &str,
    path: &str,
    public_key: Option<&str>,
) -> Result<ManifestRequest, String> {
    let path = absolute_path(path, "manifest path")?;
    match action {
        "inspect" => Ok(ManifestRequest::Inspect { path }),
        "verify" => Ok(ManifestRequest::Verify {
            path,
            public_key: absolute_path(
                public_key.ok_or("manifest verify requires a public key path")?,
                "manifest public key path",
            )?,
        }),
        _ => Err("manifest action must be inspect or verify".into()),
    }
}

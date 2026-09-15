mod export;
mod inspect;
mod migrate;
mod repair;
mod verify;

use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("synergy-db: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().ok_or(usage())?;
    match command.as_str() {
        "inspect" => {
            let root = path(&mut arguments, "database root")?;
            finish(&mut arguments)?;
            let inventory = inspect::inspect(&root)?;
            println!(
                "root={} files={} bytes={}",
                inventory.root.display(),
                inventory.entries.len(),
                inventory.total_bytes
            );
            for entry in inventory.entries {
                println!("{}\t{}", entry.bytes, entry.relative_path.display());
            }
        }
        "verify" => {
            let root = path(&mut arguments, "database root")?;
            finish(&mut arguments)?;
            let verified = verify::verify(&root)?;
            println!(
                "verified files={} bytes={} digest={} schema={}",
                verified.inventory.entries.len(),
                verified.inventory.total_bytes,
                verified.digest.0,
                verified
                    .schema
                    .map(|(name, version)| format!("{name}:{version}"))
                    .unwrap_or_else(|| "unversioned".into())
            );
        }
        "export" => {
            let source = path(&mut arguments, "source database")?;
            let destination = path(&mut arguments, "export destination")?;
            finish(&mut arguments)?;
            export::export(&source, &destination)?;
            println!("exported {} -> {}", source.display(), destination.display());
        }
        "migrate" => {
            let root = path(&mut arguments, "database root")?;
            let schema = arguments.next().ok_or("missing schema name")?;
            let version = arguments
                .next()
                .ok_or("missing target schema version")?
                .parse::<u32>()
                .map_err(|_| "target schema version must be a u32")?;
            finish(&mut arguments)?;
            migrate::migrate(&root, &schema, version)?;
            println!("schema={schema}:{version}");
        }
        "repair" => {
            let root = path(&mut arguments, "database root")?;
            let apply = match arguments.next() {
                None => false,
                Some(flag) if flag == "--apply" => true,
                Some(_) => return Err("repair accepts only the optional --apply flag".into()),
            };
            finish(&mut arguments)?;
            let plan = repair::plan(&root)?;
            for path in &plan.stale_temporary_files {
                println!("{}", path.display());
            }
            if apply {
                println!("removed={}", repair::apply(&root, &plan)?);
            } else {
                println!(
                    "dry-run files={}; pass --apply to remove only listed temporary files",
                    plan.stale_temporary_files.len()
                );
            }
        }
        _ => return Err(usage()),
    }
    Ok(())
}

fn path(arguments: &mut impl Iterator<Item = String>, label: &str) -> Result<PathBuf, String> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {label}"))
}

fn finish(arguments: &mut impl Iterator<Item = String>) -> Result<(), String> {
    arguments
        .next()
        .is_none()
        .then_some(())
        .ok_or_else(|| "unexpected trailing arguments".into())
}

fn usage() -> String {
    "usage: synergy-db <inspect ROOT|verify ROOT|export ROOT DEST|migrate ROOT NAME VERSION|repair ROOT [--apply]>".into()
}

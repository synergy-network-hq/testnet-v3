//! Version requirement parsing and validation for SynQ compiler

use std::cmp::Ordering;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl FromStr for Version {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(format!("Invalid version format: {}", s));
        }

        let major = parts[0]
            .parse::<u32>()
            .map_err(|_| format!("Invalid major version: {}", parts[0]))?;
        let minor = parts[1]
            .parse::<u32>()
            .map_err(|_| format!("Invalid minor version: {}", parts[1]))?;
        let patch = if parts.len() == 3 {
            parts[2]
                .parse::<u32>()
                .map_err(|_| format!("Invalid patch version: {}", parts[2]))?
        } else {
            0
        };

        Ok(Version {
            major,
            minor,
            patch,
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => Some(self.patch.cmp(&other.patch)),
                other => Some(other),
            },
            other => Some(other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VersionRequirement {
    pub comparator: String,
    pub version: Version,
}

impl VersionRequirement {
    pub fn satisfies(&self, compiler_version: &Version) -> Result<bool, String> {
        match self.comparator.as_str() {
            "^" => {
                // Caret: compatible within same major version
                // ^1.0.0 matches >=1.0.0 <2.0.0
                Ok(compiler_version >= &self.version
                    && compiler_version.major == self.version.major)
            }
            ">=" => Ok(compiler_version >= &self.version),
            "<=" => Ok(compiler_version <= &self.version),
            ">" => Ok(compiler_version > &self.version),
            "<" => Ok(compiler_version < &self.version),
            "=" => Ok(compiler_version == &self.version),
            _ => Err(format!("Unknown comparator: {}", self.comparator)),
        }
    }
}

impl FromStr for VersionRequirement {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        if s.starts_with('^') {
            let version_str = &s[1..];
            let version = Version::from_str(version_str)?;
            Ok(VersionRequirement {
                comparator: "^".to_string(),
                version,
            })
        } else if s.starts_with(">=") {
            let version_str = &s[2..];
            let version = Version::from_str(version_str)?;
            Ok(VersionRequirement {
                comparator: ">=".to_string(),
                version,
            })
        } else if s.starts_with("<=") {
            let version_str = &s[2..];
            let version = Version::from_str(version_str)?;
            Ok(VersionRequirement {
                comparator: "<=".to_string(),
                version,
            })
        } else if s.starts_with('>') {
            let version_str = &s[1..];
            let version = Version::from_str(version_str)?;
            Ok(VersionRequirement {
                comparator: ">".to_string(),
                version,
            })
        } else if s.starts_with('<') {
            let version_str = &s[1..];
            let version = Version::from_str(version_str)?;
            Ok(VersionRequirement {
                comparator: "<".to_string(),
                version,
            })
        } else if s.starts_with('=') {
            let version_str = &s[1..];
            let version = Version::from_str(version_str)?;
            Ok(VersionRequirement {
                comparator: "=".to_string(),
                version,
            })
        } else {
            // Default to caret if no comparator
            let version = Version::from_str(s)?;
            Ok(VersionRequirement {
                comparator: "^".to_string(),
                version,
            })
        }
    }
}

pub fn get_compiler_version() -> Version {
    // In real implementation, would read from Cargo.toml or version file
    Version {
        major: 1,
        minor: 0,
        patch: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let v = Version::from_str("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);

        let v = Version::from_str("1.2").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_version_comparison() {
        let v1 = Version::from_str("1.0.0").unwrap();
        let v2 = Version::from_str("1.0.1").unwrap();
        assert!(v2 > v1);

        let v3 = Version::from_str("2.0.0").unwrap();
        assert!(v3 > v1);
    }

    #[test]
    fn test_version_requirement() {
        let req = VersionRequirement::from_str("^1.0.0").unwrap();
        let compiler = Version::from_str("1.5.0").unwrap();
        assert!(req.satisfies(&compiler).unwrap());

        let compiler2 = Version::from_str("2.0.0").unwrap();
        assert!(!req.satisfies(&compiler2).unwrap());
    }
}

//! Exact three node-platform groups, with closed architecture/ABI slots.
//! Pins are artifact integrity data, never release or activation qualification.
//! None is an explicit unresolved target; a Darwin pin is never reused for Linux.
use super::GenesisError;
use synergy_address_engine::apqe::{
    provider::Target,
    r1_framing::{self as c, Value},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactTarget {
    LinuxX86_64Gnu,
    LinuxArm64Gnu,
    MacosArm64,
    MacosX86_64,
    WindowsX86_64Gnu,
    WindowsX86_64Msvc,
    WindowsArm64Msvc,
}
impl ArtifactTarget {
    pub const ALL: [Self; 7] = [
        Self::LinuxX86_64Gnu,
        Self::LinuxArm64Gnu,
        Self::MacosArm64,
        Self::MacosX86_64,
        Self::WindowsX86_64Gnu,
        Self::WindowsX86_64Msvc,
        Self::WindowsArm64Msvc,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::LinuxX86_64Gnu => "linux-x86_64-gnu",
            Self::LinuxArm64Gnu => "linux-arm64-gnu",
            Self::MacosArm64 => "macos-arm64",
            Self::MacosX86_64 => "macos-x86_64",
            Self::WindowsX86_64Gnu => "windows-x86_64-gnu",
            Self::WindowsX86_64Msvc => "windows-x86_64-msvc",
            Self::WindowsArm64Msvc => "windows-arm64-msvc",
        }
    }
    pub fn from_provider(target: Target) -> Result<Self, GenesisError> {
        match target {
            Target::DarwinArm64 => Ok(Self::MacosArm64),
            Target::LinuxX86_64Gnu => Ok(Self::LinuxX86_64Gnu),
            Target::LinuxArm64Gnu => Ok(Self::LinuxArm64Gnu),
            Target::WindowsX86_64Gnu => Ok(Self::WindowsX86_64Gnu),
            _ => Err(GenesisError::Profile),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactPins {
    pub mldsa65: [u8; 32],
    pub mldsa87: [u8; 32],
    pub mlkem1024: [u8; 32],
}
impl ArtifactPins {
    fn validate(&self) -> Result<(), GenesisError> {
        if [self.mldsa65, self.mldsa87, self.mlkem1024].contains(&[0; 32]) {
            Err(GenesisError::Profile)
        } else {
            Ok(())
        }
    }
    fn value(&self) -> Result<Value, GenesisError> {
        self.validate()?;
        Ok(Value::Array(vec![
            Value::Array(vec![Value::Unsigned(65), c::bytes(&self.mldsa65)]),
            Value::Array(vec![Value::Unsigned(87), c::bytes(&self.mldsa87)]),
            Value::Array(vec![Value::Unsigned(1024), c::bytes(&self.mlkem1024)]),
        ]))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PlatformArtifactMatrix {
    pub linux: LinuxArtifacts,
    pub macos: MacosArtifacts,
    pub windows: WindowsArtifacts,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LinuxArtifacts {
    pub x86_64_gnu: Option<ArtifactPins>,
    pub arm64_gnu: Option<ArtifactPins>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MacosArtifacts {
    pub arm64: Option<ArtifactPins>,
    pub x86_64: Option<ArtifactPins>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WindowsArtifacts {
    pub x86_64_gnu: Option<ArtifactPins>,
    pub x86_64_msvc: Option<ArtifactPins>,
    pub arm64_msvc: Option<ArtifactPins>,
}
impl PlatformArtifactMatrix {
    pub fn darwin_public_validation_only(pins: ArtifactPins) -> Self {
        Self {
            macos: MacosArtifacts {
                arm64: Some(pins),
                x86_64: None,
            },
            ..Self::default()
        }
    }
    pub fn get(&self, target: ArtifactTarget) -> Option<&ArtifactPins> {
        match target {
            ArtifactTarget::LinuxX86_64Gnu => self.linux.x86_64_gnu.as_ref(),
            ArtifactTarget::LinuxArm64Gnu => self.linux.arm64_gnu.as_ref(),
            ArtifactTarget::MacosArm64 => self.macos.arm64.as_ref(),
            ArtifactTarget::MacosX86_64 => self.macos.x86_64.as_ref(),
            ArtifactTarget::WindowsX86_64Gnu => self.windows.x86_64_gnu.as_ref(),
            ArtifactTarget::WindowsX86_64Msvc => self.windows.x86_64_msvc.as_ref(),
            ArtifactTarget::WindowsArm64Msvc => self.windows.arm64_msvc.as_ref(),
        }
    }
    pub fn unresolved_targets(&self) -> Vec<ArtifactTarget> {
        ArtifactTarget::ALL
            .into_iter()
            .filter(|t| self.get(*t).is_none())
            .collect()
    }
    /// Closed typed mapping of an already strictly decoded APQE value. No ABI
    /// aliases, unknown target slots or zero-filled missing-artifact records.
    pub fn from_canonical_value(value: &Value) -> Result<Self, GenesisError> {
        let Value::Array(groups) = value else {
            return Err(GenesisError::Profile);
        };
        if groups.len() != 3 {
            return Err(GenesisError::Profile);
        }
        let mut result = Self::default();
        for (group, name, targets) in [
            (&groups[0], "linux", &ArtifactTarget::ALL[0..2]),
            (&groups[1], "macos", &ArtifactTarget::ALL[2..4]),
            (&groups[2], "windows", &ArtifactTarget::ALL[4..7]),
        ] {
            let Value::Array(fields) = group else {
                return Err(GenesisError::Profile);
            };
            let [Value::Text(actual_name), Value::Array(slots)] = fields.as_slice() else {
                return Err(GenesisError::Profile);
            };
            if actual_name != name || slots.len() != targets.len() {
                return Err(GenesisError::Profile);
            }
            for (slot, target) in slots.iter().zip(targets) {
                let Value::Array(fields) = slot else {
                    return Err(GenesisError::Profile);
                };
                let [Value::Text(actual_target), Value::Array(optional)] = fields.as_slice() else {
                    return Err(GenesisError::Profile);
                };
                if actual_target != target.name() {
                    return Err(GenesisError::Profile);
                }
                let pins = match optional.as_slice() {
                    [] => None,
                    [Value::Array(pins)] => {
                        let [Value::Array(a), Value::Array(b), Value::Array(c)] = pins.as_slice()
                        else {
                            return Err(GenesisError::Profile);
                        };
                        fn pin(row: &[Value], algorithm: u64) -> Result<[u8; 32], GenesisError> {
                            let [Value::Unsigned(actual), Value::Bytes(bytes)] = row else {
                                return Err(GenesisError::Profile);
                            };
                            if *actual != algorithm {
                                return Err(GenesisError::Profile);
                            }
                            bytes
                                .as_slice()
                                .try_into()
                                .map_err(|_| GenesisError::Profile)
                        }
                        let p = ArtifactPins {
                            mldsa65: pin(a, 65)?,
                            mldsa87: pin(b, 87)?,
                            mlkem1024: pin(c, 1024)?,
                        };
                        p.validate()?;
                        Some(p)
                    }
                    _ => return Err(GenesisError::Profile),
                };
                match target {
                    ArtifactTarget::LinuxX86_64Gnu => result.linux.x86_64_gnu = pins,
                    ArtifactTarget::LinuxArm64Gnu => result.linux.arm64_gnu = pins,
                    ArtifactTarget::MacosArm64 => result.macos.arm64 = pins,
                    ArtifactTarget::MacosX86_64 => result.macos.x86_64 = pins,
                    ArtifactTarget::WindowsX86_64Gnu => result.windows.x86_64_gnu = pins,
                    ArtifactTarget::WindowsX86_64Msvc => result.windows.x86_64_msvc = pins,
                    ArtifactTarget::WindowsArm64Msvc => result.windows.arm64_msvc = pins,
                }
            }
        }
        if result.canonical_value()? != *value {
            return Err(GenesisError::Profile);
        }
        Ok(result)
    }
    pub fn canonical_value(&self) -> Result<Value, GenesisError> {
        fn slot(
            target: ArtifactTarget,
            pins: Option<&ArtifactPins>,
        ) -> Result<Value, GenesisError> {
            Ok(Value::Array(vec![
                c::text(target.name()),
                Value::Array(match pins {
                    None => vec![],
                    Some(p) => vec![p.value()?],
                }),
            ]))
        }
        fn group(
            matrix: &PlatformArtifactMatrix,
            name: &str,
            targets: &[ArtifactTarget],
        ) -> Result<Value, GenesisError> {
            Ok(Value::Array(vec![
                c::text(name),
                Value::Array(
                    targets
                        .iter()
                        .map(|t| slot(*t, matrix.get(*t)))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ]))
        }
        Ok(Value::Array(vec![
            group(self, "linux", &ArtifactTarget::ALL[0..2])?,
            group(self, "macos", &ArtifactTarget::ALL[2..4])?,
            group(self, "windows", &ArtifactTarget::ALL[4..7])?,
        ]))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exactly_three_groups_keep_missing_targets_and_platform_pins_distinct() {
        let pins = ArtifactPins {
            mldsa65: [1; 32],
            mldsa87: [2; 32],
            mlkem1024: [3; 32],
        };
        let mut m = PlatformArtifactMatrix::darwin_public_validation_only(pins);
        assert_eq!(m.unresolved_targets().len(), 6);
        assert_eq!(m.get(ArtifactTarget::MacosArm64), Some(&pins));
        assert_eq!(m.get(ArtifactTarget::LinuxX86_64Gnu), None);
        let before = m.canonical_value().unwrap().encode(65536).unwrap();
        m.linux.x86_64_gnu = Some(ArtifactPins {
            mldsa65: [4; 32],
            ..pins
        });
        let after = m.canonical_value().unwrap().encode(65536).unwrap();
        assert_ne!(before, after);
        assert_eq!(m.get(ArtifactTarget::MacosArm64), Some(&pins));
        let groups = Value::decode(&after, 65536).unwrap();
        assert!(matches!(groups,Value::Array(ref groups) if groups.len()==3));
        m.windows.x86_64_gnu = Some(pins);
        assert_eq!(
            ArtifactTarget::from_provider(Target::WindowsX86_64Gnu).unwrap(),
            ArtifactTarget::WindowsX86_64Gnu
        );
        assert_eq!(m.get(ArtifactTarget::WindowsX86_64Gnu), Some(&pins));
        assert_eq!(m.get(ArtifactTarget::WindowsX86_64Msvc), None);
        assert_eq!(m.get(ArtifactTarget::WindowsArm64Msvc), None);
        m.windows.x86_64_msvc = Some(ArtifactPins {
            mldsa65: [0; 32],
            ..pins
        });
        assert!(m.canonical_value().is_err());
        assert!(ArtifactTarget::from_provider(Target::Other).is_err());
    }
}

//! Typed public R1 presentation for explicit preparation consumers only.
//! Identity R1 pp265,269–271: parsing does not authenticate a network or grant
//! authorization. The historical NodeAddress parser is deliberately separate.
use crate::NodeClass;
use synergy_address::r1_public::NativeIdentityPresentation;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1NodePresentation {
    text: String,
    class: NodeClass,
    raw48: [u8; 48],
}
impl R1NodePresentation {
    /// Expected class comes from the selected role profile, never the prefix.
    pub fn parse(text: &str, expected: NodeClass) -> Result<Self, &'static str> {
        let parsed = NativeIdentityPresentation::parse(text)
            .map_err(|_| "invalid full-width R1 public presentation")?;
        if parsed.namespace() != format!("synv{}", expected.digit()) {
            return Err("R1 node class differs from selected role profile");
        }
        Ok(Self {
            text: parsed.to_text(),
            class: expected,
            raw48: *parsed.raw48(),
        })
    }
    pub fn as_str(&self) -> &str {
        &self.text
    }
    pub fn class(&self) -> NodeClass {
        self.class
    }
    pub fn raw48(&self) -> &[u8; 48] {
        &self.raw48
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_width_candidate_preserves_all_five_classes_and_case() {
        for digit in 1..=5 {
            let class = NodeClass::try_from(digit).unwrap();
            let text = format!("synv{digit}.2.{}", "A".repeat(64));
            let parsed = R1NodePresentation::parse(&text, class).unwrap();
            assert_eq!(parsed.as_str(), text);
            assert_eq!(parsed.raw48(), &[0; 48]);
            assert_eq!(parsed.class(), class);
            let lower = text.replace(&"A".repeat(64), &"a".repeat(64));
            assert_ne!(
                R1NodePresentation::parse(&lower, class).unwrap().raw48(),
                parsed.raw48()
            );
            assert!(crate::NodeAddress::parse(text).is_err());
        }
    }
    #[test]
    fn explicit_profile_refuses_wrong_class_and_historical_or_malformed_text() {
        let class = NodeClass::ConsensusAndChainIntegrity;
        for text in [
            format!("synv5.2.{}", "A".repeat(64)),
            format!("synv1.2.{}=", "A".repeat(64)),
            format!("synv1.3.{}", "A".repeat(64)),
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn".into(),
        ] {
            assert!(R1NodePresentation::parse(&text, class).is_err());
        }
        assert!(crate::NodeAddress::parse("synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn").is_ok());
    }
}

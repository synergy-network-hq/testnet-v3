/// System messages use a separately authorized path; this marker prevents
/// callers from treating ingress configuration as system/validator authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemIngress;

impl SystemIngress {
    pub const fn may_determine_finality(self) -> bool {
        false
    }
}

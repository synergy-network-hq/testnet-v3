#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Error {
    BadLength {
        name: &'static str,
        actual: usize,
        expected: usize,
    },
    FfiFailure {
        operation: &'static str,
        code: i32,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::BadLength {
                name,
                actual,
                expected,
            } => write!(
                f,
                "error: {} expected {} bytes, got {}",
                name, expected, actual
            ),
            Error::FfiFailure { operation, code } => {
                write!(f, "error: {} failed with status {}", operation, code)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub mod kem;
pub mod sign;

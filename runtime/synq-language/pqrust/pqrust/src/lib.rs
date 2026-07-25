pub use pqrust_traits as traits;

pub mod prelude {
    pub use pqrust_traits::kem::{
        Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
    };
    pub use pqrust_traits::sign::{
        DetachedSignature as _, PublicKey as _, SecretKey as _, SignedMessage as _,
    };
}

pub mod kem {
    #[cfg(feature = "pqrust-cmce")]
    pub use pqrust_cmce::{
        cmce348864, cmce348864f, cmce460896, cmce460896f, cmce6688128,
        cmce6688128f, cmce6960119, cmce6960119f, cmce8192128, cmce8192128f,
    };
    #[cfg(feature = "pqrust-hqckem")]
    pub use pqrust_hqckem::{hqckem128, hqckem192, hqckem256};
    #[cfg(feature = "pqrust-mlkem")]
    pub use pqrust_mlkem::{mlkem1024, mlkem512, mlkem768};
}

pub mod sign {
    #[cfg(feature = "pqrust-fndsa")]
    pub use pqrust_fndsa::{fndsa1024, fndsa512, fndsapadded1024, fndsapadded512};
    #[cfg(feature = "pqrust-mldsa")]
    pub use pqrust_mldsa::{mldsa44, mldsa65, mldsa87};
    #[cfg(feature = "pqrust-slhdsa")]
    pub use pqrust_slhdsa::{
        slhdsasha2128fsimple, slhdsasha2128ssimple, slhdsasha2192fsimple, slhdsasha2192ssimple,
        slhdsasha2256fsimple, slhdsasha2256ssimple, slhdsashake128fsimple,
        slhdsashake128ssimple, slhdsashake192fsimple, slhdsashake192ssimple,
        slhdsashake256fsimple, slhdsashake256ssimple,
    };
}
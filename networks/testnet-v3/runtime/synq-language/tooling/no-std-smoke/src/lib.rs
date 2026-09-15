#![no_std]

#[cfg(feature = "pqc-aegis")]
use pqsynq::{Kem, Sign};

#[no_mangle]
pub extern "C" fn pqsynq_no_std_compile_probe() -> usize {
    #[cfg(not(feature = "pqc-aegis"))]
    {
        0
    }

    #[cfg(feature = "pqc-aegis")]
    {
        let _ = Kem::mlkem512();
        let _ = Kem::mlkem768();
        let _ = Kem::mlkem1024();
        let _ = Kem::hqckem128();
        let _ = Kem::hqckem192();
        let _ = Kem::hqckem256();
        let _ = Sign::mldsa44();
        let _ = Sign::mldsa65();
        let _ = Sign::mldsa87();
        let _ = Sign::fndsa512();
        let _ = Sign::fndsa1024();
        pqsynq::version().len()
    }
}

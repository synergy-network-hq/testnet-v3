#![no_std]

use core::slice;

#[no_mangle]
pub unsafe extern "C" fn pqrust_RUST_randombytes(buf: *mut u8, len: libc::size_t) -> libc::c_int {
    let buf = slice::from_raw_parts_mut(buf, len);
    getrandom::fill(buf).expect("RNG Failed");
    0
}

#[no_mangle]
pub unsafe extern "C" fn PQRUST_RUST_randombytes(buf: *mut u8, len: libc::size_t) -> libc::c_int {
    pqrust_RUST_randombytes(buf, len)
}

#[no_mangle]
pub unsafe extern "C" fn PQCLEAN_randombytes(buf: *mut u8, len: libc::size_t) -> libc::c_int {
    pqrust_RUST_randombytes(buf, len)
}

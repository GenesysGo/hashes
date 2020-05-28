//! Test messages from FIPS 180-1
#![no_std]
#[macro_use]
extern crate digest;

use digest::dev::{digest_test, one_million_a};

new_test!(
    ripemd160_main,
    "ripemd160",
    ripemd160::Ripemd160,
    digest_test
);

#[test]
fn ripemd160_1million_a() {
    let output = include_bytes!("data/one_million_a.bin");
    one_million_a::<ripemd160::Ripemd160>(output);
}

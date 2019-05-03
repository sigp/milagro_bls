#![cfg_attr(
    not(feature = "std"),
    no_std,
    feature(alloc),
    feature(alloc_prelude),
    feature(prelude_import)
)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
pub(crate) mod prelude {
    pub use alloc::prelude::v1::*;
    pub use core::prelude::v1::*;
}

#[cfg(not(feature = "std"))]
#[allow(unused)]
#[prelude_import]
use crate::prelude::*;

#[rustfmt::skip]
pub mod aes;
#[rustfmt::skip]
pub mod arch;
#[rustfmt::skip]
pub mod gcm;
#[rustfmt::skip]
pub mod hash256;
#[rustfmt::skip]
pub mod hash384;
#[rustfmt::skip]
pub mod hash512;
#[rustfmt::skip]
pub mod nhs;
#[rustfmt::skip]
pub mod rand;
#[rustfmt::skip]
pub mod sha3;

#[rustfmt::skip]
pub mod bls381;
#[rustfmt::skip]
pub mod bls383;
#[rustfmt::skip]
pub mod secp256k1;

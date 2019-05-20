#![cfg_attr(
    not(feature = "std"),
    no_std,
    feature(alloc),
    feature(alloc_prelude),
    feature(prelude_import)
)]

#[cfg(not(feature = "std"))]
#[macro_use]
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

extern crate amcl;
#[cfg(feature = "std")]
#[macro_use]
extern crate lazy_static;
extern crate rand;

mod aggregates;
mod amcl_utils;
mod errors;
mod g1;
mod g2;
mod keys;
mod rng;
mod signature;

use self::amcl::bls381 as BLSCurve;

pub use aggregates::{AggregatePublicKey, AggregateSignature};
pub use amcl_utils::hash_on_g2;
pub use errors::DecodeError;
pub use keys::{Keypair, PublicKey, SecretKey};
pub use signature::Signature;

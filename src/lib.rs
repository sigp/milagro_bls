#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

extern crate amcl;
#[cfg(feature = "std")]
#[macro_use]
extern crate lazy_static;
extern crate rand;

mod aggregates;
mod amcl_utils;
mod keys;
mod signature;

use self::amcl::bls381 as BLSCurve;

pub use aggregates::{AggregatePublicKey, AggregateSignature};
pub use amcl_utils::{AmclError, G1_BYTES, G2_BYTES, SECRET_KEY_BYTES};
pub use keys::{Keypair, PublicKey, SecretKey};
pub use signature::Signature;

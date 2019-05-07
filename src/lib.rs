extern crate amcl;
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
mod sqrt_division_chain;

use self::amcl::bls381 as BLSCurve;

pub use aggregates::{AggregatePublicKey, AggregateSignature};
pub use amcl_utils::{
    fouque_tibouchi_g1, fouque_tibouchi_g2, fouque_tibouchi_twice_g1, fouque_tibouchi_twice_g2,
    hash_and_test_g1, hash_and_test_g2, optimised_sw_g2, optimised_sw_g2_twice,
};
pub use errors::DecodeError;
pub use keys::{Keypair, PublicKey, SecretKey};
pub use signature::Signature;

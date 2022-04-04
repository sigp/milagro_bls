extern crate amcl;
#[cfg(feature = "std")]
extern crate hex;
extern crate rand;

use BLSCurve::bls381::proof_of_possession::DST_G2;
use BLSCurve::ecp::ECP;
use BLSCurve::ecp2::ECP2;
use BLSCurve::pair::{ate2, fexp};

pub use amcl::errors::AmclError;
pub use BLSCurve::big::{Big, MODBYTES};
pub use BLSCurve::bls381::proof_of_possession::{G1_BYTES, G2_BYTES, SECRET_KEY_BYTES};
pub use BLSCurve::bls381::utils::{
    self, deserialize_g1, deserialize_g2, serialize_g1, serialize_g2, subgroup_check_g1,
    subgroup_check_g2,
};
pub use BLSCurve::fp12::FP12;
pub use BLSCurve::fp2::FP2;
pub use BLSCurve::pair::{self, g1mul, g2mul};
pub use BLSCurve::rom::CURVE_ORDER;

pub type GroupG1 = ECP;
pub type GroupG2 = ECP2;

#[cfg(feature = "std")]
lazy_static! {
    pub static ref GENERATORG1: GroupG1 = GroupG1::generator();
    pub static ref GENERATORG2: GroupG2 = GroupG2::generator();
}

// Take given message convert it to GroupG2 point
pub fn hash_to_curve_g2(msg: &[u8]) -> GroupG2 {
    utils::hash_to_curve_g2(msg, DST_G2)
}

// Evaluation of e(A, B) * e(C, D) == 1
pub fn ate2_evaluation(a: &GroupG2, b: &GroupG1, c: &GroupG2, d: &GroupG1) -> bool {
    let mut pairing = ate2(a, b, c, d);
    pairing = fexp(&pairing);
    FP12::new_int(1).equals(&pairing)
}

// Take a GroupG1 point (x, y) and compress it to a 384 bit array.
// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn compress_g1(g1: &GroupG1) -> [u8; G1_BYTES] {
    serialize_g1(g1)
}

// Take a 384 bit array and convert to GroupG1 point (x, y)
// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn decompress_g1(g1_bytes: &[u8]) -> Result<GroupG1, AmclError> {
    // Ensure it is compressed
    if g1_bytes.len() != G1_BYTES {
        return Err(AmclError::InvalidG1Size);
    }
    deserialize_g1(g1_bytes)
}

// Take a GroupG2 point (x, y) and compress it to a 384*2 bit array.
// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn compress_g2(g2: &GroupG2) -> [u8; G2_BYTES] {
    serialize_g2(g2)
}

// Take a 384*2 bit array and convert to GroupG2 point (x, y)
// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn decompress_g2(g2_bytes: &[u8]) -> Result<GroupG2, AmclError> {
    // Ensure it is compressed
    if g2_bytes.len() != G2_BYTES {
        return Err(AmclError::InvalidG2Size);
    }
    deserialize_g2(g2_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_decompression_g1_round_trip() {
        // Input 1
        let compressed = hex::decode("b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f").unwrap();
        let mut decompressed = decompress_g1(&compressed).unwrap();
        let compressed_result = compress_g1(&mut decompressed).to_vec();
        assert_eq!(compressed, compressed_result);

        // Input 2
        let compressed = hex::decode("b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81").unwrap();
        let mut decompressed = decompress_g1(&compressed).unwrap();
        let compressed_result = compress_g1(&mut decompressed).to_vec();
        assert_eq!(compressed, compressed_result);

        // Input 3
        let compressed = hex::decode("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a").unwrap();
        let mut decompressed = decompress_g1(&compressed).unwrap();
        let compressed_result = compress_g1(&mut decompressed).to_vec();
        assert_eq!(compressed, compressed_result);
    }

    #[test]
    fn test_to_from_infinity_g1() {
        let mut point = GroupG1::new();
        let compressed = compress_g1(&mut point);
        let round_trip_point = decompress_g1(&compressed).unwrap();
        assert_eq!(point.to_string(), round_trip_point.to_string());
    }

    #[test]
    fn test_to_from_infinity_g2() {
        let mut point = GroupG2::new();
        let compressed = compress_g2(&mut point);
        let round_trip_point = decompress_g2(&compressed).unwrap();
        assert_eq!(point.to_string(), round_trip_point.to_string());
    }

    #[test]
    fn compression_decompression_g2_round_trip() {
        // Input 1
        let mut compressed_a = hex::decode("a666d31d7e6561371644eb9ca7dbcb87257d8fd84a09e38a7a491ce0bbac64a324aa26385aebc99f47432970399a2ecb").unwrap();
        let mut compressed_b = hex::decode("0def2d4be359640e6dae6438119cbdc4f18e5e4496c68a979473a72b72d3badf98464412e9d8f8d2ea9b31953bb24899").unwrap();
        compressed_a.append(&mut compressed_b);

        let mut decompressed = decompress_g2(&compressed_a).unwrap();
        let compressed_result = compress_g2(&mut decompressed).to_vec();
        assert_eq!(compressed_a, compressed_result);

        // Input 2
        let mut compressed_a = hex::decode("a63e88274adb7a98d112c16f7057f388786496c8f57e03ee9052b46b15eb0166645008f8cc929eb4475e386f3e6f1df8").unwrap();
        let mut compressed_b = hex::decode("1181e97fac61e371a22f34a4622f7e343ca0d99846b175a92ad1bf1df6fd4d0800e4edb7c2eb3d8437ed10cbc2d88823").unwrap();
        compressed_a.append(&mut compressed_b);

        let mut decompressed = decompress_g2(&compressed_a).unwrap();
        let compressed_result = compress_g2(&mut decompressed).to_vec();
        assert_eq!(compressed_a, compressed_result);

        // Input 3
        let mut compressed_a = hex::decode("b090fbc9d5c6c80fec73c567202a75664cd00c2592e472a4d81d2ed4b6a166311e809ca25eb88c5d0189cbf1baa8ea79").unwrap();
        let mut compressed_b = hex::decode("18ca20f0b66678c0230e65eb4ebb3d621940984f71eb5481453e4489dafcc7f6ee2c863b76671467002a8f2392063005").unwrap();
        compressed_a.append(&mut compressed_b);

        let mut decompressed = decompress_g2(&compressed_a).unwrap();
        let compressed_result = compress_g2(&mut decompressed).to_vec();
        assert_eq!(compressed_a, compressed_result);
    }
}

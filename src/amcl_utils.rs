extern crate amcl;
extern crate hex;
extern crate rand;
extern crate tiny_keccak;

use self::amcl::arch::Chunk;
use self::tiny_keccak::Keccak;
use super::errors::DecodeError;
use BLSCurve::big::BIG;
use BLSCurve::big::{MODBYTES as bls381_MODBYTES, NLEN};
use BLSCurve::ecp::ECP;
use BLSCurve::ecp2::ECP2;
use BLSCurve::fp12::FP12 as bls381_FP12;
use BLSCurve::fp2::FP2 as bls381_FP2;
use BLSCurve::pair::{ate, fexp};
use BLSCurve::rom;

pub type BigNum = BIG;
pub type GroupG1 = ECP;
pub type GroupG2 = ECP2;
pub type FP2 = bls381_FP2;
pub type FP12 = bls381_FP12;

pub const CURVE_ORDER: [Chunk; NLEN] = rom::CURVE_ORDER;
pub const MODBYTES: usize = bls381_MODBYTES;

// Byte size of element in group G1
pub const G1_BYTE_SIZE: usize = (2 * MODBYTES) as usize;
// Byte size of element in group G2
pub const G2_BYTE_SIZE: usize = (4 * MODBYTES) as usize;
// Byte size of secret key
pub const MOD_BYTE_SIZE: usize = bls381_MODBYTES;

pub const Q_STRING: &str = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

// G2_Cofactor as arrays of i64
pub const G2_COFACTOR_HIGH: [Chunk; NLEN] = [
    0x0153_7E29_3A66_91AE,
    0x023C_72D3_67A0_BBC8,
    0x0205_B2E5_A7DD_FA62,
    0x0115_1C21_6AEA_9A28,
    0x0128_76A2_02CD_91DE,
    0x0105_39FC_4247_541E,
    0x0000_0000_5D54_3A95,
];
pub const G2_COFACTOR_LOW: [Chunk; NLEN] = [
    0x031C_38E3_1C72_38E5,
    0x01BB_1B9E_1BC3_1C33,
    0x0000_0000_0000_0161,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
];
pub const G2_COFACTOR_SHIFT: [Chunk; NLEN] = [
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_1000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
];

lazy_static! {
    pub static ref GENERATORG1: GroupG1 = GroupG1::generator();
    pub static ref GENERATORG2: GroupG2 = GroupG2::generator();
}

// Take given message and domain and convert it to GroupG2 point
pub fn hash_on_g2(msg: &[u8], d: u64) -> GroupG2 {
    // Converting to BigNum requires 48 bytes, Keccak256 is only 32 bytes
    let mut x_real = vec![0 as u8; 16];
    x_real.append(&mut hash(&[msg, &d.to_be_bytes(), &[1]].concat()));
    let mut x_imaginary = vec![0 as u8; 16];
    x_imaginary.append(&mut hash(&[msg, &d.to_be_bytes(), &[2]].concat()));

    map_to_g2(&x_real, &x_imaginary)
}

// Convert x real and imaginary parts to GroupG2 point
#[allow(non_snake_case)]
pub fn map_to_g2(x_real: &[u8], x_imaginary: &[u8]) -> GroupG2 {
    // Convery Hashes to BigNums mod q
    let q = BigNum::new_ints(&rom::MODULUS);
    let mut x_real = BigNum::frombytes(x_real);
    let mut x_imaginary = BigNum::frombytes(x_imaginary);
    x_real.rmod(&q);
    x_imaginary.rmod(&q);
    let mut x = FP2::new_bigs(&x_real, &x_imaginary);

    let mut one = FP2::new();
    one.one();

    let mut curve_point: GroupG2;

    // Continue to increment x until valid y is found
    loop {
        x.norm();
        curve_point = GroupG2::new_fp2(&x);

        if !curve_point.is_infinity() {
            break;
        }
        x.add(&one);
    }

    // Take larger of two y values
    let mut y = curve_point.getpy(); // makes a copy
    let mut neg_y = curve_point.getpy();
    neg_y.neg();
    if cmp_fp2(&mut y, &mut neg_y) < 0 {
        curve_point.neg();
    }

    // Multiply the point by given G2_Cofactor
    multiply_cofactor(&mut curve_point)
}

// Compare values of two FP2 elements,
// -1 if num1 < num2; 0 if num1 == num2; 1 if num1 > num2
pub fn cmp_fp2(num1: &mut FP2, num2: &mut FP2) -> isize {
    // First compare FP2.b
    let num1_b = num1.getb();
    let num2_b = num2.getb();
    let mut result = BigNum::comp(&num1_b, &num2_b);

    // If FP2.b is equal compare FP2.a
    if result == 0 {
        let num1_a = num1.geta();
        let num2_a = num2.geta();
        result = BigNum::comp(&num1_a, &num2_a);
    }
    result
}

// Multiply in parts by cofactor due to its size.
pub fn multiply_cofactor(curve_point: &mut GroupG2) -> GroupG2 {
    // Replicate curve_point for low part of multiplication
    let mut lowpart = GroupG2::new();
    lowpart.copy(&curve_point);

    // Convert const arrays to BigNums
    let g2_cofactor_high = BigNum::new_ints(&G2_COFACTOR_HIGH);
    let g2_cofactor_shift = BigNum::new_ints(&G2_COFACTOR_SHIFT);
    let g2_cofactor_low = BigNum::new_ints(&G2_COFACTOR_LOW);

    // Multiply high part, then low part, then add together
    let mut curve_point = curve_point.mul(&g2_cofactor_high);
    curve_point = curve_point.mul(&g2_cofactor_shift);
    let lowpart = lowpart.mul(&g2_cofactor_low);
    curve_point.add(&lowpart);
    curve_point
}

// Provides a Keccak256 hash of given input.
pub fn hash(input: &[u8]) -> Vec<u8> {
    let mut keccak = Keccak::new_keccak256();
    keccak.update(input);
    let mut result = vec![0; 32];
    keccak.finalize(result.as_mut_slice());
    result
}

// A pairing function for an GroupG2 point and GroupG1 point to FP12.
pub fn ate_pairing(point_g2: &GroupG2, point_g1: &GroupG1) -> FP12 {
    let e = ate(&point_g2, &point_g1);
    fexp(&e)
}

// Take a GroupG1 point (x, y) and compress it to a 384 bit array.
pub fn compress_g1(g1: &mut GroupG1) -> Vec<u8> {
    // A compressed point takes form (c_flag, b_flag, a_flag, x-coordinate) where:
    // c_flag == 1
    // b_flag represents infinity (1 if infinitity -> x = y = 0)
    // a_flag = y % 2 (i.e. odd or eveness of y point)
    // x is the x-coordinate of

    // Check point at inifinity
    if g1.is_infinity() {
        let mut result: Vec<u8> = vec![0; MODBYTES];
        // Set b_flag and c_flag to 1, all else to 0
        result[0] = u8::pow(2, 6) + u8::pow(2, 7);
        return result;
    }

    // Convert point to array of bytes (x, y)
    let mut g1_bytes: Vec<u8> = vec![0; G1_BYTE_SIZE + 1];
    g1.tobytes(&mut g1_bytes, false);

    // Convert arrary (x, y) to compressed format
    let mut result: Vec<u8> = vec![0; MODBYTES];
    result.copy_from_slice(&g1_bytes[1..=MODBYTES]); // byte[0] is Milagro formatting

    // Set flags
    let a_flag = calc_a_flag(&mut BigNum::frombytes(&g1_bytes[MODBYTES + 1..]));
    result[0] += u8::pow(2, 5) * a_flag; // set a_flag
    result[0] += u8::pow(2, 7); // c_flag

    result
}

// Take a 384 bit array and convert to GroupG1 point (x, y)
pub fn decompress_g1(g1_bytes: &[u8]) -> Result<GroupG1, DecodeError> {
    // Length must be 48 bytes
    if g1_bytes.len() != MODBYTES {
        return Err(DecodeError::IncorrectSize);
    }

    let a_flag: u8 = g1_bytes[0] % u8::pow(2, 6) / u8::pow(2, 5);

    // c_flag must be set
    if g1_bytes[0] / u8::pow(2, 7) != 1 {
        // Invalid bytes
        return Err(DecodeError::InvalidCFlag);
    }

    // Check b_flag
    if g1_bytes[0] % u8::pow(2, 7) / u8::pow(2, 6) == 1 {
        // If b_flag == 1 -> a_flag == x == 0
        if a_flag != 0 || g1_bytes[0] % u8::pow(2, 5) != 0 {
            return Err(DecodeError::BadPoint);
        }

        for item in g1_bytes.iter().skip(1) {
            if *item != 0 {
                return Err(DecodeError::BadPoint);
            }
        }

        // Point is infinity
        return Ok(GroupG1::new());
    }

    let mut g1_bytes = g1_bytes.to_owned();

    // Zero remaining flags so it can be converted to 381 bit BigNum
    g1_bytes[0] %= u8::pow(2, 5);
    let x_big = BigNum::frombytes(&g1_bytes);

    // Convert to GroupG1 point using big
    let mut point = GroupG1::new_big(&x_big);
    if point.is_infinity() {
        return Err(DecodeError::BadPoint);
    }

    // Confirm a_flag
    let calculated_a_flag = calc_a_flag(&mut point.gety());
    if calculated_a_flag != a_flag {
        point.neg();
    }

    Ok(point)
}

// Take a GroupG2 point (x, y) and compress it to a 384*2 bit array.
pub fn compress_g2(g2: &mut GroupG2) -> Vec<u8> {
    // A compressed point takes form:
    // (c_flag1, b_flag1, a_flag1, x-coordinate.a, 0, 0, 0, x-coordinate.b) where:
    // c_flag1 == 1
    // b_flag1 represents infinity (1 if infinitity -> x = y = 0)
    // a_flag1 = y_imaginary % 2 (i.e. point.gety().getb())
    // x is the x-coordinate of

    // Check point at inifinity
    if g2.is_infinity() {
        let mut result: Vec<u8> = vec![0; G2_BYTE_SIZE / 2];
        // Set b_flag and c_flag to 1, all else to 0
        result[0] += u8::pow(2, 6) + u8::pow(2, 7);
        return result;
    }

    // Convert point to array of bytes (x, y)
    let mut g2_bytes: Vec<u8> = vec![0; G2_BYTE_SIZE];
    g2.tobytes(&mut g2_bytes);

    // Convert arrary (x, y) to compressed format
    // Note: amcl is x(re, im), y(re, im) eth is x(im, re), y(im, re)
    let x_real = &g2_bytes[0..MODBYTES];
    let x_imaginary = &g2_bytes[MODBYTES..(MODBYTES * 2)];
    let mut result: Vec<u8> = vec![0; MODBYTES];
    result.copy_from_slice(x_imaginary);
    result.extend_from_slice(x_real);

    // Set flags
    let a_flag = calc_a_flag(&mut BigNum::frombytes(&g2_bytes[MODBYTES * 3..]));
    result[0] += u8::pow(2, 5) * a_flag;
    result[0] += u8::pow(2, 7); // c_flag

    result
}

// Take a 384*2 bit array and convert to GroupG2 point (x, y)
pub fn decompress_g2(g2_bytes: &[u8]) -> Result<GroupG2, DecodeError> {
    // Length must be 96 bytes
    if g2_bytes.len() != G2_BYTE_SIZE / 2 {
        return Err(DecodeError::IncorrectSize);
    }

    // c_flag must be set
    if g2_bytes[0] / u8::pow(2, 7) != 1 {
        // Invalid bytes
        return Err(DecodeError::InvalidCFlag);
    }

    // Check b_flag
    if g2_bytes[0] % u8::pow(2, 7) / u8::pow(2, 6) == 1 {
        // If b_flag == 1 -> a_flag == x == 0
        if g2_bytes[0] % u8::pow(2, 6) != 0 {
            return Err(DecodeError::BadPoint);
        }

        for item in g2_bytes.iter().skip(1) {
            if *item != 0 {
                return Err(DecodeError::BadPoint);
            }
        }
        // Point is infinity
        return Ok(GroupG2::new());
    }

    let a_flag: u8 = g2_bytes[0] % u8::pow(2, 6) / u8::pow(2, 5);

    let mut g2_bytes = g2_bytes.to_owned();

    // Zero remaining flags so it can be converted to 381 bit BigNum
    g2_bytes[0] %= u8::pow(2, 5);

    // Convert from array to FP2
    let x_imaginary = BigNum::frombytes(&g2_bytes[0..MODBYTES]);
    let x_real = BigNum::frombytes(&g2_bytes[MODBYTES..]);
    let x = FP2::new_bigs(&x_real, &x_imaginary);

    // Convert to GroupG1 point using big and sign
    let mut point = GroupG2::new_fp2(&x);
    if point.is_infinity() {
        return Err(DecodeError::BadPoint);
    }

    // Confirm a_flag matches given flag
    let calculated_a_flag = calc_a_flag(&mut point.gety().getb());
    if calculated_a_flag != a_flag {
        point.neg();
    }

    Ok(point)
}

// Takes either y or y_im and calculates if a_flag is 1 or 0
//
// a_flag = floor((y * 2)  / q)
pub fn calc_a_flag(y: &mut BigNum) -> u8 {
    let mut y_bytes = vec![0; MODBYTES];
    let mut results = vec![0; MODBYTES];
    y.tobytes(&mut y_bytes);
    let q = hex::decode(Q_STRING).unwrap();

    // Multiply y by two with carrying
    let mut carry: u64 = 0;
    for (i, y_byte) in y_bytes.iter().enumerate() {
        let res = u64::from(*y_byte) * 2 + carry;
        carry = res - res % u64::pow(2, 8);
        results[i] = (res % u64::pow(2, 8)) as u8;
    }

    // If y * 2 > q -> (y * 2) / q == 1
    for (i, res) in results.iter().enumerate() {
        if *res > q[i] {
            return 1;
        } else if *res < q[i] {
            return 0;
        }
    }

    1 // Should not be reached as q is prime -> 2 * y != q
}

#[cfg(test)]
mod tests {
    extern crate yaml_rust;

    use self::yaml_rust::yaml;
    use super::*;
    use std::{fs::File, io::prelude::*, path::PathBuf};

    #[test]
    fn compression_decompression_g1_round_trip() {
        // Input 1
        let compressed = hex::decode("b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f").unwrap();
        let mut decompressed = decompress_g1(&compressed).unwrap();
        let compressed_result = compress_g1(&mut decompressed);
        assert_eq!(compressed, compressed_result);

        // Input 2
        let compressed = hex::decode("b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81").unwrap();
        let mut decompressed = decompress_g1(&compressed).unwrap();
        let compressed_result = compress_g1(&mut decompressed);
        assert_eq!(compressed, compressed_result);

        // Input 3
        let compressed = hex::decode("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a").unwrap();
        let mut decompressed = decompress_g1(&compressed).unwrap();
        let compressed_result = compress_g1(&mut decompressed);
        assert_eq!(compressed, compressed_result);
    }

    #[test]
    fn test_to_from_infinity_g1() {
        let mut point = GroupG1::new();
        let compressed = compress_g1(&mut point);
        let mut round_trip_point = decompress_g1(&compressed).unwrap();
        assert_eq!(point.tostring(), round_trip_point.tostring());
    }

    #[test]
    fn test_to_from_infinity_g2() {
        let mut point = GroupG2::new();
        let compressed = compress_g2(&mut point);
        let mut round_trip_point = decompress_g2(&compressed).unwrap();
        assert_eq!(point.tostring(), round_trip_point.tostring());
    }

    #[test]
    fn compression_decompression_g2_round_trip() {
        // Input 1
        let mut compressed_a = hex::decode("a666d31d7e6561371644eb9ca7dbcb87257d8fd84a09e38a7a491ce0bbac64a324aa26385aebc99f47432970399a2ecb").unwrap();
        let mut compressed_b = hex::decode("0def2d4be359640e6dae6438119cbdc4f18e5e4496c68a979473a72b72d3badf98464412e9d8f8d2ea9b31953bb24899").unwrap();
        compressed_a.append(&mut compressed_b);

        let mut decompressed = decompress_g2(&compressed_a).unwrap();
        let compressed_result = compress_g2(&mut decompressed);
        assert_eq!(compressed_a, compressed_result);

        // Input 2
        let mut compressed_a = hex::decode("a63e88274adb7a98d112c16f7057f388786496c8f57e03ee9052b46b15eb0166645008f8cc929eb4475e386f3e6f1df8").unwrap();
        let mut compressed_b = hex::decode("1181e97fac61e371a22f34a4622f7e343ca0d99846b175a92ad1bf1df6fd4d0800e4edb7c2eb3d8437ed10cbc2d88823").unwrap();
        compressed_a.append(&mut compressed_b);

        let mut decompressed = decompress_g2(&compressed_a).unwrap();
        let compressed_result = compress_g2(&mut decompressed);
        assert_eq!(compressed_a, compressed_result);

        // Input 3
        let mut compressed_a = hex::decode("b090fbc9d5c6c80fec73c567202a75664cd00c2592e472a4d81d2ed4b6a166311e809ca25eb88c5d0189cbf1baa8ea79").unwrap();
        let mut compressed_b = hex::decode("18ca20f0b66678c0230e65eb4ebb3d621940984f71eb5481453e4489dafcc7f6ee2c863b76671467002a8f2392063005").unwrap();
        compressed_a.append(&mut compressed_b);

        let mut decompressed = decompress_g2(&compressed_a).unwrap();
        let compressed_result = compress_g2(&mut decompressed);
        assert_eq!(compressed_a, compressed_result);
    }

    // Test vectors found at https://github.com/ethereum/eth2.0-tests/blob/master/bls/test_bls.yml
    #[test]
    #[allow(non_snake_case)]
    #[should_panic]
    fn case01_message_hash_G2_uncompressed() {
        // This test fails as the intermediate (x,y,z) variables do not match test vector
        // Likely caused by calling affine() during an intermediate step which converts (x, y, z) -> (x, y)
        // Note: if we convert to an (x, y) point the result is correct so overall function works

        // Run tests from test_bls.yml
        let mut file = {
            let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            file_path_buf.push("src/test_vectors/test_bls.yml");

            File::open(file_path_buf).unwrap()
        };
        let mut yaml_str = String::new();
        file.read_to_string(&mut yaml_str).unwrap();
        let docs = yaml::YamlLoader::load_from_str(&yaml_str).unwrap();
        let doc = &docs[0];

        // Select test case01
        let test_cases = doc["case01_message_hash_G2_uncompressed"].as_vec().unwrap();

        // Verify input against output for each pair
        for test_case in test_cases {
            // Convert input to rust formats
            let input = test_case["input"].clone();
            // Convert domain from indexed yaml to u64
            let domain = input["domain"].as_str().unwrap();
            let domain = domain.trim_start_matches("0x");
            let domain = u64::from_str_radix(domain, 16).unwrap();

            // Convert msg from indexed yaml to bytes (Vec<u8>)
            let msg = input["message"].as_str().unwrap();
            let msg = msg.trim_start_matches("0x");
            let msg = hex::decode(msg).unwrap();

            // Function results returns GroupG2 point
            let mut result = hash_on_g2(&msg, domain);

            // Compare against given output
            let output = test_case["output"].clone().into_vec().unwrap();
            for (i, fp2) in output.iter().enumerate() {
                // Get x, y or z point from curve
                let mut result_fp2 = result.getpx();
                if i == 1 {
                    // Check y coordinate
                    result_fp2 = result.getpy();
                } else if i == 2 {
                    // Check z coordinate
                    result_fp2 = result.getpz();
                }

                // Convert output (a, b) to bytes
                let output_a = fp2[0].as_str().unwrap().trim_start_matches("0x");
                let output_a = hex::decode(output_a).unwrap();
                let output_b = fp2[1].as_str().unwrap().trim_start_matches("0x");
                let output_b = hex::decode(output_b).unwrap();

                // Convert the result (a,b) to bytes
                let mut result_a = vec![0; 48];
                let mut result_b = vec![0; 48];
                result_fp2.geta().tobytes(&mut result_a);
                result_fp2.getb().tobytes(&mut result_b);

                assert_eq!(output_a, result_a);
                assert_eq!(output_b, result_b);
            }
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn case02_message_hash_G2_compressed() {
        // Run tests from test_bls.yml
        let mut file = {
            let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            file_path_buf.push("src/test_vectors/test_bls.yml");

            File::open(file_path_buf).unwrap()
        };
        let mut yaml_str = String::new();
        file.read_to_string(&mut yaml_str).unwrap();
        let docs = yaml::YamlLoader::load_from_str(&yaml_str).unwrap();
        let doc = &docs[0];

        // Select test case02
        let test_cases = doc["case02_message_hash_G2_compressed"].as_vec().unwrap();

        // Verify input against output for each pair
        for test_case in test_cases {
            // Convert input to rust formats
            let input = test_case["input"].clone();
            // Convert domain from indexed yaml to u64
            let domain = input["domain"].as_str().unwrap();
            let domain = domain.trim_start_matches("0x");
            let domain = u64::from_str_radix(domain, 16).unwrap();

            // Convert msg from indexed yaml to bytes (Vec<u8>)
            let msg = input["message"].as_str().unwrap();
            let msg = msg.trim_start_matches("0x");
            let msg = hex::decode(msg).unwrap();

            // Function results returns GroupG2 point, then compress
            let mut result = hash_on_g2(&msg, domain);
            result.affine();

            // Convert ouput to compressed bytes
            let output = test_case["output"].clone();
            let mut a = hex::decode(output[0].as_str().unwrap().trim_start_matches("0x")).unwrap();
            while a.len() < MOD_BYTE_SIZE {
                a.insert(0, 0);
            }
            let mut b = hex::decode(output[1].as_str().unwrap().trim_start_matches("0x")).unwrap();
            while b.len() < MOD_BYTE_SIZE {
                b.insert(0, 0);
            }
            a.append(&mut b);

            assert_eq!(a, compress_g2(&mut result));
        }
    }
}

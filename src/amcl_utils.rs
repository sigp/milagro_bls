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
use BLSCurve::fp::FP as bls381_FP;
use BLSCurve::pair::{ate, fexp};
use BLSCurve::rom;

pub type BigNum = BIG;
pub type GroupG1 = ECP;
pub type GroupG2 = ECP2;

pub type FP = bls381_FP;
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

    pub static ref ISO3_A2: FP2 = FP2::new_ints(0, 240);
    pub static ref ISO3_B2: FP2 = FP2::new_ints(1012, 1012);
    pub static ref ISO3_E2: FP2 = FP2::new_ints(1, 1);

    // Roots of unity and eta
    pub static ref SQRT_1: FP = FP::new_big(&BIG::frombytes(&hex::decode("6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09").unwrap()));
    pub static ref EV1: FP = FP::new_big(&BIG::frombytes(&hex::decode("02c4a7244a026bd3e305cc456ad9e235ed85f8b53954258ec8186bb3d4eccef7c4ee7b8d4b9e063a6c88d0aa3e03ba01").unwrap()));
    pub static ref EV2: FP = FP::new_big(&BIG::frombytes(&hex::decode("085fa8cd9105715e641892a0f9a4bb2912b58b8d32f26594c60679cc7973076dc6638358daf3514d6426a813ae01f51a").unwrap()));

    // ISO-3 Mapping values
    pub static ref XNUM: [FP2; 4] = [
        FP2::new_bigs(
            &BIG::frombytes(&hex::decode("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6").unwrap()),
            &BIG::frombytes(&hex::decode("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6").unwrap())
        ),
        FP2::new_bigs(
            &BIG::new(),
            &BIG::frombytes(&hex::decode("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a").unwrap())
        ),
        FP2::new_bigs(
            &BIG::frombytes(&hex::decode("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a").unwrap()),
            &BIG::frombytes(&hex::decode("8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d").unwrap())
        ),
        FP2::new_bigs(
            &BIG::frombytes(&hex::decode("171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1").unwrap()),
            &BIG::new()
        )
    ];
    pub static ref XDEN: [FP2; 3] = [
        FP2::new_bigs(
            &BIG::new(),
            &BIG::frombytes(&hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63").unwrap())
        ),
        FP2::new_bigs(
            &BIG::frombytes(&hex::decode("0c").unwrap()),
            &BIG::frombytes(&hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f").unwrap())
        ),
        FP2::new_int(1),
    ];
    pub static ref YNUM: [FP2; 4] = [
        FP2::new_bigs(
            &BIG::frombytes(&hex::decode("1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706").unwrap()),
            &BIG::frombytes(&hex::decode("1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706").unwrap())
        ),
        FP2::new_bigs(
            &BIG::new(),
            &BIG::frombytes(&hex::decode("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be").unwrap())
        ),
        FP2::new_bigs(
            &BIG::frombytes(&hex::decode("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c").unwrap()),
            &BIG::frombytes(&hex::decode("8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f").unwrap())
        ),
        FP2::new_bigs(
            &BIG::frombytes(&hex::decode("124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10").unwrap()),
            &BIG::new()
        )
    ];
    pub static ref YDEN: [FP2; 4] = [
        FP2::new_bigs(
            &BIG::frombytes(&hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb").unwrap()),
            &BIG::frombytes(&hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb").unwrap())
        ),
        FP2::new_bigs(
            &BIG::new(),
            &BIG::frombytes(&hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3").unwrap())
        ),
        FP2::new_bigs(
            &BIG::frombytes(&hex::decode("12").unwrap()),
            &BIG::frombytes(&hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99").unwrap())
        ),
        FP2::new_int(1)
    ];
}

// Take given message and domain and convert it to GroupG2 point
pub fn hash_on_g2(msg: &[u8], domain: u64) -> GroupG2 {
    // This is a wrapper to easily change implementation if we switch hashing methods
    hash_and_test_g2(msg, domain)
}

// Compare values of two FP2 elements,
// -1 if num1 < num2; 0 if num1 == num2; 1 if num1 > num2
pub fn cmp_fp2(num1: &mut FP2, num2: &mut FP2) -> isize {
    // First compare FP2.b
    let num1_b = num1.getb();
    let num2_b = num2.getb();
    let mut result = BigNum::comp(&num1_b, &num2_b);

    // If FP2.b is equal compare FP2.b
    if result == 0 {
        let num1_a = num1.geta();
        let num2_a = num2.geta();
        result = BigNum::comp(&num1_a, &num2_a);
    }
    result
}

// Multiply in parts by cofactor due to its size.
pub fn multiply_g2_cofactor(curve_point: &mut GroupG2) -> GroupG2 {
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

// Provides a Keccak512 hash of given input.
pub fn hash512(input: &[u8]) -> Vec<u8> {
    let mut keccak = Keccak::new_keccak512();
    keccak.update(input);
    let mut result = vec![0; 64];
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
    // TODO: We should not need to get Q from a string here it is in 'rom'
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

/**********************
* Hash to G1 Methods
**********************/

// Use hash-and-test method to convert a hash to a G1 point
pub fn hash_and_test_g1(msg: &[u8], domain: u64) -> GroupG1 {
    // Counter for incrementing the pre-hash messages
    let mut counter = 0 as u8;
    let mut curve_point: GroupG1;
    let q = BigNum::new_ints(&rom::MODULUS);

    // Continue to increment pre-hash message until valid x coordinate is found
    loop {
        // Hash (message, domain, counter) for x coordinate
        let mut x = vec![0 as u8; 16];
        x.append(&mut hash(&[msg, &domain.to_be_bytes(), &[counter]].concat()));

        // Convert Hashes to BigNums mod q
        let mut x = BigNum::frombytes(&x);
        x.rmod(&q);

        curve_point = GroupG1::new_big(&x);

        if !curve_point.is_infinity() {
            break;
        }

        counter += 1;
    }

    // Take larger of two y values
    let y = curve_point.gety();
    let mut neg_y = curve_point.gety();
    neg_y = BigNum::modneg(&mut neg_y, &q);
    if BigNum::comp(&y, &neg_y) < 0 {
        curve_point.neg();
    }

    // Multiply the point by given G1_Cofactor
    curve_point.cfp(); // TODO: ensure this is correct G1 cofactor
    curve_point
}

// Fouque Tibouchi G1
pub fn fouque_tibouchi_twice_g1(msg: &[u8], domain: u64) -> GroupG1 {
    // Hash (message, domain) for x coordinate
    let t0 = hash512(&[msg, &domain.to_be_bytes(), &[1]].concat());
    let t1 = hash512(&[msg, &domain.to_be_bytes(), &[2]].concat());

    // Convert hashes to Fp
    let t0 = BigNum::frombytes(&t0);
    let t1 = BigNum::frombytes(&t1);
    let mut t0 = FP::new_big(&t0);
    let mut t1 = FP::new_big(&t1);

    // Encode to G1
    let mut t0 = sw_encoding_g1(&mut t0);
    let t1 = sw_encoding_g1(&mut t1);

    // t0 = t0 + t1
    t0.add(&t1);
    t0.cfp(); // TODO ensure this multiplies by cofactor correctly
    t0
}

// Fouque Tibouchi twice and adds the result on G1
pub fn fouque_tibouchi_g1(msg: &[u8], domain: u64) -> GroupG1 {
    // Hash (message, domain) for x coordinate
    let t0 = hash512(&[msg, &domain.to_be_bytes(), &[1]].concat());

    // Convert hashes to Fp
    let t0 = BigNum::frombytes(&t0);
    let mut t0 = FP::new_big(&t0);

    // Encode to G1
    let mut t0 = sw_encoding_g1(&mut t0);

    // Multiplies by G1 cofactor
    t0.cfp();

    t0
}

// Shallue-van de Woestijne encoding
pub fn sw_encoding_g1(t: &mut FP) -> GroupG1 {
    // Map zero hash to point at infinity
    if t.iszilch() {
        return GroupG1::new();
    }

    // Parity to avoid negation collisions
    let mut neg_t = t.clone();
    neg_t.neg();
    let parity = BigNum::comp(&t.x, &neg_t.x);

    let fp_one = FP::new_int(1);

    // w = t
    let mut w = t.clone();
    // w = t^2
    w.sqr();
    // w = t^2 + b
    w.add(&FP::new_int(rom::CURVE_B_I));
    // w = t^2 + b + 1
    w.add(&fp_one);
    // w = 1 / (t^2 + b + 1)
    w.inverse();
    // w = t / (t^2 + b + 1)
    w.mul(&t);
    // sqrt(-3)
    // OPTIMIZE: This should probably be added as a global const
    let mut sqrt_n3 = FP::new_int(-3);
    sqrt_n3 = sqrt_n3.sqrt();

    // w = sqrt(-3) * t / (t^2 + b + 1)
    w.mul(&sqrt_n3);

    // x1 = (-1 + sqrt(-3)) / 2 - tw
    let mut x1 = sqrt_n3.clone();
    x1.sub(&fp_one);
    x1.norm();
    x1.div2();
    let mut tw = t.clone();
    tw.mul(&w);
    x1.sub(&tw);

    // OPTIMIZATION: Check if x1 is valid here and return.

    // x2 = -1 - x1
    let mut x2 = x1.clone();
    x2.neg();
    x2.sub(&fp_one);

    // OPTIMIZATION: Check if x2 is valid here and return.

    // x3 = 1 + 1 / w^2
    let mut x3 = w.clone();
    x3.sqr();
    x3.inverse();
    x3.add(&fp_one);

    // Take first valid point of x1, x2, x3
    let mut curve_point = GroupG1::new_big(&x1.redc());
    if curve_point.is_infinity() {
        curve_point = GroupG1::new_big(&x2.redc());
        if curve_point.is_infinity() {
            curve_point = GroupG1::new_big(&x3.redc());
        }
    }

    // Ensure if t > -t then y > -y && if t < -t then y < -y
    let y = curve_point.getpy();
    let mut neg_y = y.clone();
    neg_y.neg();
    let parity_2 = BigNum::comp(&y.x, &neg_y.x);
    if (parity < 0 && parity_2 > 0) || (parity > 0 && parity_2 < 0) {
        curve_point.neg();
    }

    curve_point
}

/**********************
* Hash to G2 Methods
**********************/

// Use hash-and-test method to convert a Hash to a G2 point
#[allow(non_snake_case)]
pub fn hash_and_test_g2(msg: &[u8], domain: u64) -> GroupG2 {
    // Counter for incrementing the pre-hash messages
    let mut real_counter = 1 as u8;
    let mut imaginary_counter = 2 as u8;
    let mut curve_point: GroupG2;

    // Continue to increment pre-hash message until valid x coordinate is found
    loop {
        // Hash (message, domain, counter) for x-real and x-imaginary
        let mut x_real = vec![0 as u8; 16];
        x_real.append(&mut hash(&[msg, &domain.to_be_bytes(), &[real_counter]].concat()));
        let mut x_imaginary = vec![0 as u8; 16];
        x_imaginary.append(&mut hash(&[msg, &domain.to_be_bytes(), &[imaginary_counter]].concat()));

        // Convert Hashes to Fp2
        let x_real = BigNum::frombytes(&x_real);
        let x_imaginary = BigNum::frombytes(&x_imaginary);
        let mut x = FP2::new_bigs(&x_real, &x_imaginary);

        x.norm();
        curve_point = GroupG2::new_fp2(&x);

        if !curve_point.is_infinity() {
            break;
        }

        real_counter += 1;
        imaginary_counter += 1;
    }

    // Take larger of two y values
    let mut y = curve_point.getpy();
    let mut neg_y = curve_point.getpy();
    neg_y.neg();
    if cmp_fp2(&mut y, &mut neg_y) < 0 {
        curve_point.neg();
    }

    // Multiply the point by given G2_Cofactor
    multiply_g2_cofactor(&mut curve_point)
}


// Fouque Tibouchi Twice and add results on G2
pub fn fouque_tibouchi_twice_g2(msg: &[u8], domain: u64) -> GroupG2 {
    // Hash (message, domain) for x coordinate
    let t00 = hash512(&[msg, &domain.to_be_bytes(), &[10]].concat());
    let t01 = hash512(&[msg, &domain.to_be_bytes(), &[11]].concat());
    let t10 = hash512(&[msg, &domain.to_be_bytes(), &[20]].concat());
    let t11 = hash512(&[msg, &domain.to_be_bytes(), &[21]].concat());

    // Convert hashes to Fp2
    let t00 = BigNum::frombytes(&t00);
    let t01 = BigNum::frombytes(&t01);
    let t10 = BigNum::frombytes(&t10);
    let t11 = BigNum::frombytes(&t11);
    let mut t0 = FP2::new_bigs(&t00, &t01);
    let mut t1 = FP2::new_bigs(&t10, &t11);

    // Encode to G1
    let mut t0 = sw_encoding_g2(&mut t0);
    let t1 = sw_encoding_g2(&mut t1);

    // t0 = t0 + t1
    t0.add(&t1);

    multiply_g2_cofactor(&mut t0)
}

// Fouque Tibouchi G2
pub fn fouque_tibouchi_g2(msg: &[u8], domain: u64) -> GroupG2 {
    // Hash (message, domain) for x coordinate
    let t00 = hash512(&[msg, &domain.to_be_bytes(), &[10]].concat());
    let t01 = hash512(&[msg, &domain.to_be_bytes(), &[11]].concat());

    // Convert hashes to Fp2
    let t00 = BigNum::frombytes(&t00);
    let t01 = BigNum::frombytes(&t01);
    let mut t0 = FP2::new_bigs(&t00, &t01);

    // Encode to G1
    let mut t0 = sw_encoding_g2(&mut t0);

    multiply_g2_cofactor(&mut t0)
}

// Shallue-van de Woestijne encoding
pub fn sw_encoding_g2(t: &mut FP2) -> GroupG2 {
    // Map zero hash to point at infinity
    if t.iszilch() {
        return GroupG2::new();
    }

    // OPTIMIZATIONS: Remove the clones()
    // Parity to avoid negation collisions
    let mut neg_t = t.clone();
    neg_t.neg();
    let parity = BigNum::comp(&t.getb(), &mut neg_t.getb());

    let fp2_one = FP2::new_int(1);

    // w = t
    let mut w = t.clone();
    // w = t^2
    w.sqr();
    // w = t^2 + b
    let fp_b = FP::new_int(rom::CURVE_B_I);
    w.add(&FP2::new_fps(&fp_b, &fp_b));
    // w = t^2 + b + 1
    w.add(&fp2_one);
    // w = 1 / (t^2 + b + 1)
    w.inverse();
    // w = t / (t^2 + b + 1)
    w.mul(&t);
    // sqrt(-3)

    // OPTIMIZE: This should probably be added as a global const
    let mut sqrt_n3 = FP::new_int(-3);
    sqrt_n3 = sqrt_n3.sqrt();

    // w = sqrt(-3) * t / (t^2 + b + 1)
    w.pmul(&sqrt_n3);

    // x1 = (-1 + sqrt(-3)) / 2 - tw
    let mut x1 = FP2::new_fp(&sqrt_n3);
    x1.sub(&fp2_one);
    x1.norm();
    x1.div2();
    let mut tw = t.clone();
    tw.mul(&w);
    x1.sub(&tw);

    // OPTIMIZATION: Check if x1 is valid here and return.

    // x2 = -1 - x1
    let mut x2 = x1.clone();
    x2.neg();
    x2.sub(&fp2_one);

    // OPTIMIZATION: Check if x2 is valid here and return.

    // x3 = 1 + 1 / w^2
    let mut x3 = w.clone();
    x3.sqr();
    x3.inverse();
    x3.add(&fp2_one);

    // Take first valid point of x1, x2, x3
    let mut curve_point = GroupG2::new_fp2(&x1);
    if curve_point.is_infinity() {
        curve_point = GroupG2::new_fp2(&x2);
        if curve_point.is_infinity() {
            curve_point = GroupG2::new_fp2(&x3);
        }
    }


    // Ensure if t > -t then y > -y && if t < -t then y < -y
    let mut y = curve_point.gety();
    let mut neg_y = y.clone();
    neg_y.neg();
    let parity_2 = BigNum::comp(&y.getb(), &neg_y.getb());
    if (parity < 0 && parity_2 > 0) || (parity > 0 && parity_2 < 0) {
        curve_point.neg();
    }

    curve_point
}


// A hash-to-curve method by Wahby and Boneh
pub fn optimised_swu_g2(msg: &[u8], domain: u64) -> GroupG2 {
    // Hash (message, domain) for x coordinate
    let t00 = hash512(&[msg, &domain.to_be_bytes(), &[10]].concat());
    let t01 = hash512(&[msg, &domain.to_be_bytes(), &[11]].concat());

    // Convert hashes to Fp2
    let t00 = BigNum::frombytes(&t00);
    let t01 = BigNum::frombytes(&t01);
    let t0 = FP2::new_bigs(&t00, &t01);

    // Convert to point on 3-Isogeny curve
    let (x, y, z) = unoptimized_iso3_hash_to_point(&t0);

    // Convert from 3-Isogeny curve to G2 point
    iso3_to_g2(x, y, z)
}
pub fn unoptimized_iso3_hash_to_point(t: &FP2) -> (FP2, FP2, FP2) {
    // Setup required variables
    let mut t2 = t.clone(); // t
    t2.sqr(); // t^2 (store for later)
    let mut et2 = t2.clone(); // et2 = t^2
    et2.mul(&ISO3_E2); // et2 = e * t^2
    let mut common = et2.clone(); // e * t^2
    common.sqr(); // e^2 + t^4
    common.add(&et2); // common = e^2 * t^4 + e * t^2

    // Deal with case where e^2 * t^4 + e * t^2 == 0
    let mut x0: FP2;
    let mut z: FP2;
    if common.iszilch() {
        x0 = ISO3_B2.clone(); // x0 = b
        let mut denominator = ISO3_E2.clone();
        denominator.mul(&ISO3_A2); // denominator = e * a

        z = denominator.clone();
        // OPTIMIZATION: Consider faster method of inverse here
        denominator.inverse(); // denominator = 1 / (e * a)

        x0.mul(&denominator);
    } else {
        // Numerator (x0)
        x0 = common.clone();
        x0.add(&FP2::new_ints(1, 0));
        x0.mul(&ISO3_B2); // b * (e^2 * t^4 + e * t^2 + 1)

        // Denominator
        let mut denominator = common.clone();
        denominator.mul(&ISO3_A2);

        z = denominator.clone();
        // OPTIMIZATION: Consider faster method of inverse here
        denominator.inverse();

        x0.mul(&denominator);
    }

    // Calculate g(x0) = x^3 + ax + b
    let mut gx0 = x0.clone();
    gx0.sqr();
    gx0.mul(&x0);
    let mut ax0 = x0.clone();
    ax0.mul(&ISO3_A2);
    gx0.add(&ax0);
    gx0.add(&ISO3_B2);

    let mut y0 = gx0.clone();
    if y0.sqrt() {
        // y0 is a valid square root
        return (x0, y0, z);
    }

    // y0 is not a valid square root attempt to calculate x1
    // x1 = e * t^2 * x0
    let mut x1 = x0;
    x1.mul(&ISO3_E2);
    let mut t2 = t.clone();
    t2.sqr(); // t^2
    x1.add(&t2);

    // y1^2 = e^3 * t^6
    let mut gx1 = gx0;
    let mut t6 = t2.clone(); // t^2
    t6.sqr(); // t^4
    t6.mul(&t2); // t^6
    gx1.mul(&t6); // t^6 * g(x0)
    let mut e3 = ISO3_E2.clone(); // e
    e3.sqr(); // e^2
    e3.mul(&ISO3_E2); // e^3
    gx1.mul(&e3); // e^3 * t^6 * g(x0)

    // OPTIMIZATION: sqrt should be done using sqrt candidates
    if !gx1.sqrt() {
        // Square root failed and we have an issue
        println!("Square root of x1 failed");
    }

    (x1, gx1, z)
}

pub fn iso3_to_g2(x: FP2, y: FP2, z: FP2) -> GroupG2 {
    // TODO: write iso3 function


    // TODO: remove when function is complete
    GroupG2::new_fp2s(&x, &y)
}

// Setup the 4 roots of unity
pub fn roots_of_unity() -> [FP2; 4] {
    let a = FP2::new_ints(1, 0);
    let b = FP2::new_ints(0, 1);
    let c = FP2::new_fps(&SQRT_1, &SQRT_1);
    let mut neg_sqrt_1 = SQRT_1.clone();
    neg_sqrt_1.neg();
    let d = FP2::new_fps(&SQRT_1, &neg_sqrt_1);

    [a, b, c, d]
}

// Setup the four different roots of eta = sqrt(e^3 * (-1)^(1/4))
pub fn etas() -> [FP2; 4] {
    let a = FP2::new_fps(&EV1, &FP::new());
    let b = FP2::new_fps(&FP::new(), &EV1);
    let c = FP2::new_fps(&EV2, &EV2);
    let mut negative_ev2 = EV2.clone();
    negative_ev2.neg();
    let d = FP2::new_fps(&EV2, &negative_ev2);

    [a, b, c, d]
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


    /*********************
    * Experimental Tests *
    **********************/
    #[test]
    fn test_hash_and_test_g1() {
        let msg = [1 as u8; 32];

        for i in 0..100 {
            assert!(!hash_and_test_g1(&msg, i).is_infinity());
        }
    }

    #[test]
    fn test_hash_and_test_g2() {
        let msg = [1 as u8; 32];

        for i in 0..100 {
            assert!(!hash_and_test_g2(&msg, i).is_infinity());
        }
    }

    #[test]
    fn test_fouque_tibouchi_g1() {
        let msg = [1 as u8; 32];

        for i in 0..100 {
            assert!(!fouque_tibouchi_g1(&msg, i).is_infinity());
        }
    }

    #[test]
    fn test_fouque_tibouchi_g2() {
        let msg = [1 as u8; 32];

        for i in 0..100 {
            let mut point = fouque_tibouchi_g2(&msg, i);
            assert!(!point.is_infinity());
        }
    }

    // TODO: Delete - Temp test to print certain values
    #[test]
    pub fn print_quatics() {
        /*
        let bytes = hex::decode("02c4a7244a026bd3e305cc456ad9e235ed85f8b53954258ec8186bb3d4eccef7c4ee7b8d4b9e063a6c88d0aa3e03ba01").unwrap();
        let big = BIG::frombytes(&bytes);
        let mut fp2 = FP2::new_big(&big);
        fp2.sqr();
        fp2.norm();
        println!("{:?}", fp2.tostring());
        fp2.sqr();
        fp2.norm();
        println!("{:?}", fp2.tostring());
        fp2.sqr();
        fp2.norm();
        println!("{:?}", fp2.tostring());
        */
        let mut e = ISO3_E2.clone();
        e.sqr();
        e.mul(&ISO3_E2);
        println!("{:?}", e.tostring());
        let mut neg_1 = FP2::new_ints(0, 1);
        neg_1.inverse();
        neg_1.sqrt();
        e.mul(&neg_1);
        e.sqrt();
        println!("{:?}", e.tostring());
    }
}

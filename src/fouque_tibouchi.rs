/* An implementation of the Fouque Tibouchi hash to curve.
*
*/

use super::amcl_utils::{BigNum, clear_g2_cofactor, FP, FP2, GroupG1, GroupG2, hash_to_field_g1, hash_to_field_g2};
use BLSCurve::rom;

// Fouque Tibouchi G1
pub fn fouque_tibouchi_twice_g1(msg: &[u8], domain: u64) -> GroupG1 {
    // Hash to Fp
    let mut t0 = hash_to_field_g1(&[msg, &domain.to_be_bytes()].concat(), 0);
    let mut t1 = hash_to_field_g1(&[msg, &domain.to_be_bytes()].concat(), 1);

    // Encode to G1
    let mut point0 = sw_encoding_g1(&mut t0);
    let point1 = sw_encoding_g1(&mut t1);

    // t0 = t0 + t1
    point0.add(&point1);
    // Multiplies by G1 cofactor to return a point in the correct subgroup
    point0.cfp(); // TODO: conform this to the specificed cofactor clearing
    point0
}

// Fouque Tibouchi twice and adds the result on G1
pub fn fouque_tibouchi_g1(msg: &[u8], domain: u64) -> GroupG1 {
    // Hash the message into a Fp value
    let mut t = hash_to_field_g1(&[msg, &domain.to_be_bytes()].concat(), 0);

    // Encode to G1
    let mut point = sw_encoding_g1(&mut t);

    // Multiplies by G1 cofactor to return a point in the correct subgroup
    point.cfp(); // TODO: conform this to the specificed cofactor clearing

    point
}

// Fouque Tibouchi Twice and add results on G2
pub fn fouque_tibouchi_twice_g2(msg: &[u8], domain: u64) -> GroupG2 {
    // Hash to Fp2
    let mut t0 = hash_to_field_g2(&[msg, &domain.to_be_bytes()].concat(), 0);
    let mut t1 = hash_to_field_g2(&[msg, &domain.to_be_bytes()].concat(), 1);

    // Encode to G2
    let mut point0 = sw_encoding_g2(&mut t0);
    let point1 = sw_encoding_g2(&mut t1);

    // t0 = t0 + t1
    point0.add(&point1);

    // Clears the cofactor and returns a point in the corect subgroup
    clear_g2_cofactor(&mut point0)
}

// Fouque Tibouchi G2
pub fn fouque_tibouchi_g2(msg: &[u8], domain: u64) -> GroupG2 {
    // Hash to Fp2
    let mut t = hash_to_field_g2(&[msg, &domain.to_be_bytes()].concat(), 0);

    // Encode to G1
    let mut point = sw_encoding_g2(&mut t);

    // Clears the cofactor and returns a point in the corect subgroup
    clear_g2_cofactor(&mut point)
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

    // x2 = -1 - x1
    let mut x2 = x1.clone();
    x2.neg();
    x2.sub(&fp_one);

    // x3 = 1 + 1 / w^2
    let mut x3 = w.clone();
    x3.sqr();
    x3.inverse();
    x3.add(&fp_one);

    // TODO: Make this constant time
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
        // TODO: Make this constant time?
        curve_point.neg();
    }

    curve_point
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


#[cfg(tests)]
mod tests {
    extern crate yaml_rust;

    use self::yaml_rust::yaml;
    use super::*;
    use std::{fs::File, io::prelude::*, path::PathBuf};

    #[test]
    fn test_fouque_tibouchi_g1() {
        let msg = [1 as u8; 48];

        for i in 0..100 {
            assert!(!fouque_tibouchi_g1(&msg, i).is_infinity());
        }
    }

    #[test]
    fn test_fouque_tibouchi_g2() {
        let msg = [1 as u8; 48];

        for i in 0..100 {
            let mut point = fouque_tibouchi_g2(&msg, i);
            assert!(!point.is_infinity());
        }
    }
}

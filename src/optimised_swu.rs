/* An implementation of the hash to curve method by Wahby and Boneh with some minor adjustments
* Implementation: https://github.com/kwantam/bls_sigs_ref
* Paper: https://eprint.iacr.org/2019/403.pdf
* Adjustments:
* - Final Output is Standard Projective form (X, Y, Z) -> (X / Z, Y / Z) as opposed to
*   Jacobian (X, Y, Z) -> (X / Z^2, Y / Z^3)
* - This is currently not a constant time implementation (To be Converted)
*/
use super::amcl_utils::{BigNum, clear_g2_cofactor, FP, FP2, GroupG2, hash_to_field_g2};
use sqrt_division_chain::sqrt_division_chain;


#[cfg(feature = "std")]
lazy_static! {
    // Curve parameters of ISO-3 y^2 = x^3 + ax + b
    pub static ref ISO3_A2: FP2 = FP2::new_ints(0, 240);
    pub static ref ISO3_B2: FP2 = FP2::new_ints(1012, 1012);
    pub static ref ISO3_E2: FP2 = FP2::new_ints(1, 1);

    // Roots of unity and eta
    pub static ref SQRT_1: FP = FP::new_big(&BigNum::frombytes(&hex::decode("06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09").unwrap()));
    pub static ref EV1: FP = FP::new_big(&BigNum::frombytes(&hex::decode("02c4a7244a026bd3e305cc456ad9e235ed85f8b53954258ec8186bb3d4eccef7c4ee7b8d4b9e063a6c88d0aa3e03ba01").unwrap()));
    pub static ref EV2: FP = FP::new_big(&BigNum::frombytes(&hex::decode("085fa8cd9105715e641892a0f9a4bb2912b58b8d32f26594c60679cc7973076dc6638358daf3514d6426a813ae01f51a").unwrap()));

    // ISO-3 Mapping values
    pub static ref XNUM: [FP2; 4] = [
        FP2::new_bigs(
            &BigNum::frombytes(&hex::decode("05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6").unwrap()),
            &BigNum::frombytes(&hex::decode("05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6").unwrap())
        ),
        FP2::new_bigs(
            &BigNum::new(),
            &BigNum::frombytes(&hex::decode("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a").unwrap())
        ),
        FP2::new_bigs(
            &BigNum::frombytes(&hex::decode("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e").unwrap()),
            &BigNum::frombytes(&hex::decode("08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d").unwrap())
        ),
        FP2::new_bigs(
            &BigNum::frombytes(&hex::decode("171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1").unwrap()),
            &BigNum::new()
        )
    ];
    pub static ref XDEN: [FP2; 4] = [
        FP2::new_bigs(
            &BigNum::new(),
            &BigNum::frombytes(&hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63").unwrap())
        ),
        FP2::new_bigs(
            &BigNum::new_int(12),
            &BigNum::frombytes(&hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f").unwrap())
        ),
        FP2::new_int(1),
        FP2::new(),
    ];
    pub static ref YNUM: [FP2; 4] = [
        FP2::new_bigs(
            &BigNum::frombytes(&hex::decode("1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706").unwrap()),
            &BigNum::frombytes(&hex::decode("1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706").unwrap())
        ),
        FP2::new_bigs(
            &BigNum::new(),
            &BigNum::frombytes(&hex::decode("05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be").unwrap())
        ),
        FP2::new_bigs(
            &BigNum::frombytes(&hex::decode("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c").unwrap()),
            &BigNum::frombytes(&hex::decode("08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f").unwrap())
        ),
        FP2::new_bigs(
            &BigNum::frombytes(&hex::decode("124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10").unwrap()),
            &BigNum::new()
        )
    ];
    pub static ref YDEN: [FP2; 4] = [
        FP2::new_bigs(
            &BigNum::frombytes(&hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb").unwrap()),
            &BigNum::frombytes(&hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb").unwrap())
        ),
        FP2::new_bigs(
            &BigNum::new(),
            &BigNum::frombytes(&hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3").unwrap())
        ),
        FP2::new_bigs(
            &BigNum::new_int(18),
            &BigNum::frombytes(&hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99").unwrap())
        ),
        FP2::new_ints(1, 0)
    ];
}

// A hash-to-curve method by Wahby and Boneh
pub fn optimised_swu_g2(msg: &[u8], domain: u64) -> GroupG2 {
    // Hash (message, domain) for x coordinate
    let t0 = hash_to_field_g2(&[msg, &domain.to_be_bytes()].concat(), 0);

    // Convert to point on 3-Isogeny curve
    let (x, y, z) = hash_to_iso3_point(&t0);

    // Convert from 3-Isogeny curve to G2 point
    let mut point = iso3_to_g2(&x, &y, &z);

    // Clear the cofactor
    clear_g2_cofactor(&mut point)
}

// A hash-to-curve method by Wahby and Boneh
pub fn optimised_swu_g2_twice(msg: &[u8], domain: u64) -> GroupG2 {
    // Hash to field to get two Fp2 values
    let t0 = hash_to_field_g2(&[msg, &domain.to_be_bytes()].concat(), 0);
    let t1 = hash_to_field_g2(&[msg, &domain.to_be_bytes()].concat(), 1);

    // Convert to Jacobian point on 3-Isogeny curve
    let (x0, y0, z0) = hash_to_iso3_point(&t0);
    let (x1, y1, z1) = hash_to_iso3_point(&t1);

    // Jacobian Ellitic Curve Addition
    let (x0, y0, z0) = jacobian_add_fp2(&x0, &y0, &z0, &x1, &y1, &z1);

    // Convert from 3-Isogeny curve to G2 point
    let mut point = iso3_to_g2(&x0, &y0, &z0);

    // Clear the cofactor
    clear_g2_cofactor(&mut point)
}

// Calculate sqrt(u/v) return value and and boolean if square root exists
pub fn sqrt_division_fp2(u: &FP2, v: &FP2) -> (bool, FP2) {
    // Calculate uv^15
    let mut tmp1 = v.clone(); // v
    let mut tmp2 = v.clone(); // v
    tmp1.sqr(); // v^2
    tmp2.mul(&tmp1); // v^3
    tmp1.sqr(); // v^4
    tmp2.mul(&tmp1); // v^7
    tmp1.sqr(); // v^8
    tmp1.mul(&tmp2); // v^15
    tmp1.mul(&u); // uv^15
    tmp2.mul(&u); // uv^7

    let mut sqrt_candidate = sqrt_division_chain(&tmp1); // (uv^15)^((p - 9) / 16)
    sqrt_candidate.mul(&tmp2); // uv^7 * (uv^15)^((p - 9) / 16)

    // Check against each of the roots of unity
    let mut roots = roots_of_unity();
    for root in roots.iter_mut() {
        root.mul(&sqrt_candidate);

        // Check (root * sqrt_candidate)^2 * v - u == 0
        tmp1 = root.clone();
        tmp1.sqr();
        tmp1.mul(&v);
        tmp1.sub(&u);
        if tmp1.iszilch() {
            return (true, *root);
        }
    }

    // No valid square roots found return: uv^7 * (uv^15)^((p - 9) / 16)
    (false, sqrt_candidate)
}

// Take a Jacobian set (x, y, z) on the ISO-3 curve and map it to a GroupG2 point
pub fn iso3_to_g2(x: &FP2, y: &FP2, z: &FP2) -> GroupG2 {
    let polynomials_coefficients: [&[FP2; 4]; 4] = [&*XNUM, &*XDEN, &*YNUM, &*YDEN];
    let z_vals = z_powers(&z);

    // x-num, x-den, y-num, y-den
    let mut mapped_vals: [FP2; 4] = [FP2::new(), FP2::new(), FP2::new(), FP2::new()];

    // Horner caculation for evaluating polynomials
    for (i, polynomial) in polynomials_coefficients[..].iter().enumerate() {
        mapped_vals[i] = polynomial[polynomial.len() - 1].clone();
        for (z_index, value) in polynomial.iter().rev().skip(1).enumerate() {
            // Each value is a specific k for a polynomial
            let mut zk = value.clone();
            zk.mul(&z_vals[z_index]); // k(z_index) * z^(2 * (3 - z_index))

            mapped_vals[i].mul(&x);
            mapped_vals[i].add(&zk);
        }
    }

    // y-num multiplied by y
    mapped_vals[2].mul(&y);
    // y-den multiplied by z^3
    mapped_vals[3].mul(&z_vals[0]);
    mapped_vals[3].mul(&z);

    let mut z_g2 = mapped_vals[1].clone(); // x-den
    z_g2.mul(&mapped_vals[3]); // x-den * y-den

    let mut x_g2 = mapped_vals[0].clone(); // x-num
    x_g2.mul(&mapped_vals[3]); // x-num * y-den

    let mut y_g2 = mapped_vals[2].clone(); // y-num
    y_g2.mul(&mapped_vals[1]); // y-num * x-den

    GroupG2::new_projective(x_g2, y_g2, z_g2)
}

// Returns z^2, z^4, z^6
pub fn z_powers(z: &FP2) -> [FP2; 3] {
    let mut two = z.clone();
    two.sqr();

    let mut four = two.clone();
    four.sqr();

    let mut six = four.clone();
    six.mul(&two);

    [two, four, six]
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

/*************************************
*  Jacobian Coordinate Operations
*************************************/
// Take a hashed Fp2 value t and map it to a point in the ISO-3 curve
// Outputs results in jacobian
pub fn hash_to_iso3_point(t: &FP2) -> (FP2, FP2, FP2) {
    let mut t2 = t.clone(); // t
    let neg_t = t2.is_neg(); // Store for later

    // Setup required variables
    t2.sqr(); // t^2 (store for later)
    let mut et2 = t2.clone(); // et2 = t^2
    et2.mul(&ISO3_E2); // et2 = e * t^2
    let mut common = et2.clone(); // e * t^2
    common.sqr(); // e^2 + t^4
    common.add(&et2); // common = e^2 * t^4 + e * t^2

    // Numerator (x0)
    let mut x_numerator = common.clone();
    x_numerator.add(&FP2::new_ints(1, 0));
    x_numerator.mul(&ISO3_B2); // b * (e^2 * t^4 + e * t^2 + 1)

    // Denominator (x0)
    let mut x_denominator: FP2;
    // Deal with case where e^2 * t^4 + e * t^2 == 0
    if common.iszilch() {
        x_denominator = ISO3_E2.clone();
        x_denominator.mul(&ISO3_A2); // denominator = e * a
    } else {
        x_denominator = common.clone();
        x_denominator.mul(&ISO3_A2);
        x_denominator.neg();
    }

    // u = num^3 + a * num * den^2 + b * den^3
    // v = den^3
    let mut u = x_numerator.clone();
    u.sqr(); // num^2
    u.mul(&x_numerator); // u = num^3

    let mut tmp1 = x_denominator.clone();
    tmp1.sqr(); // den^2
    let mut tmp2 = x_numerator.clone();
    tmp2.mul(&tmp1); // num * den^2
    tmp2.mul(&ISO3_A2); // a * num * den^2
    u.add(&tmp2); // u = num^3 + a * num * den^2

    tmp1.mul(&x_denominator); // den^3
    let v = tmp1.clone(); // den^3
    tmp1.mul(&ISO3_B2); // b * den^3
    u.add(&tmp1); // u = num^3 + a * num * den^2 + b * den^3

    // sqrt_candidate(x0) = uv^7 * (uv^15)^((p-9)/16) *? root of unity
    let (success, mut sqrt_candidate) = sqrt_division_fp2(&u, &v);

    // TODO: Convert this section to constant time implementation
    if !success {
        // x1 = e * t^2 * x0
        x_numerator.mul(&et2);

        // g(x0) is not square -> try x1
        // u(x1) = e^3 * t^6 * u(x0)
        u.mul(&et2); // u(x1) = e * t^2 * u(x0)
        et2.sqr(); // e^2 * t^4
        u.mul(&et2); // u(x0) = e^3 * t^6 * u(x1)

        // sqrt_candidate(x1) = sqrt_candidate(x0) * t^3
        sqrt_candidate.mul(&t2); // sqrt_candidate(x0) * t^2
        sqrt_candidate.mul(&t); // sqrt_candidate(x0) * t^3

        let mut etas = etas();
        for (i, eta) in etas.iter_mut().enumerate() {
            tmp1 = sqrt_candidate.clone();
            tmp1.mul(&eta); // eta * sqrt_candidate(x1)

            tmp1.sqr(); // (eta * sqrat_candidate(x1)) ^ 2
            tmp1.mul(&v); // v * (eta * sqrat_candidate(x1)) ^ 2
            tmp1.sub(&u); // v * (eta * sqrat_candidate(x1)) ^ 2 - u`

            if tmp1.iszilch() {
                // Valid solution found
                sqrt_candidate.mul(eta);
                break;
            } else if i == 3 {
                // No valid square root found
                panic!("Hash to curve optimised swu error");
            }
        }
    }

    // negate y if y and t oppose in signs
    if neg_t != sqrt_candidate.is_neg() {
        sqrt_candidate.neg();
    }

    // Output as Jacobian (Convert to projective?)
    // X = x-num * x-den
    tmp1 = x_numerator.clone();
    tmp1.mul(&x_denominator);
    // Y = y * x-den^3 = y * v
    sqrt_candidate.mul(&v);
    // Z = x-den
    (tmp1, sqrt_candidate, x_denominator)
}

// Take a Jacobian set (x, y, z) on the ISO-3 curve and map it to a Jacobian point on G2 Curve
pub fn iso3_to_g2_jacobian(x: &FP2, y: &FP2, z: &FP2) -> (FP2, FP2, FP2) {
    let polynomials_coefficients: [&[FP2; 4]; 4] = [&*XNUM, &*XDEN, &*YNUM, &*YDEN];
    let z_vals = z_powers(&z);

    // x-num, x-den, y-num, y-dom
    let mut mapped_vals: [FP2; 4] = [FP2::new(), FP2::new(), FP2::new(), FP2::new()];

    // Horner caculation for evaluating polynomials
    for (i, polynomial) in polynomials_coefficients[..].iter().enumerate() {
        mapped_vals[i] = polynomial[polynomial.len() - 1].clone();
        for (z_index, value) in polynomial.iter().rev().skip(1).enumerate() {
            // Each value is a specific k for a polynomial
            let mut zk = value.clone();
            zk.mul(&z_vals[z_index]); // k(z_index) * z^(2 * (3 - z_index))

            mapped_vals[i].mul(&x);
            mapped_vals[i].add(&zk);
        }
    }

    // y-num multiplied by y
    mapped_vals[2].mul(&y);
    // y-den multiplied by z^3
    mapped_vals[3].mul(&z_vals[0]);
    mapped_vals[3].mul(&z);

    let mut z_g2 = mapped_vals[1].clone(); // x-den
    z_g2.mul(&mapped_vals[3]); // x-den * y-den

    let mut x_g2 = mapped_vals[0].clone(); // x-num
    x_g2.mul(&z_g2); // x-num * x-den * y-den
    x_g2.mul(&mapped_vals[3]); // x-num * x-den * y-den^2

    let mut y_g2 = z_g2.clone(); // x-den * y-den
    y_g2.sqr(); // x-den^2 * y-den^2
    y_g2.mul(&mapped_vals[2]); // y-num * x-den^2 * y-den^2
    y_g2.mul(&mapped_vals[1]); // y-num * x-den^3 * y-den^2

    (x_g2, y_g2, z_g2) // Jacobian not standard projective
}

// Elliptic Curve Addition for Jacobian Coordinates
//
// from EFD: https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
pub fn jacobian_add_fp2(x1: &FP2, y1: &FP2, z1: &FP2, x2: &FP2 , y2: &FP2, z2: &FP2) -> (FP2, FP2, FP2) {
    let mut z1_sqr = z1.clone();
    z1_sqr.sqr();                   // Z1^2
    let mut z2_sqr = z2.clone();
    z2_sqr.sqr();                   // Z2^2

    let mut u1 = z2_sqr.clone();
    u1.mul(&x1);                    // U1 = X1 * Z2^2
    let mut u2 = z1_sqr.clone();
    u2.mul(&x2);                    // U2 = X2 * Z1^2

    let mut s1 = y1.clone();
    s1.mul(&z2);
    s1.mul(&z2_sqr);                // S1 = Y1 * Z2^3
    let mut s2 = y2.clone();
    s2.mul(&z1);
    s2.mul(&z1_sqr);                // S2 = Y2 * Z1^3

    let mut h = u2.clone();
    h.sub(&u1);                     // H = U2 - U1

    let mut i = h.clone();
    i.imul(2);
    i.reduce();
    i.sqr();                        // I = (2H)^2

    let mut j = h.clone();
    j.mul(&i);                      // J = H * I

    let mut r = s2.clone();
    r.sub(&s1);
    r.imul(2);
    r.reduce();                     // r = 2(S2 - S1)

    let mut v = u1.clone();
    v.mul(&i);                      // V = U1 - I

    let mut temp = v.clone();
    temp.imul(2);
    temp.add(&j);                   // J + 2V
    let mut x = r.clone();
    x.sqr();
    x.sub(&temp);                   // X = r^2 - J - 2V

    temp = s1.clone();
    temp.imul(2);
    temp.mul(&j);                   // 2 * S1 * J
    let mut y = v.clone();
    y.sub(&x);
    y.mul(&r);
    y.sub(&temp);                   // Y = r (V - X1) - 2 * S1 * J

    let mut z = z1.clone();
    z.add(&z2);
    z.sqr();
    z.sub(&z1_sqr);
    z.sub(&z2_sqr);
    z.mul(&h);                      // Z = 2 * Z1 * Z2 * H

    (x, y, z)
}



#[cfg(test)]
mod tests {
    extern crate yaml_rust;

    use self::yaml_rust::yaml;
    use super::*;
    use super::super::amcl_utils::*;
    use super::super::psi_cofactor::*;
    use std::{fs::File, io::prelude::*, path::PathBuf};

    #[test]
    fn optimised_swu_twice_1() {
        // Input hash from C impl input "1" + enter + ctrlD
        let msg = hex::decode("821d8c1c38ad2f46081460330d07ddfd45b5d7cd6b324efb07b9365e4336427a").unwrap();
        let mut t0 = hash_to_field_g2(&msg, 0);
        let mut t1 = hash_to_field_g2(&msg, 1);

        // Check hash to field value
        let a = BigNum::frombytes(&hex::decode("13ebfd9a2321c55f89c3f33517bb1dc0840fff8b2a7e8a838de75c2d54494bde9be9c96f994a70bf87b24f6d1ee01298").unwrap());
        let b = BigNum::frombytes(&hex::decode("17ef2367c8bc23b31cae4a04693f02e7b31080bdec0e31983d96ef3546ac43040607f89e28e73bae6427c2dfd76ffa8c").unwrap());
        let mut check_t0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("0645cf9379b1174f53ae8becc83a8a3dee00512068027769cae2462dc8c2a86ec5cdbfb82e143d87f95645090f574487").unwrap());
        let b = BigNum::frombytes(&hex::decode("18b6775520c61e688a6afe6566a3bd2279e724d3a216ccdb74ea66feac03d4460315a6d65ff5343c4a52d77f2376c74e").unwrap());
        let mut check_t1 = FP2::new_bigs(&a, &b);
        assert!(t0.equals(&mut check_t0));
        assert!(t1.equals(&mut check_t1));

        // Convert hashed value to Point on the 3-Isogeny Curve
        let (mut x0, mut y0, mut z0) = hash_to_iso3_point(&t0);
        let (mut x1, mut y1, mut z1) = hash_to_iso3_point(&t1);

        // Check ISO3 Points (Jacobian)
        let a = BigNum::frombytes(&hex::decode("0fb9833ec127105533f7c2309d0136dd70aa68e0c7aca20d312efd200f76b99c0e8a5764ac72f7fb6a5476cca0fca38a").unwrap());
        let b = BigNum::frombytes(&hex::decode("00c480ec5f8b5bc7ba534eb4c3342509efa68f3b47af97bb4212815e969fea50b3c24cd2d0ed3d22c9861bc1ddc0ab73").unwrap());
        let mut check_x0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("106c1a00a2e533faaea6c307ecfd65eaada440572af53515c849c6e8dc2a4906c72e8c2cd650d62871ddb68fda492ae8").unwrap());
        let b = BigNum::frombytes(&hex::decode("0747acddb50f752b48fb4c9d3914e9060d96f4ae5a9b8a8f1ec2b7fd3a0fac52e08200c3bfd10fe3d1664aff119880e5").unwrap());
        let mut check_y0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("062781a21914767d68f7fa61c54ae664793c1940242896e960d2c97083eb7eb966cdaf265563f3620faf5475bde93ad9").unwrap());
        let b = BigNum::frombytes(&hex::decode("0a9ebbe9bdccd08961cc25876b217cfac92129b7a1aa438eb287d6ab4258726a07f6a9360045715afbe05bc1b2d7b896").unwrap());
        let mut check_z0 = FP2::new_bigs(&a, &b);

        let a = BigNum::frombytes(&hex::decode("1566af5cfdd87e9239ad9a7d51c699781c31c4f835f1a7627edb8ee7cc8ae65a55516e273a67ceb6086c74c3f40a0843").unwrap());
        let b = BigNum::frombytes(&hex::decode("01a70d7fdd6c71af65e0de17521ae68bec90838a883ea70472eaa0b4ff3d03e5641a2fc7f018673f16db07feacc208f9").unwrap());
        let mut check_x1 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("0344a9313e4954e1b2062598fe2e2734586c98b5270c5104b1707582850c40d05883b18ddda73bbfdf8662e80fac0051").unwrap());
        let b = BigNum::frombytes(&hex::decode("0de11409af99b35a8c31d05f353e951e7365687d0ef6466470f10ac144d29fd13c844c3fdc18225bd90ac318d76469da").unwrap());
        let mut check_y1 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("090b4cf0c6e878118cf1c22b09295f6042b8bdad5cc2edcdaaaf511a75cfce38ba911c56d6462d280d1ccad3afd16ba7").unwrap());
        let b = BigNum::frombytes(&hex::decode("0f87cbef52a6270c5406beef865d2036b2db48f5efe1bebce4bffb5336467e6050725c1973df9136074b9a3b1fed2adf").unwrap());
        let mut check_z1 = FP2::new_bigs(&a, &b);

        assert!(x0.equals(&mut check_x0));
        assert!(y0.equals(&mut check_y0));
        assert!(z0.equals(&mut check_z0));
        assert!(x1.equals(&mut check_x1));
        assert!(y1.equals(&mut check_y1));
        assert!(z1.equals(&mut check_z1));

        // Jacobian addition
        let (jac_x, jac_y, jac_z) = jacobian_add_fp2(&x0, &y0, &z0, &x1, &y1, &z1);

        // 3-Isogeny Map to Point on G2 (Input: Jacobian, Output: Standard Projective)
        let mut res0 = iso3_to_g2(&jac_x, &jac_y, &jac_z);

        // Check after eval_iso3()
        let a = BigNum::frombytes(&hex::decode("07ea1e10b6956041d066bd36bcfe2431e56fab08ad145a48408550709e798c389fb8c244cc823bcb7c0023cbeecc9866").unwrap());
        let b = BigNum::frombytes(&hex::decode("0babcec1aa6d1328b2f9c2d2b2c2ea4b194ecbb17b92c081bb2f9a47f0dd7c5c59d30c6f237036c3f508d57acf4e3c99").unwrap());
        let mut check_x = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("16a3aff86fe15145def8915992824cf2c1831e237223a8bfda787c1848bf78be85a3ab0efc36fb10228fbd299e96327c").unwrap());
        let b = BigNum::frombytes(&hex::decode("073bc0e2808fadd6ae3d6690b3491b76c92f75fe4b36119d25fbe721c46a3a6bb241f2fd1be009ad073205c62b73f2e0").unwrap());
        let mut check_y = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("18ff97c4ccdbff04b899e9c17f9050ab57c9878ccd9fc310156d0ef195fb41436c07b70e1b9e5b0120691c23bbe37814").unwrap());
        let b = BigNum::frombytes(&hex::decode("007ec14b229394bfbe0248bbaa3cca2f8f2bb4ba8dafdca28cd8e3a6c16a2595c910ac69ac49174e9c34f039686516e9").unwrap());
        let mut check_z = FP2::new_bigs(&a, &b);
        check_z.inverse();
        check_x.mul(&check_z);
        check_x.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        let mut check_y2 = check_y.clone();
        check_y2.sqr();
        let mut rhs = GroupG2::rhs(&mut check_x);
        assert!(check_y2.equals(&mut rhs));
        let mut check = GroupG2::new_fp2s(&check_x, &check_y);

        assert!(res0.equals(&mut check));

        // Clear the G2 cofactor
        let mut final_res = clear_g2_psi(&mut res0);

        // Final check after clearing the cofactor
        let a = BigNum::frombytes(&hex::decode("10636b9726daa3514380e10f037650c6cfeeda42c472cc21ef429ead15c141320e0a785bddce615fb0d855b2e2c2540a").unwrap());
        let b = BigNum::frombytes(&hex::decode("19e471ef5cc852e099ca48419ed4db836c58f53a802ac8240cee18b5ec542315a2ff1259c2090f1058c41a4bcf440d55").unwrap());
        let mut check_x = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("0ba7cfb5325b88c69fbb42ffcef0bf10439d841c18e164fd1a0bdb206c7348cb54d3987fe0167c8eb847dc7675734cb6").unwrap());
        let b = BigNum::frombytes(&hex::decode("09ad7c9708e63a2eff26c578d4ec1c00993c847e14e497fdee9fbc839db44a151d9c63519f695e2f4058db3ba809429d").unwrap());
        let mut check_y = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("08483312653f15ee0a947be794c24dbc01916cef060ba0afc1ba5685610a9925d777aad05cb875dd34f4ba43a2ec7db8").unwrap());
        let b = BigNum::frombytes(&hex::decode("176864483617a9ff6fbf0d130a4c71be0ec8b2fe0169822c5a51beca219d521959b1a4b2d667443a57e5fc631fc67307").unwrap());
        let mut check_z = FP2::new_bigs(&a, &b);

        check_z.inverse();
        check_x.mul(&check_z);
        check_x.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        let mut check_y2 = check_y.clone();
        check_y2.sqr();
        let mut rhs = GroupG2::rhs(&mut check_x);
        assert!(check_y2.equals(&mut rhs));

        let mut check = GroupG2::new_fp2s(&check_x, &check_y);
        assert!(final_res.equals(&mut check));

        println!("Final 1: {}", final_res.tostring());
    }

    #[test]
    fn optimised_swu_twice_2() {
        // Input hash from C impl input "2" + enter + ctrlD
        let msg = hex::decode("b79e446e64ebdb55b2a4cd38075cae41a90b6c97016549d6fe0c12f11ee90573").unwrap();
        let mut t0 = hash_to_field_g2(&msg, 0);
        let mut t1 = hash_to_field_g2(&msg, 1);

        // Check hash to field values
        let a = BigNum::frombytes(&hex::decode("19c9676198a6342c23560d2a82986ab9c06dab9c36ba3d02951dbfb23544f530aefc5fb8987acc8a716abd886185e14a").unwrap());
        let b = BigNum::frombytes(&hex::decode("17c87d0164b140460626d2f6ca0bcd2dc7da16dd962975c61c4ff24731f39598d141fa3e301649681dbe82e1a1e0750d").unwrap());
        let mut check_t0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("097e395a6aeca943fcc697d8cc801729905f7b345cef66ddf05d5c8eca6c9f1b7c826bbcc964801cebf85298ce8af573").unwrap());
        let b = BigNum::frombytes(&hex::decode("0c4f94da83e985f32e3648de00e517663e83d90b81002c475655197da52af95e67d583e8921df22bdf23497cfc1cc19c").unwrap());
        let mut check_t1 = FP2::new_bigs(&a, &b);
        assert!(t0.equals(&mut check_t0));
        assert!(t1.equals(&mut check_t1));

        // Convert hashed value to Point on the 3-Isogeny Curve
        let (mut x0, mut y0, mut z0) = hash_to_iso3_point(&t0);
        let (mut x1, mut y1, mut z1) = hash_to_iso3_point(&t1);

        // Check ISO3 Points (Jacobian)
        let a = BigNum::frombytes(&hex::decode("10b633b9b0440157d98b7f2b26de97a1aaa71e97b97b286dbcd33ec3ecfe092a341e44d41c37562312b83604e402f90a").unwrap());
        let b = BigNum::frombytes(&hex::decode("18ddcc482b7346cb5a22f3c4f64d8e7c3286c93890153cb110345a53e891bceab27f25a8d83d2701180cbbf8aeebc6a4").unwrap());
        let mut check_x0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("131a2ea8917ceb86ca5a022f14558ab72ce51bc3cb354a5b799b5da621b2f155e89b8d27d0065b90b1210cee7aa66c61").unwrap());
        let b = BigNum::frombytes(&hex::decode("160d801e3829b6a48789693fa82679d4093328135dd5c9f09c21101286350257e54343729cb95c2d51255c24e659a4f3").unwrap());
        let mut check_y0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("09ca185d8400907cb37ba340ff84e8e2e9e2b55b72f2d4779f7543359fe2f37bd6e397413f4dcc3b63cbb40f9bad4caa").unwrap());
        let b = BigNum::frombytes(&hex::decode("12d7ebc4e5874c96c8ad3c9a655e9e5184bd48670ab1b9ebf338f3dfa4ed0a29a0b1c94f7b2adc566feb4e6b6272ccfa").unwrap());
        let mut check_z0 = FP2::new_bigs(&a, &b);

        let a = BigNum::frombytes(&hex::decode("10d0689251c8ad935484782fedab60aad3b238b8668fb8fbff27283d6775238f98dd4304b1b783e0533fcb0fdec56545").unwrap());
        let b = BigNum::frombytes(&hex::decode("12678ccbfa78e91991d0ac8f13aff23b0688ed30b1175f5baa40e6f664c875829c3fc68c5b58ac33116eff2b8d4bf57f").unwrap());
        let mut check_x1 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("156cb8cd41144944d4974aa29ebccc566383cb9a2d130a15a74da7e15f297e2e3da94babfaed4168784f1af713e8f2c8").unwrap());
        let b = BigNum::frombytes(&hex::decode("1493e12a866ac45e042ddba1ae178a5b2e698c63de6789ac7e65cf9c64cea8d084de5f5a97748a139a13a96f4a8a2c14").unwrap());
        let mut check_y1 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("058791b5fa9d54d8a94a46ebd988b36868f39a8de18e3753decd39c6b11e3c966699ca5a11e43cf65841767404c08de7").unwrap());
        let b = BigNum::frombytes(&hex::decode("16081964ec99bafb7a118899f9521e2a5fc20d20106d7404fba7f3e3a83127b17ae113ff683441b6e22bf10d323d8b72").unwrap());
        let mut check_z1 = FP2::new_bigs(&a, &b);

        assert!(x0.equals(&mut check_x0));
        assert!(y0.equals(&mut check_y0));
        assert!(z0.equals(&mut check_z0));
        assert!(x1.equals(&mut check_x1));
        assert!(y1.equals(&mut check_y1));
        assert!(z1.equals(&mut check_z1));

        // Jacobian addition
        let (jac_x, jac_y, jac_z) = jacobian_add_fp2(&x0, &y0, &z0, &x1, &y1, &z1);

        // 3-Isogeny Map to Point on G2 (Input: Jacobian, Output: Standard Projective)
        let mut res0 = iso3_to_g2(&jac_x, &jac_y, &jac_z);

        // Check after eval_iso3()
        let a = BigNum::frombytes(&hex::decode("12dd3de8b69c8c1b8f4f146bebc268b99dd5a1d99504ea17c452e757050d62ef6f5648797b125c223aac5d93424b70ff").unwrap());
        let b = BigNum::frombytes(&hex::decode("004c157bf710f88fb6e737e61a0a11974b713004ba4573da6033ec36be0bf5ed9356f1ddce2261bdd536263f3eb37a28").unwrap());
        let mut check_x = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("070f9a77f795c167c1b78a0a4f598040a363d7c6ae739b4efd993997e2cafd212d3f2d89bc0243b5e9f47bc47079ce20").unwrap());
        let b = BigNum::frombytes(&hex::decode("18f898f18aced151589832bc9df732aa53aa01beb2d840bd18e6bf0cc29150d0b4cd40864e250161d9fdc91ad252a8ea").unwrap());
        let mut check_y = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("196d7efb8e2e73be2513ac5e88579c730d8ab539561f250ab7d6fed7b1b44cd72cf96431d167c903d1e79e301975a839").unwrap());
        let b = BigNum::frombytes(&hex::decode("0076290e6c669f7360791f17c1c9c2397152bb5c430465441460e32d25ce7764db563150e023242f6125f460163fab1c").unwrap());
        let mut check_z = FP2::new_bigs(&a, &b);
        check_z.inverse();
        check_x.mul(&check_z);
        check_x.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        let mut check_y2 = check_y.clone();
        check_y2.sqr();
        let mut rhs = GroupG2::rhs(&mut check_x);
        assert!(check_y2.equals(&mut rhs));

        let mut check = GroupG2::new_fp2s(&check_x, &check_y);
        assert!(res0.equals(&mut check));

        // Clear the G2 cofactor
        let mut final_res = clear_g2_psi(&mut res0);

        // Check Final Output
        let a = BigNum::frombytes(&hex::decode("01ae06a47f65ee6bd2a5c2183d690394f1820154a5948494b251a7826e473455ba9cabe005cdd26c21ee50ce838375be").unwrap());
        let b = BigNum::frombytes(&hex::decode("11a5d76e2d5bea4bfb906a2d19fe515d2ec7bd827c38462e84b642212815e40508e9b4bcd9e9c9e30d5f16fe85a9f23a").unwrap());
        let mut check_x = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("094bd75f93aa4cf59f9aac6141f3ba2251aeb64954cc1e92ea35b5ff2f4f8640b0aa313d3f4b30898634419cc2341607").unwrap());
        let b = BigNum::frombytes(&hex::decode("0bd0aa2a56ede7f0adbbf5dbdfc6fd2337e90d9049878a88b46d1792111f9ff8640d4d072168e289e86e612a0dace92d").unwrap());
        let mut check_y = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("1990f0d273879af0fdb067a08663339a3184bd326c10314db0e84bafb259e0f802d5b051a693d09d258a6c7d3cca8ed7").unwrap());
        let b = BigNum::frombytes(&hex::decode("00605da10253e069ccd91aeb8fd233c721fa92c865f202e6c93bce3d57ff62c328c50b4b8ede61398f5b0ce76b465f47").unwrap());
        let mut check_z = FP2::new_bigs(&a, &b);
        check_z.inverse();
        check_x.mul(&check_z);
        check_x.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        let mut check_y2 = check_y.clone();
        check_y2.sqr();
        let mut rhs = GroupG2::rhs(&mut check_x);
        assert!(check_y2.equals(&mut rhs));

        let mut check = GroupG2::new_fp2s(&check_x, &check_y);
        assert!(final_res.equals(&mut check));

        println!("Final 2:{}", final_res.tostring());

    }

    #[test]
    fn optimised_swu_twice_3() {
        // Input hash from C impl input "3" + enter + ctrlD
        let msg = hex::decode("7c1997b9728f11f77f3921d4bf6684fa3c9648957bebd8840cfaab97d3c8986d").unwrap();
        let mut t0 = hash_to_field_g2(&msg, 0);
        let mut t1 = hash_to_field_g2(&msg, 1);

        // Check hash to field values
        let a = BigNum::frombytes(&hex::decode("192fa68a928fe5c78d7d682fafdad4ecbcef2220825e965e502b6e4d8c8896545cd28239c4f77926d50ecc87413756da").unwrap());
        let b = BigNum::frombytes(&hex::decode("08ab705d65d061da89b203e95e6e1a25f89038f61aebc498f84a1bae6ed4201785f44e12a4fa6f2c5536dea9f27df0a4").unwrap());
        let mut check_t0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("0b38a2f9e7e8216d39a295dd2f6298e675a4956de44ce37fa02e977c8ffeb55d4dabe0e134835abbba9f14d0fac4cb79").unwrap());
        let b = BigNum::frombytes(&hex::decode("0a07e99edfff8a301d233b9ecc4346d4b89ff814b6cda50ddde3524ade30b2d932a4c2c8d6ae1ad0eab0618f7bb52c53").unwrap());
        let mut check_t1 = FP2::new_bigs(&a, &b);
        assert!(t0.equals(&mut check_t0));
        assert!(t1.equals(&mut check_t1));

        // Convert hashed value to Point on the 3-Isogeny Curve
        let (mut x0, mut y0, mut z0) = hash_to_iso3_point(&t0);
        let (mut x1, mut y1, mut z1) = hash_to_iso3_point(&t1);

        // Check 3-Isogeny points (Jacobian)
        let a = BigNum::frombytes(&hex::decode("0b28cf20a94cd9cc902f20d9ee1ab44b67673c08f6e89de4d3be4cd796a3952bbe5be139e8e1b521743c70daf8aad297").unwrap());
        let b = BigNum::frombytes(&hex::decode("19b27035ce9f2884a4a6c6c09f0b47f643c947140e1a15783fc3d928b896cb32f8ec2afbe812d66c41b6fffb49a26118").unwrap());
        let mut check_x0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("10caa2e00b1e4188de722d593ce10fdce8e4f5820e4e3ee5e20992a595f65c8ad8d059d8b4ed11bc730f3c0cbd703174").unwrap());
        let b = BigNum::frombytes(&hex::decode("1935e0899c223a1f7b93a62bf5ab2739e77bc49e60c646af51e9b462d30385880d9fcaa5ef5fdd8a13df8af2b85dc24d").unwrap());
        let mut check_y0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("0eaf0b776e08b489343507bd639c04181bb9564545c4ecf1f7b4e653a2898d180b2865148789a4ce34e7e35d63418067").unwrap());
        let b = BigNum::frombytes(&hex::decode("13422a52394e86d5a8616b532073a5b2006e6f24ba596a94601c9264e5a2959ed7ba9fe8bc810490accb3e0a466d4369").unwrap());
        let mut check_z0 = FP2::new_bigs(&a, &b);

        let a = BigNum::frombytes(&hex::decode("02e1aa7aaa5b7b3d14d9a5290e5a678823722e3bc9d5c8e75d0f448520d0efcbc158fe33a6aa5a460655c933232740da").unwrap());
        let b = BigNum::frombytes(&hex::decode("0b0a03c1a5458f876bed00af5f2ca06e91ab754714a03cf3268410740a0e38d50ea94078414995af7eee0c63379bac7f").unwrap());
        let mut check_x1 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("090e1e82caa9519e1a507cb714c8e175794593ae5cc15a67ffd88094073448757c6eb816cd2e85b97c6b4e969c8e1584").unwrap());
        let b = BigNum::frombytes(&hex::decode("1714530c568cbe72151bb4eaf3bf02ad503406572ad1cc9d6abadcf59db896423275d5bbc70ed7cf314ec9219d1cc903").unwrap());
        let mut check_y1 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("073a19bf66c2ddf0e02b36a00011b8959f4a7fb59cd13770bf843f08c780928db27e3d472912976086f8cb1395814aac").unwrap());
        let b = BigNum::frombytes(&hex::decode("0c6c8de666070cfb0377052c069996384f43e38d1b9e42d0d5a5211bd592515823239a016528f0ec630dc23205d9b26c").unwrap());
        let mut check_z1 = FP2::new_bigs(&a, &b);

        assert!(x0.equals(&mut check_x0));
        assert!(y0.equals(&mut check_y0));
        assert!(z0.equals(&mut check_z0));
        assert!(x1.equals(&mut check_x1));
        assert!(y1.equals(&mut check_y1));
        assert!(z1.equals(&mut check_z1));


        let (mut jac_x, mut jac_y, mut jac_z) = jacobian_add_fp2(&x0, &y0, &z0, &x1, &y1, &z1);

        let mut res0 = iso3_to_g2(&jac_x, &jac_y, &jac_z);

        // Check after eval_iso3()
        let a = BigNum::frombytes(&hex::decode("10f15d2d82046be483f0a2d24641d011ada1c028a139a9c2e2b3753c88fa20af9c9cbb3b5ae3a706d9aa7d4b168cfc9c").unwrap());
        let b = BigNum::frombytes(&hex::decode("18b6d01d4e800ebadd600b83092c6b7d23a854d3e77fc666836a827e0c7635a32c274e0a1870a4138dc7798d87a32a70").unwrap());
        let mut check_x = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("02933c17729d6da528ba3a94fe3b617e154f6ac7cb3790829dffa45f1444396821d74909fa2f91e5a20ab12981ae598c").unwrap());
        let b = BigNum::frombytes(&hex::decode("0bba1a7e48556472b361e952cbd91ff1a2ede735621767886b316beacf7b8ab8dfc56be2616ed7e1641320a59bd38ac2").unwrap());
        let mut check_y = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("09ab37fe14d1656706102bcd107bfafc4f2bd013271bf32983ad54dcb8c440b33571ed7e5922e0b2ccda5f62bd3a8574").unwrap());
        let b = BigNum::frombytes(&hex::decode("145b2d715c31c65994ffb75e281c8a6f45e44c7fa6aa8626452a16be32edea0401dbd8d6ebd601020a9eb19c474d3709").unwrap());
        let mut check_z = FP2::new_bigs(&a, &b);
        check_z.inverse();
        check_x.mul(&check_z);
        check_x.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        let mut check_y2 = check_y.clone();
        check_y2.sqr();
        let mut rhs = GroupG2::rhs(&mut check_x);
        assert!(check_y2.equals(&mut rhs));

        let mut check = GroupG2::new_fp2s(&check_x, &check_y);
        assert!(res0.equals(&mut check));

        // Clear the G2 cofactor
        let mut final_res = clear_g2_psi(&mut res0);

        // Check Final Output
        let a = BigNum::frombytes(&hex::decode("0f7d648e73da1a8eda4709fd113f84952a08913a1cdd0a9a6425e8f6057868806c9ad3340b0db309e8b9eae6c559f10e").unwrap());
        let b = BigNum::frombytes(&hex::decode("0abed29ace5ba1204bbd36d4484bb7ed3ad46f57a910319db612eb715e86dd36a8ccf43c499137e62a36dc1dcbff2343").unwrap());
        let mut check_x = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("100fb2d793de23d29c191ee519f6ea14a0f9b0191182d69e1708e6996227dc198771bfa92139d46964bcc774f8738035").unwrap());
        let b = BigNum::frombytes(&hex::decode("191825a1976fa3b865ff3f79580e6d92d8ab76541d2af234beb7b2cee8cf6ca84d59fcc308ed01ab5909254c2df2ee99").unwrap());
        let mut check_y = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("13114a742efbda0422ffc04e4b1a6d1a3895543fd8fc3ec3af64b8fc1b449094b49668273ab5b00a8873955238aeb883").unwrap());
        let b = BigNum::frombytes(&hex::decode("076df0f0af03f9f54442883ce4c782557abd39e5b4889da2914f569cd9303a5404de4f2e987cb281241424bd66ddd1f1").unwrap());
        let mut check_z = FP2::new_bigs(&a, &b);
        check_z.inverse();
        check_x.mul(&check_z);
        check_x.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        let mut check_y2 = check_y.clone();
        check_y2.sqr();
        let mut rhs = GroupG2::rhs(&mut check_x);
        assert!(check_y2.equals(&mut rhs));

        let mut check = GroupG2::new_fp2s(&check_x, &check_y);
        assert!(final_res.equals(&mut check));

        println!("Final 3{}", final_res.tostring());
    }

    #[test]
    fn optimised_swu_twice_small_msg() {
        // Input manually entered
        let msg = hex::decode("02a6").unwrap();
        let mut t0 = hash_to_field_g2(&msg, 0);
        let mut t1 = hash_to_field_g2(&msg, 1);

        // Check hash to field values
        let a = BigNum::frombytes(&hex::decode("17b5fb24d98e8195f53bf6273783f39fa9ad2dc3346949362a2cf43de46d19116f8d945e52b46b468762cd8dd5b6b6a6").unwrap());
        let b = BigNum::frombytes(&hex::decode("0ad18f9a699d661943a31f4c45f1e56bd3b20d4903d43cde114e1ca2893058c7905965e1681834c5d44f6fa377ed2438").unwrap());
        let mut check_t0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("13574d620c9b335845355de63f92fc4d59d43fe18e4b829b751ed12e91098bc17595eaa875f0f4c759ff3fd83b0dbd78").unwrap());
        let b = BigNum::frombytes(&hex::decode("15a5017c3d552a4564e815d6ab7ed61e77c27ae07d789054998359c1a0e966cfed96c8f3e8dbb8bcf35d4def48824431").unwrap());
        let mut check_t1 = FP2::new_bigs(&a, &b);
        assert!(t0.equals(&mut check_t0));
        assert!(t1.equals(&mut check_t1));

        // Convert hashed value to Point on the 3-Isogeny Curve
        let (mut x0, mut y0, mut z0) = hash_to_iso3_point(&t0);
        let (mut x1, mut y1, mut z1) = hash_to_iso3_point(&t1);

        // Check 3-Isogeny points (Jacobian)
        let a = BigNum::frombytes(&hex::decode("15fc888a4413ceb2e431cf2b4eef1f15c68aeb58c9f8b155f8922d9c08f54d4d80a7c3c9963e99a5aac9a3e1551fe486").unwrap());
        let b = BigNum::frombytes(&hex::decode("0260f020e243cd565a6ac3602d822fc8d2351e98beed14236bad74d88c4f7daeaa334709bfd4ec8c977d8fa8d9d31256").unwrap());
        let mut check_x0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("066e4f493f61127fb0ff3ee01f0c5d1ef5cacfb584a4d99230a042ca793f70765cc9195ea552e585ed0333e0edffd361").unwrap());
        let b = BigNum::frombytes(&hex::decode("172edbd64e6ad9db55b4e7585ced3eb3b3102771a0e54d95e02c8f442892c7735b09c52f316012b329d95ed670fc3f24").unwrap());
        let mut check_y0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("12960a06b3e903abc1e8e9a95425419010ee47d0f3f2f1ebf1aadaf7532844a385d8db0bf398525409ba324ab6b2809b").unwrap());
        let b = BigNum::frombytes(&hex::decode("055559f0406eb7210b5f1b1066ee91c9aa2fd49476ec923d71f238dcc339cdbe8762c3073fb4e6dbee38f1fa52290992").unwrap());
        let mut check_z0 = FP2::new_bigs(&a, &b);

        let a = BigNum::frombytes(&hex::decode("1576d4cf336161af4b1bc41f00f8ef55377932dd7012ace52c0199e9ad11358ea80d3dab1ec4b036a00d66346fd619e5").unwrap());
        let b = BigNum::frombytes(&hex::decode("0668413c2b1f189d0a34da84b9e8fabc30e9c79e6257b3348caa2ab38a449d81193880e0f3321dcc96e4f63a140da252").unwrap());
        let mut check_x1 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("1905cf11b46551cdbb8881073f2c4a9c95a02c630968c10dce4ca074d55fe86db89dae0558e89e269709faacebcc0a69").unwrap());
        let b = BigNum::frombytes(&hex::decode("13584d263666a81c8c03e98c5e80de3edcbccc74a4902bd81605f2d21048927e61c05fcc1091ff4bd70f261467efa768").unwrap());
        let mut check_y1 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("10c061b63748f7b7e301b642f125b5cd2bd4691570951afb5629689fc629a2f6e59cc0d18ff1d27f1a190e5e69f1a257").unwrap());
        let b = BigNum::frombytes(&hex::decode("0bbe6eba0185347e7c0e64f92b8b309ad2d38a3602ccb406790ffa2bad4177082c975e87c616dd9b783d45f87f4185be").unwrap());
        let mut check_z1 = FP2::new_bigs(&a, &b);

        assert!(x0.equals(&mut check_x0));
        assert!(y0.equals(&mut check_y0));
        assert!(z0.equals(&mut check_z0));
        assert!(x1.equals(&mut check_x1));
        assert!(y1.equals(&mut check_y1));
        assert!(z1.equals(&mut check_z1));


        let (mut jac_x, mut jac_y, mut jac_z) = jacobian_add_fp2(&x0, &y0, &z0, &x1, &y1, &z1);

        let mut res0 = iso3_to_g2(&jac_x, &jac_y, &jac_z);

        // Check after eval_iso3()
        let a = BigNum::frombytes(&hex::decode("1212fb4a4e68b63d117c86ad51e59dbe2f36525cf1f115136042c891fbd4203063337e53a15678bdfebee02a14d6ab29").unwrap());
        let b = BigNum::frombytes(&hex::decode("0421efdc9628e90a9ad582d8ab154e6d79e352dd3a5fe6b2eaec4b04be126d126ce642049c3a800fb41b964df902a943").unwrap());
        let mut check_x = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("107dec18003efe388e9fbbe3584c5777c8608610b60d296a214c912e1df5b988665de38482c8a8ed04591b5fde04ee08").unwrap());
        let b = BigNum::frombytes(&hex::decode("102dd7533ced5f577592a4cc4160d9e76b30077994239a762ba6d6a9a625146b14948303fba772a67d5cf6671f8959db").unwrap());
        let mut check_y = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("17c4f30771fc0778482cfd3703c126369563438445ef256200fb76f69d41f96f547fb40f8ccf1213ef44aed6e130bdac").unwrap());
        let b = BigNum::frombytes(&hex::decode("1232491b93132224e53dbf0b6473d62ff265c8cff1a870d628138ea342a5d86d0b0010414002781505a5b68bc2c25fbe").unwrap());
        let mut check_z = FP2::new_bigs(&a, &b);
        check_z.inverse();
        check_x.mul(&check_z);
        check_x.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        let mut check_y2 = check_y.clone();
        check_y2.sqr();
        let mut rhs = GroupG2::rhs(&mut check_x);
        assert!(check_y2.equals(&mut rhs));

        let mut check = GroupG2::new_fp2s(&check_x, &check_y);
        assert!(res0.equals(&mut check));

        // Clear the G2 cofactor
        let mut final_res = clear_g2_psi(&mut res0);

        // Check Final Output
        let a = BigNum::frombytes(&hex::decode("15033d8bcc602a85ccbbb79ba9ea8f01ce1e99304edffb2a49fbfe38141733da5f300ac0b4cb504b3c1ff58461ef3edf").unwrap());
        let b = BigNum::frombytes(&hex::decode("15af65fb5da64918c5e761f282e79a116fde9e1d210e4a96d2fbe9c311db510349abbf4c5c01a12a77e0480fe3ecd546").unwrap());
        let mut check_x = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("04d22e6419e9bdf08fc3bf3d2e2a50e62780b2792d364469f9ddcea52c1cb85d30380ed01fad0da0dc120ce10d92ecc5").unwrap());
        let b = BigNum::frombytes(&hex::decode("07e3b72e074a9bce848beb13accd48f8989a3b24cc3769493c986b02a90ff1c09467f6b44819cecd6cef3a7f81d32dae").unwrap());
        let mut check_y = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("08430b17d99604b0763bd57769108d6c688a1ee75cd06b2ac88de8a35c8898e4fb8536164ba1a6f14797ee0584753e21").unwrap());
        let b = BigNum::frombytes(&hex::decode("167b3d6c8e0770bcc4c616cce97778e9fccd07a2bc5fae14f011d12e7d5c4d32ff7b76852e02cc0fb63c0e8563eb5222").unwrap());
        let mut check_z = FP2::new_bigs(&a, &b);
        check_z.inverse();
        check_x.mul(&check_z);
        check_x.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        let mut check_y2 = check_y.clone();
        check_y2.sqr();
        let mut rhs = GroupG2::rhs(&mut check_x);
        assert!(check_y2.equals(&mut rhs));

        let mut check = GroupG2::new_fp2s(&check_x, &check_y);
        assert!(final_res.equals(&mut check));
        println!("Final small: {}", final_res.tostring());
    }

    #[test]
    fn optimised_swu_twice_msg_0() {
        // Input manually entered
        let msg = hex::decode("00").unwrap();
        let mut t0 = hash_to_field_g2(&msg, 0);
        let mut t1 = hash_to_field_g2(&msg, 1);

        // Check hash to field values
        let a = BigNum::frombytes(&hex::decode("150deb9eb912f36d4e5ea8aec1b8fe08c8ddfff6d3a2d81cf54233d2d08ae44f0b50a9e01a671465180ab4b0716468bc").unwrap());
        let b = BigNum::frombytes(&hex::decode("0e93f02e701b9d7cb8e38950e127b64a78243ea4526a699f6af317e9739efd597489ec727692d89dd7f3490678672c53").unwrap());
        let mut check_t0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("01a2537f646bd2991388fc4ab53621a157a23d5632d547c269ff9b989e683fe7d10c6a4698ea83d589d611a75944ebd7").unwrap());
        let b = BigNum::frombytes(&hex::decode("0935419ca653e504bbff894eac9be1e6a0f77ebd6e87dd37da0b5e0cd3119f1bbf2a8d610f273cd6ea2b48ffa148d110").unwrap());
        let mut check_t1 = FP2::new_bigs(&a, &b);
        assert!(t0.equals(&mut check_t0));
        assert!(t1.equals(&mut check_t1));

        // Convert hashed value to Point on the 3-Isogeny Curve
        let (mut x0, mut y0, mut z0) = hash_to_iso3_point(&t0);
        let (mut x1, mut y1, mut z1) = hash_to_iso3_point(&t1);

        // Check 3-Isogeny points (Jacobian)
        let a = BigNum::frombytes(&hex::decode("0d22dcac62270d68ef7b43616d1ac6cbc734320a3fd86391e888ab06166376a5e768c790b8daa8aa7adca31777645efa").unwrap());
        let b = BigNum::frombytes(&hex::decode("05cacc57c98bd2e451c7e9ddf0f02fc1bf67a1e742aa0518fd2949f4830a3375633c31bb2b7f9f409e134c68e279dd00").unwrap());
        let mut check_x0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("0c5b3480d1d757f88f845a45508966212a69a3457496a665adb93fd74271d16243981fe636b513f50a1fb373f017c0ce").unwrap());
        let b = BigNum::frombytes(&hex::decode("1857a881e2f7543d7671f36e30cfda0a14e038866e0b94b0165dca607749b75b3b703c1f3fa911f37d38f2e8143c1823").unwrap());
        let mut check_y0 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("02ef61e805aeceb4026436adae72dba9acdedd92535b52691e88b11f30a17eb767d9925c5acb2fa7d3ed2450922c7f11").unwrap());
        let b = BigNum::frombytes(&hex::decode("06bc352ac58032c0b52ab489890f415ba30f7bb58f71a54d2269c401eee17930bda500a1a927deca1058f9d4696bc67b").unwrap());
        let mut check_z0 = FP2::new_bigs(&a, &b);

        let a = BigNum::frombytes(&hex::decode("183f3f6708d07378d704d8ba2fadea95483d006582689f3c7a1832e11756951dc20d6aa2a2924497ad3410f94f6c5b13").unwrap());
        let b = BigNum::frombytes(&hex::decode("0b5a63f3a60872c5f200c2b4b25af25f37fcff49aec1981c1b96fdf9edaccfa9dfd2ca62dd2b8008376c1d48e184b264").unwrap());
        let mut check_x1 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("047536d6770f1efc1ab5ebb83e959710dfb3baf080302d87e4228fbbfb1bef6ef170ee35bf2953518de868e439a87ab8").unwrap());
        let b = BigNum::frombytes(&hex::decode("16d8d8bd4ccc5f73c5751230fda17f4529dc7430eb8d1ec20f4812afb20f6a10d3ecb7910cddd93bdbe227f34f45edb8").unwrap());
        let mut check_y1 = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("14bfb2ce447aa0fff0079fda16ce7761c706e7a1a04a4afab5135019e966f3f2af1516eb82336c43a500a67b4d69268d").unwrap());
        let b = BigNum::frombytes(&hex::decode("1654fa579add36b8fd3734472b55b2f446d000d4b9e5a46d7b8b6315906aa44f5579a1e61f4111f2eb24c58a8b1cb721").unwrap());
        let mut check_z1 = FP2::new_bigs(&a, &b);

        assert!(x0.equals(&mut check_x0));
        assert!(y0.equals(&mut check_y0));
        assert!(z0.equals(&mut check_z0));
        assert!(x1.equals(&mut check_x1));
        assert!(y1.equals(&mut check_y1));
        assert!(z1.equals(&mut check_z1));


        let (mut jac_x, mut jac_y, mut jac_z) = jacobian_add_fp2(&x0, &y0, &z0, &x1, &y1, &z1);

        let mut res0 = iso3_to_g2(&jac_x, &jac_y, &jac_z);

        // Check after eval_iso3()
        let a = BigNum::frombytes(&hex::decode("140fe61ec5b97b06893d75e02d95bf6e2f5fd37b68dd0d85acc1a6e5ffa36ce19dd81a7d9be9945e12cfce8288faa51b").unwrap());
        let b = BigNum::frombytes(&hex::decode("043f79f32f057155a761f41d02846419c5aeb8ae762462482d50ae412ce935266e5e63034093dcb0b7196d3c028d1528").unwrap());
        let mut check_x = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("0f305c2c027f474cf2c7718bb5c9aa4c8e21d1133b54b5a06c4e3bdff9df7221fd633bff29c965620bbad8e3f5c8c56a").unwrap());
        let b = BigNum::frombytes(&hex::decode("13afa3a202e77cc86b3f766c49db23971a3f357569f31ef6358da820bcc2089d637937f4ed2b0427c7b186f3f091e4e9").unwrap());
        let mut check_y = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("134de28de8318e473fca8ced870f380fbd5679b14ef8648e677f781891fbdf730762b4633963b258c3190e798ce74f14").unwrap());
        let b = BigNum::frombytes(&hex::decode("109dfa418e73796b40a1606fd7efbe7e28c7f0ad1d82d110799cc31106d158ce97f64ec2e05e09d822c9ebcf34a03f97").unwrap());
        let mut check_z = FP2::new_bigs(&a, &b);
        check_z.inverse();
        check_x.mul(&check_z);
        check_x.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        let mut check_y2 = check_y.clone();
        check_y2.sqr();
        let mut rhs = GroupG2::rhs(&mut check_x);
        assert!(check_y2.equals(&mut rhs));

        let mut check = GroupG2::new_fp2s(&check_x, &check_y);
        assert!(res0.equals(&mut check));

        // Clear the G2 cofactor
        let mut final_res = clear_g2_psi(&mut res0);

        // Check Final Output
        let a = BigNum::frombytes(&hex::decode("031b85b49554ce5801f61c10d1abdc533f5ba06524a94bf0f9bab9cc9ac4db8ae5cba40f11d5bb1c988e79f29675741e").unwrap());
        let b = BigNum::frombytes(&hex::decode("17e38bd5d56cd763e2c580a8102cb02f58a629298c520e750ed3c1a06ce42e78ffce37b1dc6297e2bc45cfd593dc498a").unwrap());
        let mut check_x = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("053576afd53b130a42e7cb221a71e0900afc2e9441530af2f2eb9586a436ce40ae4c565a8e14cb0ff8ff70d56e66cb4d").unwrap());
        let b = BigNum::frombytes(&hex::decode("185c2d6cf88f37ced50ac94b68666ad70977abb0d987a33952cc8066581dd36e2cdeea0b6e4d413405a585a80ef0f091").unwrap());
        let mut check_y = FP2::new_bigs(&a, &b);
        let a = BigNum::frombytes(&hex::decode("12a73f06c1f0ce895139969567e9f5f1921f5cb4fdb0022a6dad0b8b33c66e066e62526388690a9f9b4e295a07ddef86").unwrap());
        let b = BigNum::frombytes(&hex::decode("130527a6d37048062bab1e8bb879155498945489ad3d815377b35a7456b7fc9d56d155c8c4cb5e387903b5c16dbe0991").unwrap());
        let mut check_z = FP2::new_bigs(&a, &b);
        check_z.inverse();
        check_x.mul(&check_z);
        check_x.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        let mut check_y2 = check_y.clone();
        check_y2.sqr();
        let mut rhs = GroupG2::rhs(&mut check_x);
        assert!(check_y2.equals(&mut rhs));

        let mut check = GroupG2::new_fp2s(&check_x, &check_y);
        assert!(final_res.equals(&mut check));
        println!("Final zero: {}", final_res.tostring());
    }
}

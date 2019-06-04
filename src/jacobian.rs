use amcl_utils::{BigNum, FP, FP2};

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
    x.sub(&temp);                   // Y = r^2 - J - 2V

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

/* An implementation of co-factor clearing
* Implementation: https://github.com/kwantam/bls_sigs_ref
* Paper: https://eprint.iacr.org/2017/419
* Adjustments:
* - Input and Output are Standard Projective form (X, Y, Z) -> (X / Z, Y / Z) as opposed to
*   Jacobian (X, Y, Z) -> (X / Z^2, Y / Z^3)
*/
use super::amcl_utils::{BigNum, FP, FP2, GroupG2};

#[cfg(feature = "std")]
lazy_static! {
    // Psi Constants for clearing G2 Cofactor
    pub static ref PSI_INVERSES_W_SQR_CUBE: FP2 = FP2::new_bigs(
        &BigNum::frombytes(&hex::decode("0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd556").unwrap()),
        &BigNum::frombytes(&hex::decode("0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555").unwrap()));
    pub static ref PSI_QI_X: FP = FP::new_big(
        &BigNum::frombytes(&hex::decode("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad").unwrap()));
    pub static ref PSI_QI_Y: FP = FP::new_big(
        &BigNum::frombytes(&hex::decode("06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09").unwrap()));
    pub static ref PSI_TWIST_CORRECTION_X: FP = FP::new_big(
        &BigNum::frombytes(&hex::decode("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad").unwrap()));
    pub static ref PSI_TWIST_CORRECTION_Y: FP2 = FP2::new_bigs(
        &BigNum::frombytes(&hex::decode("135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2").unwrap()),
        &BigNum::frombytes(&hex::decode("06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09").unwrap()));
}

// Clearing the G2 cofactor via Psi.
//
// See https://eprint.iacr.org/2017/419 Section 4.1
pub fn clear_g2_psi(point: &mut GroupG2) -> GroupG2 {
    let mut point2 = point.clone();
    point2.add(&point); // 2P
    let mut temp0 = psi_addition_chain(&point); // -xP
    temp0.add(&point); // (-x + 1) P
    let mut temp1 = point.clone(); // P
    temp1.neg(); // -P
    let temp2 = psi(&temp1); // - psi(P)
    temp0.add(&temp2); // (-x + 1) P + - psi(P)
    let mut temp3 = psi_addition_chain(&temp0); // (x^2 - x) P + x psi(P)
    temp3.add(&temp2); // (x^2 - x) P + (x - 1) psi(P)
    temp1.add(&temp3); // (x^2 - x - 1) P + (x - 1) psi(P)
    point2 = psi(&point2); // psi(2P)
    point2 = psi(&point2); // psi(psi(2P))
    temp1.add(&point2); // (x^2 - x - 1) P + (x - 1) psi(P) - psi(psi(2P))
    temp1 // (x^2 - x - 1) P + (x - 1) psi(P) - psi(psi(2P))
}

// Returns -xP
fn psi_addition_chain(point: &GroupG2) -> GroupG2 {
    let mut x = point.clone();

    x.dbl(); // 2
    x.add(&point); // 3
    for _ in 0..2 {
        x.dbl(); // 12
    }
    x.add(&point); // 13
    for _ in 0..3 {
        x.dbl(); // 104
    }
    x.add(&point); // 105
    for _ in 0..9 {
        x.dbl(); // 53,760
    }
    x.add(&point); // 53761
    for _ in 0..32 {
        x.dbl(); // 230901736800256
    }
    x.add(&point); // 230901736800257
    for _ in 0..16 {
        x.dbl(); // 15132376222941577216
    }
    x
}

// Psi
fn psi(point: &GroupG2) -> GroupG2 {
    let mut x_den = point.getpz(); // Z
    let mut y_den = point.getpz(); // Z

    // Calculate new x
    let mut x = psi_x(point.getpx());
    x.pmul(&PSI_TWIST_CORRECTION_X);
    x.times_i();
    let mut x_den = psi_x(x_den);

    // Calculate new y
    let mut y = psi_y(point.getpy());
    y.mul(&PSI_TWIST_CORRECTION_Y);
    let y_den = psi_y(y_den);

    // Standard Projective
    let mut z = x_den.clone();
    z.mul(&y_den); // x_denominator * y_denominator
    x.mul(&y_den); // x * y_denominator
    y.mul(&x_den); // y * x_denominator

    GroupG2::new_projective(x, y, z)
}

fn psi_x(mut x: FP2) -> FP2 {
    x.mul(&PSI_INVERSES_W_SQR_CUBE);
    x.pmul(&PSI_QI_X);
    x.conj();
    x
}

fn psi_y(mut y: FP2) -> FP2 {
    y.mul(&PSI_INVERSES_W_SQR_CUBE);
    y.spmt();
    y.pmul(&PSI_QI_Y);
    y
}

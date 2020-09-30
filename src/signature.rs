extern crate amcl;

use super::amcl_utils::{
    self, ate2_evaluation, compress_g2, decompress_g2, g2mul, hash_to_curve_g2, subgroup_check_g2,
    AmclError, GroupG2, G2_BYTES,
};
use super::keys::{PublicKey, SecretKey};

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Signature {
    pub point: GroupG2,
}

impl Signature {
    /// Instantiate a new Signature from a message and a SecretKey.
    pub fn new(msg: &[u8], sk: &SecretKey) -> Self {
        let hash_point = hash_to_curve_g2(msg);
        let sig = g2mul(&hash_point, sk.as_raw());
        Self { point: sig }
    }

    /// CoreVerify
    ///
    /// Verifies the Signature against a PublicKey.
    /// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3
    pub fn verify(&self, msg: &[u8], pk: &PublicKey) -> bool {
        // Signature Subgroup checks
        if !subgroup_check_g2(&self.point) {
            return false;
        }
        // KeyValidate
        if !pk.key_validate() {
            return false;
        }

        let mut msg_hash_point = hash_to_curve_g2(msg);
        msg_hash_point.affine();

        // Faster ate2 evaualtion checks e(S, -G1) * e(H, PK) == 1
        let mut generator_g1_negative = amcl_utils::GroupG1::generator();
        generator_g1_negative.neg();
        ate2_evaluation(
            &self.point,
            &generator_g1_negative,
            &msg_hash_point,
            &pk.point,
        )
    }

    /// Instantiate a Signature from compressed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, AmclError> {
        let point = decompress_g2(&bytes)?;
        Ok(Self { point })
    }

    /// Compress the Signature as bytes.
    pub fn as_bytes(&self) -> [u8; G2_BYTES] {
        compress_g2(&self.point)
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;
    extern crate rand;

    use super::super::keys::Keypair;
    use super::*;

    #[test]
    fn basic_sign_verify() {
        let keypair = Keypair::random(&mut rand::thread_rng());
        let sk = keypair.sk;
        let vk = keypair.pk;

        let messages = vec!["", "a", "an example"];

        for m in messages {
            /*
             * Simple sign and verify
             */
            let bytes = m.as_bytes();
            let sig = Signature::new(&bytes, &sk);
            assert!(sig.verify(&bytes, &vk));

            /*
             * Test serializing, then deserializing the signature
             */
            let sig_bytes = sig.as_bytes();
            let new_sig = Signature::from_bytes(&sig_bytes).unwrap();
            assert_eq!(&sig.as_bytes().to_vec(), &new_sig.as_bytes().to_vec());
            assert!(new_sig.verify(&bytes, &vk));
        }
    }

    #[test]
    fn verification_failure_message() {
        let keypair = Keypair::random(&mut rand::thread_rng());
        let sk = keypair.sk;
        let vk = keypair.pk;

        let mut msg = "Some msg";
        let sig = Signature::new(&msg.as_bytes(), &sk);
        msg = "Other msg";
        assert_eq!(sig.verify(&msg.as_bytes(), &vk), false);
        msg = "";
        assert_eq!(sig.verify(&msg.as_bytes(), &vk), false);
    }

    #[test]
    fn test_readme() {
        // This is an exact replica of the README.md at the top level.
        let sk_bytes = vec![
            78, 252, 122, 126, 32, 0, 75, 89, 252, 31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194,
            233, 117, 181, 75, 96, 238, 79, 100, 237, 59, 140, 111,
        ];

        // Load some keys from a serialized secret key.
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&sk);

        // Sign a message
        let message = "cats".as_bytes();
        let signature = Signature::new(&message, &sk);
        assert!(signature.verify(&message, &pk));

        // Serialize then de-serialize, just 'cause we can.
        let pk_bytes = pk.as_bytes();
        let pk = PublicKey::from_bytes(&pk_bytes).unwrap();

        // Verify the message
        assert!(signature.verify(&message, &pk));
    }
}

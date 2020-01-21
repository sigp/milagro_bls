extern crate amcl;

use super::amcl_utils::{self, ate2_evaluation, hash_on_g2};
use super::errors::DecodeError;
use super::g2::G2Point;
use super::keys::{PublicKey, SecretKey};

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Signature {
    pub point: G2Point,
}

impl Signature {
    /// Instantiate a new Signature from a message and a SecretKey.
    pub fn new(msg: &[u8], sk: &SecretKey) -> Self {
        let hash_point = hash_on_g2(msg);
        let mut sig = hash_point.mul(&sk.x);
        sig.affine();
        Self {
            point: G2Point::from_raw(sig),
        }
    }

    /// Verify the Signature against a PublicKey.
    ///
    /// In theory, should only return true if the PublicKey matches the SecretKey used to
    /// instantiate the Signature.
    pub fn verify(&self, msg: &[u8], pk: &PublicKey) -> bool {
        let mut msg_hash_point = hash_on_g2(msg);
        msg_hash_point.affine();

        // Faster ate2 evaualtion checks e(S, -G1) * e(H, PK) == 1
        let mut generator_g1_negative = amcl_utils::GroupG1::generator();
        generator_g1_negative.neg();
        ate2_evaluation(
            &self.point.as_raw(),
            &generator_g1_negative,
            &msg_hash_point,
            &pk.point.as_raw(),
        )
    }

    /// Instantiate a Signature from compressed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, DecodeError> {
        let point = G2Point::from_bytes(bytes)?;
        Ok(Self { point })
    }

    /// Compress the Signature as bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut clone = self.point.clone();
        clone.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;
    extern crate rand;
    extern crate yaml_rust;

    use self::yaml_rust::yaml;
    use super::super::keys::Keypair;
    use super::*;
    use std::{fs::File, io::prelude::*, path::PathBuf};

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
            assert_eq!(&sig.as_bytes(), &new_sig.as_bytes());
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
    // Test vectors use Keccak whilst this implementation uses SHA2.
    #[should_panic]
    #[ignore]
    fn case04_sign_messages() {
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

        // Select test case04
        let test_cases = doc["case04_sign_messages"].as_vec().unwrap();

        // Verify input against output for each pair
        for test_case in test_cases {
            // Convert input to rust formats
            let input = test_case["input"].clone();
            // Convert domain from yaml to u64
            let domain = input["domain"].as_str().unwrap();
            let domain = domain.trim_start_matches("0x");
            let _domain = u64::from_str_radix(domain, 16).unwrap();

            // Convert msg from yaml to bytes (Vec<u8>)
            let msg = input["message"].as_str().unwrap();
            let msg = msg.trim_start_matches("0x");
            let msg = hex::decode(msg).unwrap();

            // Convert privateKey from yaml to SecretKey
            let privkey = input["privkey"].as_str().unwrap();
            let privkey = privkey.trim_start_matches("0x");
            let mut privkey = hex::decode(privkey).unwrap();
            while privkey.len() < 48 {
                // Prepend until correct length
                privkey.insert(0, 0);
            }
            let sk = SecretKey::from_bytes(&privkey).unwrap();

            // Create signature
            let sig = Signature::new(&msg, &sk);
            let compressed_sig = sig.as_bytes();

            // Convert given output to rust compressed signature (Vec<u8>)
            let output = test_case["output"].as_str().unwrap();
            let output = output.trim_start_matches("0x");
            let output = hex::decode(output).unwrap();

            assert_eq!(output, compressed_sig);
        }
    }
}

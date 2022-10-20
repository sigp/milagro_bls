extern crate amcl;
extern crate rand;
extern crate zeroize;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use self::zeroize::Zeroize;
use super::amcl_utils::{
    self, compress_g1, decompress_g1, g1mul, subgroup_check_g1, AmclError, Big, GroupG1,
    CURVE_ORDER, G1_BYTES, SECRET_KEY_BYTES,
};

use amcl::hash256::HASH256;
use rand::Rng;
#[cfg(feature = "std")]
use std::fmt;
use BLSCurve::bls381::utils::{
    deserialize_g1, secret_key_from_bytes, secret_key_to_bytes, serialize_uncompressed_g1,
};

// Key Generation Constants
/// Domain for key generation.
pub const KEY_SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
/// L = ceil((3 * ceil(log2(r))) / 16) = 48.
pub const L: u8 = 48;

/// A BLS secret key.
#[derive(Clone)]
pub struct SecretKey {
    x: Big,
}

impl SecretKey {
    /// Generate a new SecretKey using an Rng to seed the `amcl::rand::RAND` PRNG.
    pub fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let ikm: [u8; 32] = rng.gen();
        Self::key_generate(&ikm, &[]).unwrap() // will only error if ikm < 32 bytes
    }

    /// KeyGenerate
    ///
    /// Generate a new SecretKey based off Initial Keying Material (IKM) and key info.
    /// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.3
    pub fn key_generate(ikm: &[u8], key_info: &[u8]) -> Result<Self, AmclError> {
        if ikm.len() < 32 {
            return Err(AmclError::InvalidSecretKeySize);
        }

        let mut sk = Big::new();
        let mut salt = KEY_SALT.to_vec();

        while sk.is_zilch() {
            // salt = H(salt)
            let mut hash256 = HASH256::new();
            hash256.init();
            hash256.process_array(&salt);
            salt = hash256.hash().to_vec();

            // PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
            let mut prk = Vec::<u8>::with_capacity(1 + ikm.len());
            prk.extend_from_slice(ikm);
            prk.push(0);
            let prk = HASH256::hkdf_extract(&salt, &prk);

            // OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
            let mut info = key_info.to_vec();
            info.extend_from_slice(&[0, L]);
            let okm = HASH256::hkdf_extend(&prk, &info, L);

            // SK = OS2IP(OKM) mod r
            let r = Big::new_ints(&CURVE_ORDER);
            sk = Big::from_bytes(&okm);
            sk.rmod(&r);
        }
        Ok(Self { x: sk })
    }

    /// Instantiate a SecretKey from existing bytes.
    pub fn from_bytes(input: &[u8]) -> Result<SecretKey, AmclError> {
        Ok(Self { x: secret_key_from_bytes(input)? })
    }

    /// Export the SecretKey as 32 bytes.
    pub fn as_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        secret_key_to_bytes(&self.x)
    }

    pub fn as_raw(&self) -> &Big {
        &self.x
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.x.to_string())
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &SecretKey) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for SecretKey {}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.x.w.zeroize();
    }
}

/// A BLS public key.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct PublicKey {
    pub point: GroupG1,
}

impl PublicKey {
    /// Instantiate a PublicKey from some SecretKey.
    pub fn from_secret_key(sk: &SecretKey) -> Self {
        PublicKey {
            point: {
                #[cfg(feature = "std")]
                {
                    g1mul(&amcl_utils::GENERATORG1, sk.as_raw())
                }
                #[cfg(not(feature = "std"))]
                {
                    g1mul(&amcl_utils::GroupG1::generator(), sk.as_raw())
                }
            },
        }
    }

    /// Instantiate a PublicKey from compressed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, AmclError> {
        let public_key = Self::from_bytes_unchecked(bytes)?;
        if !public_key.key_validate() {
            return Err(AmclError::InvalidPoint);
        }

        Ok(public_key)
    }

    /// Instantiate a PublicKey from compressed bytes.
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Result<PublicKey, AmclError> {
        let point = decompress_g1(bytes)?;
        let public_key = Self { point };

        Ok(public_key)
    }

    /// Export the PublicKey to compressed bytes.
    pub fn as_bytes(&self) -> [u8; G1_BYTES] {
        compress_g1(&self.point)
    }

    /// Export the public key to uncompress (x, y) bytes
    pub fn as_uncompressed_bytes(&mut self) -> [u8; G1_BYTES * 2] {
        serialize_uncompressed_g1(&self.point)
    }

    /// InstantiatePublicKey from uncompress (x, y) bytes
    ///
    /// Does not validate the key, MUST only be used on verified keys.
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<PublicKey, AmclError> {
        if bytes.len() != G1_BYTES * 2 {
            return Err(AmclError::InvalidG1Size);
        }
        Ok(Self { point: deserialize_g1(bytes)? })
    }

    /// KeyValidate
    ///
    /// Verifies a public key is valid
    /// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.5
    pub fn key_validate(&self) -> bool {
        if self.point.is_infinity() || !subgroup_check_g1(&self.point) {
            return false;
        }
        true
    }
}

/// A helper which stores a BLS public and private key pair.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Keypair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

impl Keypair {
    /// Instantiate a Keypair using SecretKey::random().
    pub fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from_secret_key(&sk);
        Keypair { sk, pk }
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;
    extern crate rand;

    use super::super::signature::Signature;
    use super::*;

    #[test]
    fn test_secret_key_serialization_isomorphism() {
        let sk_bytes = vec![
            78, 252, 122, 126, 32, 0, 75, 89, 252, 31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194,
            233, 117, 181, 75, 96, 238, 79, 100, 237, 59, 140, 111,
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let decoded_sk = sk.as_bytes().to_vec();
        assert_eq!(decoded_sk, sk_bytes);
    }

    #[test]
    fn test_public_key_serialization_isomorphism() {
        for _ in 0..30 {
            let sk = SecretKey::random(&mut rand::thread_rng());
            let pk = PublicKey::from_secret_key(&sk);
            let decoded_pk = pk.as_bytes().to_vec();
            let encoded_pk = PublicKey::from_bytes(&decoded_pk).unwrap();
            let re_recoded_pk = encoded_pk.as_bytes().to_vec();
            assert_eq!(decoded_pk, re_recoded_pk);
        }
    }

    #[test]
    fn test_public_key_uncompressed_serialization_isomorphism() {
        for _ in 0..30 {
            let sk = SecretKey::random(&mut rand::thread_rng());
            let mut pk = PublicKey::from_secret_key(&sk);
            let decoded_pk = pk.as_uncompressed_bytes().to_vec();
            let mut encoded_pk = PublicKey::from_uncompressed_bytes(&decoded_pk).unwrap();
            let re_recoded_pk = encoded_pk.as_uncompressed_bytes().to_vec().to_vec();
            assert_eq!(decoded_pk, re_recoded_pk);
        }
    }

    #[test]
    fn test_public_key_uncompressed_serialization_infinity() {
        let mut pk_inf_bytes = vec![0u8; 48];
        pk_inf_bytes[0] = 192;
        let mut pk = PublicKey::from_bytes_unchecked(&pk_inf_bytes).unwrap();
        let decoded_pk = pk.as_uncompressed_bytes().to_vec();
        let recoded_pk = PublicKey::from_uncompressed_bytes(&decoded_pk).unwrap();
        assert_eq!(recoded_pk, pk);
        assert!(recoded_pk.point.is_infinity())
    }

    #[test]
    fn test_public_key_uncompressed_serialization_incorrect_size() {
        let bytes = vec![1; 1];
        assert_eq!(PublicKey::from_uncompressed_bytes(&bytes), Err(AmclError::InvalidG1Size));

        let bytes = vec![1; 95];
        assert_eq!(PublicKey::from_uncompressed_bytes(&bytes), Err(AmclError::InvalidG1Size));

        let bytes = vec![1; 97];
        assert_eq!(PublicKey::from_uncompressed_bytes(&bytes), Err(AmclError::InvalidG1Size));

        let bytes = vec![];
        assert_eq!(PublicKey::from_uncompressed_bytes(&bytes), Err(AmclError::InvalidG1Size));
    }

    #[test]
    fn test_public_key_uncompressed_serialization_bad_point() {
        // Point (1, 1) is not valid
        let mut bytes = vec![0; 96];
        bytes[47] = 1;
        bytes[95] = 1;
        assert_eq!(PublicKey::from_uncompressed_bytes(&bytes), Err(AmclError::InvalidPoint));
    }

    #[test]
    fn test_secret_key_from_bytes() {
        let bytes = vec![];
        assert_eq!(SecretKey::from_bytes(&bytes), Err(AmclError::InvalidSecretKeySize));

        let bytes = vec![1; 33];
        assert_eq!(SecretKey::from_bytes(&bytes), Err(AmclError::InvalidSecretKeySize));

        let bytes = vec![0; 32];
        assert_eq!(SecretKey::from_bytes(&bytes), Err(AmclError::InvalidSecretKeyRange));

        let bytes = vec![255; 32];
        assert_eq!(SecretKey::from_bytes(&bytes), Err(AmclError::InvalidSecretKeyRange));
    }

    #[test]
    fn test_secret_key_as_bytes() {
        let sk = SecretKey::random(&mut rand::thread_rng());
        assert!(sk.as_bytes().len() == 32);
    }

    #[test]
    fn test_signature_verify_with_serialized_public_key() {
        let sk_bytes = vec![
            78, 252, 122, 126, 32, 0, 75, 89, 252, 31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194,
            233, 117, 181, 75, 96, 238, 79, 100, 237, 59, 140, 111,
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&sk);

        let message = "cats".as_bytes();
        let signature = Signature::new(&message, &sk);
        assert!(signature.verify(&message, &pk));

        let pk_bytes = pk.as_bytes().to_vec();
        let pk = PublicKey::from_bytes(&pk_bytes).unwrap();
        assert!(signature.verify(&message, &pk));
    }

    #[test]
    fn test_random_secret_key_can_sign() {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let pk = PublicKey::from_secret_key(&sk);

        let message = "cats".as_bytes();
        let signature = Signature::new(&message, &sk);
        assert!(signature.verify(&message, &pk));
    }

    #[test]
    fn test_key_validate() {
        // Attempt to deserialise the point (0, 2) which is not in the group.
        let mut pk_bytes = vec![0; 48];
        pk_bytes[0] = 128;

        assert_eq!(PublicKey::from_bytes(&pk_bytes), Err(AmclError::InvalidPoint));
        assert!(PublicKey::from_bytes_unchecked(&pk_bytes).is_ok());
    }

    #[test]
    fn test_public_key_from_bytes_infinity() {
        // Infinity
        let mut pk_bytes = vec![0; 48];
        pk_bytes[0] = 196;

        assert_eq!(PublicKey::from_bytes(&pk_bytes), Err(AmclError::InvalidPoint));
    }

    #[test]
    fn test_readme() {
        // This is an exact replica of the README.md at the top level.
        // Generate a random key pair.
        let sk = SecretKey::random(&mut rand::thread_rng());
        let pk = PublicKey::from_secret_key(&sk);

        // Sign and verify a message.
        let message = "cats".as_bytes();
        let signature = Signature::new(&message, &sk);
        assert!(signature.verify(&message, &pk));
    }
}

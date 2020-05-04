extern crate amcl;
extern crate rand;
extern crate zeroize;

use self::zeroize::Zeroize;
use super::amcl_utils::{self, compress_g1, decompress_g1, Big, GroupG1, CURVE_ORDER, MODBYTES};
use super::errors::DecodeError;
use amcl::hash256::HASH256;
use rand::Rng;
#[cfg(feature = "std")]
use std::fmt;

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
        Self::key_generate(&ikm, &[])
    }

    /// KeyGenerate
    ///
    /// Generate a new SecretKey based off Initial Keying Material (IKM) and key info.
    /// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.3
    pub fn key_generate(ikm: &[u8], key_info: &[u8]) -> Self {
        // PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM || I2OSP(0, 1))
        let mut prk = Vec::<u8>::with_capacity(1 + ikm.len());
        prk.extend_from_slice(ikm);
        prk.push(0);
        let prk = HASH256::hkdf_extract(KEY_SALT, &prk);

        // OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
        let mut info = key_info.to_vec();
        info.extend_from_slice(&[0, L]);
        let okm = HASH256::hkdf_extend(&prk, &info, L);

        // SK = OS2IP(OKM) mod r
        let r = Big::new_ints(&CURVE_ORDER);
        let mut sk = Big::frombytes(&okm);
        sk.rmod(&r);
        Self { x: sk }
    }

    /// Instantiate a SecretKey from existing bytes.
    pub fn from_bytes(input: &[u8]) -> Result<SecretKey, DecodeError> {
        let mut bytes: Vec<u8>;
        // Require input <= 48 bytes, prepend zeros if necessary.
        if input.len() > MODBYTES {
            return Err(DecodeError::IncorrectSize);
        } else if input.len() < MODBYTES {
            bytes = vec![0u8; MODBYTES - input.len()];
            bytes.extend_from_slice(input);
        } else {
            bytes = input.to_vec();
        }

        // Ensure secret key is in the range [0, r-1].
        let sk = Big::frombytes(&bytes);
        if sk >= Big::new_ints(&CURVE_ORDER) {
            return Err(DecodeError::InvalidSecretKeyRange);
        }

        Ok(SecretKey { x: sk })
    }

    /// Export the SecretKey to bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        let temp = self.x.clone();
        let mut bytes: [u8; MODBYTES] = [0; MODBYTES];
        temp.tobytes(&mut bytes);
        bytes.to_vec()
    }

    pub fn as_raw(&self) -> &Big {
        &self.x
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.x.tostring())
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
                    amcl_utils::GENERATORG1.mul(sk.as_raw())
                }
                #[cfg(not(feature = "std"))]
                {
                    amcl_utils::GroupG1::generator().mul(sk.as_raw())
                }
            },
        }
    }

    /// Instantiate a PublicKey from some GroupG1 point.
    pub fn new_from_raw(pt: &GroupG1) -> Self {
        PublicKey { point: pt.clone() }
    }

    /// Instantiate a PublicKey from compressed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, DecodeError> {
        let point = decompress_g1(&bytes)?;
        Ok(Self { point })
    }

    /// Export the PublicKey to compressed bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        compress_g1(&self.point)
    }

    /// Export the public key to uncompress (x, y) bytes
    pub fn as_uncompressed_bytes(&mut self) -> Vec<u8> {
        if self.point.is_infinity() {
            return vec![0; 96];
        }

        let mut result: Vec<u8> = vec![];
        let mut bytes = [0 as u8; 48];
        self.point.getx().tobytes(&mut bytes);
        result.extend_from_slice(&bytes);
        self.point.gety().tobytes(&mut bytes);
        result.extend_from_slice(&bytes);
        result
    }

    /// InstantiatePublicKey from uncompress (x, y) bytes
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<PublicKey, DecodeError> {
        if bytes.len() != 96 {
            return Err(DecodeError::IncorrectSize);
        }

        let mut nil = true;
        for byte in bytes {
            if *byte != 0 {
                nil = false;
                break;
            }
        }
        if nil {
            // Point is infinity
            return Ok(PublicKey::new_from_raw(&GroupG1::new()));
        }

        let x_big = Big::frombytes(&bytes[0..48]);
        let y_big = Big::frombytes(&bytes[48..]);
        let point = GroupG1::new_bigs(&x_big, &y_big);

        if point.is_infinity() {
            return Err(DecodeError::BadPoint);
        }

        Ok(PublicKey::new_from_raw(&point))
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 252, 122, 126, 32, 0, 75, 89, 252,
            31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194, 233, 117, 181, 75, 96, 238, 79, 100,
            237, 59, 140, 111,
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let decoded_sk = sk.as_bytes();
        assert_eq!(decoded_sk, sk_bytes);
    }

    #[test]
    fn test_public_key_serialization_isomorphism() {
        for _ in 0..30 {
            let sk = SecretKey::random(&mut rand::thread_rng());
            let pk = PublicKey::from_secret_key(&sk);
            let decoded_pk = pk.as_bytes();
            let encoded_pk = PublicKey::from_bytes(&decoded_pk).unwrap();
            let re_recoded_pk = encoded_pk.as_bytes();
            assert_eq!(decoded_pk, re_recoded_pk);
        }
    }

    #[test]
    fn test_public_key_uncompressed_serialization_isomorphism() {
        for _ in 0..30 {
            let sk = SecretKey::random(&mut rand::thread_rng());
            let mut pk = PublicKey::from_secret_key(&sk);
            let decoded_pk = pk.as_uncompressed_bytes();
            let mut encoded_pk = PublicKey::from_uncompressed_bytes(&decoded_pk).unwrap();
            let re_recoded_pk = encoded_pk.as_uncompressed_bytes();
            assert_eq!(decoded_pk, re_recoded_pk);
        }
    }

    #[test]
    fn test_public_key_uncompressed_serialization_infinity() {
        let mut pk = PublicKey::new_from_raw(&GroupG1::new());
        let decoded_pk = pk.as_uncompressed_bytes();
        let recoded_pk = PublicKey::from_uncompressed_bytes(&decoded_pk).unwrap();
        assert_eq!(recoded_pk, pk);
        assert!(recoded_pk.point.is_infinity())
    }

    #[test]
    fn test_public_key_uncompressed_serialization_incorrect_size() {
        let bytes = vec![1; 1];
        assert_eq!(
            PublicKey::from_uncompressed_bytes(&bytes),
            Err(DecodeError::IncorrectSize)
        );

        let bytes = vec![1; 95];
        assert_eq!(
            PublicKey::from_uncompressed_bytes(&bytes),
            Err(DecodeError::IncorrectSize)
        );

        let bytes = vec![1; 97];
        assert_eq!(
            PublicKey::from_uncompressed_bytes(&bytes),
            Err(DecodeError::IncorrectSize)
        );

        let bytes = vec![];
        assert_eq!(
            PublicKey::from_uncompressed_bytes(&bytes),
            Err(DecodeError::IncorrectSize)
        );
    }

    #[test]
    fn test_public_key_uncompressed_serialization_bad_point() {
        // Point (1, 1) is not valid
        let mut bytes = vec![0; 96];
        bytes[47] = 1;
        bytes[95] = 1;
        assert_eq!(
            PublicKey::from_uncompressed_bytes(&bytes),
            Err(DecodeError::BadPoint)
        );
    }

    #[test]
    fn test_secret_key_from_bytes() {
        let bytes = vec![1; 1];
        assert!(SecretKey::from_bytes(&bytes).is_ok());

        let bytes = vec![1; 49];
        assert_eq!(
            SecretKey::from_bytes(&bytes),
            Err(DecodeError::IncorrectSize)
        );

        let bytes = vec![0; 48];
        assert!(SecretKey::from_bytes(&bytes).is_ok());

        let bytes = vec![255; 48];
        assert_eq!(
            SecretKey::from_bytes(&bytes),
            Err(DecodeError::InvalidSecretKeyRange)
        );
    }

    #[test]
    fn test_signature_verify_with_serialized_public_key() {
        let sk_bytes = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 252, 122, 126, 32, 0, 75, 89, 252,
            31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194, 233, 117, 181, 75, 96, 238, 79, 100,
            237, 59, 140, 111,
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&sk);

        let message = "cats".as_bytes();
        let signature = Signature::new(&message, &sk);
        assert!(signature.verify(&message, &pk));

        let pk_bytes = pk.as_bytes();
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
}

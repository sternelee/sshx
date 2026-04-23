//! Encryption of byte streams based on a random key.

use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit as _};
use rand::Rng;

type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;

// Note: The KDF salt is public, as it needs to be used from the web client. It
// only exists to make rainbow table attacks less likely.
const SALT: &str =
    "This is a non-random salt for sshx.io, since we want to stretch the security of 83-bit keys!";

const V1_HASH_LEN: usize = 16;
const V2_HASH_LEN: usize = 32;

/// Nonce size for AES-256-GCM.
const GCM_NONCE_SIZE: usize = 12;
/// Tag size for AES-256-GCM.
const GCM_TAG_SIZE: usize = 16;
/// Total zeros length for v2: nonce + ciphertext + tag.
const V2_ZEROS_LEN: usize = GCM_NONCE_SIZE + V1_HASH_LEN + GCM_TAG_SIZE;

/// Encryption version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptVersion {
    /// AES-128-CTR (legacy).
    V1,
    /// AES-256-GCM with integrity.
    V2,
}

/// Encrypts byte streams using the Argon2 hash of a random key.
#[derive(Clone)]
pub struct Encrypt {
    version: EncryptVersion,
    v1_key: Option<[u8; V1_HASH_LEN]>,
    v2_key: Option<[u8; V2_HASH_LEN]>,
}

impl Encrypt {
    /// Construct a new encryptor using the latest version (v2).
    pub fn new(key: &str) -> Self {
        Self::new_v2(key)
    }

    /// Construct a v1 encryptor for backward compatibility.
    pub fn new_v1(key: &str) -> Self {
        use argon2::{Algorithm, Argon2, Params, Version};
        // These parameters must match the browser implementation.
        let hasher = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(19 * 1024, 2, 1, Some(V1_HASH_LEN)).unwrap(),
        );
        let mut aes_key = [0; V1_HASH_LEN];
        hasher
            .hash_password_into(key.as_bytes(), SALT.as_bytes(), &mut aes_key)
            .expect("failed to hash key with argon2");
        Self {
            version: EncryptVersion::V1,
            v1_key: Some(aes_key),
            v2_key: None,
        }
    }

    /// Construct a v2 encryptor.
    fn new_v2(key: &str) -> Self {
        use argon2::{Algorithm, Argon2, Params, Version};
        let hasher = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(19 * 1024, 2, 1, Some(V2_HASH_LEN)).unwrap(),
        );
        let mut aes_key = [0; V2_HASH_LEN];
        hasher
            .hash_password_into(key.as_bytes(), SALT.as_bytes(), &mut aes_key)
            .expect("failed to hash key with argon2");
        Self {
            version: EncryptVersion::V2,
            v1_key: None,
            v2_key: Some(aes_key),
        }
    }

    /// Detect version from encrypted zeros length.
    pub fn version_from_zeros(zeros: &[u8]) -> Option<EncryptVersion> {
        match zeros.len() {
            V1_HASH_LEN => Some(EncryptVersion::V1),
            V2_ZEROS_LEN => Some(EncryptVersion::V2),
            _ => None,
        }
    }

    /// Get the encryption version.
    pub fn version(&self) -> EncryptVersion {
        self.version
    }

    /// Get the encrypted zero block.
    pub fn zeros(&self) -> Vec<u8> {
        match self.version {
            EncryptVersion::V1 => {
                let key = self.v1_key.unwrap();
                let mut zeros = [0; V1_HASH_LEN];
                let mut cipher = Aes128Ctr64BE::new(&key.into(), &zeros.into());
                cipher.apply_keystream(&mut zeros);
                zeros.to_vec()
            }
            EncryptVersion::V2 => {
                let key: Key<Aes256Gcm> = self.v2_key.unwrap().into();
                let cipher = Aes256Gcm::new(&key);
                let nonce = [0u8; GCM_NONCE_SIZE]; // deterministic zero nonce for zeros
                let payload = Payload {
                    msg: &[0u8; V1_HASH_LEN],
                    aad: &[],
                };
                let ciphertext = cipher
                    .encrypt((&nonce).into(), payload)
                    .expect("GCM encryption of zeros should not fail");
                // Prepend nonce: 12 + 16 + 16 = 44 bytes
                let mut result = Vec::with_capacity(GCM_NONCE_SIZE + ciphertext.len());
                result.extend_from_slice(&nonce);
                result.extend_from_slice(&ciphertext);
                result
            }
        }
    }

    /// Encrypt a segment of data from a stream.
    pub fn encrypt(&self, stream_num: u64, offset: u64, data: &[u8]) -> Vec<u8> {
        assert_ne!(stream_num, 0, "stream number must be nonzero"); // security check

        match self.version {
            EncryptVersion::V1 => {
                let key = self.v1_key.unwrap();
                let mut iv = [0; 16];
                iv[0..8].copy_from_slice(&stream_num.to_be_bytes());

                let mut cipher = Aes128Ctr64BE::new(&key.into(), &iv.into());
                cipher.seek(offset);
                let mut buf = data.to_vec();
                cipher.apply_keystream(&mut buf);
                buf
            }
            EncryptVersion::V2 => {
                let key = self.v2_key.unwrap();
                let key: Key<Aes256Gcm> = key.into();
                let cipher = Aes256Gcm::new(&key);
                let mut nonce = [0u8; GCM_NONCE_SIZE];
                rand::rng().fill_bytes(&mut nonce);
                let aad = aad(stream_num, offset);
                let payload = Payload {
                    msg: data,
                    aad: &aad,
                };
                let ciphertext = cipher
                    .encrypt((&nonce).into(), payload)
                    .expect("GCM encryption should not fail");
                // Prepend nonce
                let mut result = Vec::with_capacity(GCM_NONCE_SIZE + ciphertext.len());
                result.extend_from_slice(&nonce);
                result.extend_from_slice(&ciphertext);
                result
            }
        }
    }

    /// Decrypt a segment of data from a stream.
    pub fn decrypt(&self, stream_num: u64, offset: u64, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        assert_ne!(stream_num, 0, "stream number must be nonzero"); // security check

        match self.version {
            EncryptVersion::V1 => {
                // CTR mode is self-inverse.
                Ok(self.encrypt(stream_num, offset, data))
            }
            EncryptVersion::V2 => {
                if data.len() < GCM_NONCE_SIZE + GCM_TAG_SIZE {
                    anyhow::bail!("ciphertext too short");
                }
                let nonce = &data[..GCM_NONCE_SIZE];
                let ciphertext = &data[GCM_NONCE_SIZE..];
                let key: Key<Aes256Gcm> = self.v2_key.unwrap().into();
                let cipher = Aes256Gcm::new(&key);
                let aad = aad(stream_num, offset);
                let payload = Payload {
                    msg: ciphertext,
                    aad: &aad,
                };
                cipher
                    .decrypt(nonce.try_into().unwrap(), payload)
                    .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))
            }
        }
    }
}

/// Build AAD from stream number and offset.
fn aad(stream_num: u64, offset: u64) -> [u8; 16] {
    let mut result = [0u8; 16];
    result[0..8].copy_from_slice(&stream_num.to_be_bytes());
    result[8..16].copy_from_slice(&offset.to_be_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::{Encrypt, EncryptVersion};

    #[test]
    fn make_encrypt_v1() {
        let encrypt = Encrypt::new_v1("test");
        assert_eq!(encrypt.version(), EncryptVersion::V1);
        assert_eq!(
            encrypt.zeros(),
            [198, 3, 249, 238, 65, 10, 224, 98, 253, 73, 148, 1, 138, 3, 108, 143],
        );
    }

    #[test]
    fn make_encrypt_v2() {
        let encrypt = Encrypt::new_v2("test");
        assert_eq!(encrypt.version(), EncryptVersion::V2);
        assert_eq!(encrypt.zeros().len(), 44);
        // Zeros should be deterministic for the same key.
        assert_eq!(encrypt.zeros(), encrypt.zeros());
    }

    #[test]
    fn roundtrip_v1() {
        let encrypt = Encrypt::new_v1("this is a test key");
        let data = b"hello world";
        let encrypted = encrypt.encrypt(1, 0, data);
        assert_eq!(encrypted.len(), data.len());
        let decrypted = encrypt.decrypt(1, 0, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn roundtrip_v2() {
        let encrypt = Encrypt::new_v2("this is a test key");
        let data = b"hello world";
        let encrypted = encrypt.encrypt(1, 0, data);
        assert!(encrypted.len() > data.len()); // nonce + tag overhead
        let decrypted = encrypt.decrypt(1, 0, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn v2_aad_integrity() {
        let encrypt = Encrypt::new_v2("this is a test key");
        let data = b"hello world";
        let encrypted = encrypt.encrypt(1, 0, data);

        // Decrypting with wrong stream_num should fail.
        assert!(encrypt.decrypt(2, 0, &encrypted).is_err());
        // Decrypting with wrong offset should fail.
        assert!(encrypt.decrypt(1, 1, &encrypted).is_err());
    }

    #[test]
    fn v2_different_nonces() {
        let encrypt = Encrypt::new_v2("this is a test key");
        let data = b"hello world";
        let encrypted1 = encrypt.encrypt(1, 0, data);
        let encrypted2 = encrypt.encrypt(1, 0, data);
        // Same plaintext should produce different ciphertexts due to random nonces.
        assert_ne!(encrypted1, encrypted2);
        // But both should decrypt correctly.
        assert_eq!(encrypt.decrypt(1, 0, &encrypted1).unwrap(), data);
        assert_eq!(encrypt.decrypt(1, 0, &encrypted2).unwrap(), data);
    }

    #[test]
    fn matches_offset_v1() {
        let encrypt = Encrypt::new_v1("this is a test key");
        let data = b"1st block.(16B)|2nd block......|3rd block";
        let encrypted = encrypt.encrypt(1, 0, data);
        assert_eq!(encrypted.len(), data.len());
        for i in 1..data.len() {
            let encrypted_suffix = encrypt.encrypt(1, i as u64, &data[i..]);
            assert_eq!(encrypted_suffix, &encrypted[i..]);
        }
    }

    #[test]
    #[should_panic]
    fn zero_stream_num_encrypt() {
        let encrypt = Encrypt::new_v2("this is a test key");
        encrypt.encrypt(0, 0, b"hello world");
    }

    #[test]
    #[should_panic]
    fn zero_stream_num_decrypt() {
        let encrypt = Encrypt::new_v2("this is a test key");
        let _ = encrypt.decrypt(0, 0, b"hello world");
    }

    #[test]
    fn version_detection() {
        let v1 = Encrypt::new_v1("test");
        let v2 = Encrypt::new_v2("test");
        assert_eq!(
            Encrypt::version_from_zeros(&v1.zeros()),
            Some(EncryptVersion::V1)
        );
        assert_eq!(
            Encrypt::version_from_zeros(&v2.zeros()),
            Some(EncryptVersion::V2)
        );
        assert_eq!(Encrypt::version_from_zeros(&[0u8; 20]), None);
    }
}

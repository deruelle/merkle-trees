use super::Hasher;
use sha2::{Digest, Sha256};

/// SHA-256 hasher using the `sha2` crate from RustCrypto.
///
/// Produces a 32-byte array (256 bits).
#[derive(Clone)]
pub struct Sha256Hasher;

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Hasher {
    pub fn new() -> Self {
        Sha256Hasher
    }
}

impl Hasher for Sha256Hasher {
    fn hash_bytes(&self, data: &[u8]) -> [u8; 32] {
        let result = Sha256::digest(data);
        result.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hasher_length() {
        let hasher = Sha256Hasher::new();
        let hash = hasher.hash_bytes(b"hello");
        assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes (256 bits)
    }

    #[test]
    fn test_different_inputs_different_hashes() {
        let hasher = Sha256Hasher;
        let hash1 = hasher.hash_bytes(b"hello");
        let hash2 = hasher.hash_bytes(b"world");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_same_input_same_hash() {
        let hasher = Sha256Hasher::new();
        let hash1 = hasher.hash_bytes(b"test");
        let hash2 = hasher.hash_bytes(b"test");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_known_hash() {
        let hasher = Sha256Hasher::new();
        // "hello" SHA-256 hash (from any online SHA-256 calculator)
        let hash = hasher.hash_bytes(b"hello");
        let expected: [u8; 32] = [
            0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9,
            0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62,
            0x93, 0x8b, 0x98, 0x24,
        ];
        assert_eq!(hash, expected);
    }
}

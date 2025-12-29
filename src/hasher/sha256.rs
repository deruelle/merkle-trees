use super::Hasher;
use sha2::{Digest, Sha256};

/// SHA-256 hasher using the `sha2` crate from RustCrypto.
///
/// Produces a 64-character hexadecimal string (256 bits = 32 bytes = 64 hex chars).
pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    fn hash_bytes(data: &[u8]) -> String {
        let result = Sha256::digest(data);
        format!("{:x}", result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hasher_length() {
        let hash = Sha256Hasher::hash_bytes(b"hello");
        assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex chars
    }

    #[test]
    fn test_different_inputs_different_hashes() {
        let hash1 = Sha256Hasher::hash_bytes(b"hello");
        let hash2 = Sha256Hasher::hash_bytes(b"world");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_same_input_same_hash() {
        let hash1 = Sha256Hasher::hash_bytes(b"test");
        let hash2 = Sha256Hasher::hash_bytes(b"test");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_known_hash() {
        // "hello" SHA-256 hash (from any online SHA-256 calculator)
        let hash = Sha256Hasher::hash_bytes(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}

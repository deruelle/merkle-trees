use super::Hasher;

/// A simple placeholder hasher for testing (NOT cryptographically secure!)
///
/// This hasher uses a simple sum-based algorithm and is only intended
/// for testing and demonstration purposes.
#[derive(Clone)]
pub struct SimpleHasher;

impl Default for SimpleHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleHasher {
    pub fn new() -> Self {
        SimpleHasher
    }
}

impl Hasher for SimpleHasher {
    fn hash_bytes(&self, data: &[u8]) -> [u8; 32] {
        // Simple sum-based "hash" - just for demonstration
        let sum: u32 = data.iter().map(|&b| b as u32).sum();
        let mut hash = [0u8; 32];
        // Store the sum in the first 4 bytes (big-endian)
        hash[0..4].copy_from_slice(&sum.to_be_bytes());
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_hasher() {
        let hasher = SimpleHasher::new();
        let hash = hasher.hash_bytes(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_different_inputs_different_hashes() {
        let hasher = SimpleHasher::new();
        let hash1 = hasher.hash_bytes(b"hello");
        let hash2 = hasher.hash_bytes(b"world");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_same_input_same_hash() {
        let hasher = SimpleHasher;
        let hash1 = hasher.hash_bytes(b"test");
        let hash2 = hasher.hash_bytes(b"test");
        assert_eq!(hash1, hash2);
    }
}

use super::Hasher;

/// A simple placeholder hasher for testing (NOT cryptographically secure!)
///
/// This hasher uses a simple sum-based algorithm and is only intended
/// for testing and demonstration purposes.
#[derive(Clone)]
pub struct SimpleHasher;

impl SimpleHasher {
    pub fn new() -> Self {
        SimpleHasher
    }
}

impl Default for SimpleHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for SimpleHasher {
    fn hash_bytes(&self, data: &[u8]) -> String {
        // Simple sum-based "hash" - just for demonstration
        let sum: u32 = data.iter().map(|&b| b as u32).sum();
        format!("{:08x}", sum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_hasher() {
        let hasher = SimpleHasher::new();
        let hash = hasher.hash_bytes(b"hello");
        assert!(!hash.is_empty());
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
        let hasher = SimpleHasher::new();
        let hash1 = hasher.hash_bytes(b"test");
        let hash2 = hasher.hash_bytes(b"test");
        assert_eq!(hash1, hash2);
    }
}

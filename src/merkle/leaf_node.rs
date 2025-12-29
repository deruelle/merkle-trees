use crate::hasher::Hasher;
use crate::merkle::hash::Hash;

/// A leaf node containing raw data.
///
/// Leaves are the foundation of the Merkle tree, containing the actual
/// data that gets hashed. They use a 0x00 domain separator to distinguish
/// their hashes from internal nodes.
#[derive(Clone)]
pub struct LeafNode {
    data: Vec<u8>,
    hash_value: String,
}

impl LeafNode {
    /// Create a new leaf from raw data using the provided hasher.
    pub fn new<H: Hasher>(data: Vec<u8>, hasher: &H) -> Self {
        let hash_value = Self::compute_hash(&data, hasher);
        LeafNode { data, hash_value }
    }

    /// Get the data stored in this leaf.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Compute the hash for this leaf (0x00 domain separator).
    fn compute_hash<H: Hasher>(data: &[u8], hasher: &H) -> String {
        let mut to_hash = vec![0x00];
        to_hash.extend_from_slice(data);
        hasher.hash_bytes(&to_hash)
    }
}

impl Hash for LeafNode {
    fn hash(&self) -> String {
        self.hash_value.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::SimpleHasher;

    #[test]
    fn test_leaf_creation() {
        let hasher = SimpleHasher::new();
        let leaf = LeafNode::new(b"hello".to_vec(), &hasher);
        assert_eq!(leaf.data(), b"hello");
    }

    #[test]
    fn test_leaf_hashes_itself() {
        let hasher = SimpleHasher::new();
        let leaf = LeafNode::new(b"hello".to_vec(), &hasher);
        assert!(!leaf.hash().is_empty());
    }

    #[test]
    fn test_same_data_same_hash() {
        let hasher = SimpleHasher::new();
        let leaf1 = LeafNode::new(b"test".to_vec(), &hasher);
        let leaf2 = LeafNode::new(b"test".to_vec(), &hasher);
        assert_eq!(leaf1.hash(), leaf2.hash());
    }

    #[test]
    fn test_different_data_different_hash() {
        let hasher = SimpleHasher::new();
        let leaf1 = LeafNode::new(b"hello".to_vec(), &hasher);
        let leaf2 = LeafNode::new(b"world".to_vec(), &hasher);
        assert_ne!(leaf1.hash(), leaf2.hash());
    }
}

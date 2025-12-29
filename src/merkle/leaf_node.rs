use crate::hasher::Hasher;
use crate::merkle::hash::Hash;
use std::marker::PhantomData;

/// A leaf node containing raw data.
///
/// Leaves are the foundation of the Merkle tree, containing the actual
/// data that gets hashed. They use a 0x00 domain separator to distinguish
/// their hashes from internal nodes.
pub struct LeafNode<H: Hasher> {
    data: Vec<u8>,
    hash_value: String,
    _hasher: PhantomData<H>,
}

impl<H: Hasher> LeafNode<H> {
    /// Create a new leaf from raw data.
    pub fn new(data: Vec<u8>) -> Self {
        let mut leaf = LeafNode {
            data,
            hash_value: String::new(),
            _hasher: PhantomData,
        };
        leaf.hash_value = leaf.compute_hash();
        leaf
    }

    /// Get the data stored in this leaf.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Compute the hash for this leaf (0x00 domain separator).
    fn compute_hash(&self) -> String {
        let mut to_hash = vec![0x00];
        to_hash.extend_from_slice(&self.data);
        H::hash_bytes(&to_hash)
    }
}

impl<H: Hasher> Hash for LeafNode<H> {
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
        let leaf: LeafNode<SimpleHasher> = LeafNode::new(b"hello".to_vec());
        assert_eq!(leaf.data(), b"hello");
    }

    #[test]
    fn test_leaf_hashes_itself() {
        let leaf: LeafNode<SimpleHasher> = LeafNode::new(b"hello".to_vec());
        assert!(!leaf.hash().is_empty());
    }

    #[test]
    fn test_same_data_same_hash() {
        let leaf1: LeafNode<SimpleHasher> = LeafNode::new(b"test".to_vec());
        let leaf2: LeafNode<SimpleHasher> = LeafNode::new(b"test".to_vec());
        assert_eq!(leaf1.hash(), leaf2.hash());
    }

    #[test]
    fn test_different_data_different_hash() {
        let leaf1: LeafNode<SimpleHasher> = LeafNode::new(b"hello".to_vec());
        let leaf2: LeafNode<SimpleHasher> = LeafNode::new(b"world".to_vec());
        assert_ne!(leaf1.hash(), leaf2.hash());
    }
}

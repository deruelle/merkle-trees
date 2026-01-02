use std::sync::Arc;

use crate::hasher::Hasher;
use crate::merkle::hash::Hash;
use crate::merkle::node::Node;

/// An internal node with left and right children.
///
/// InternalNode nodes form the structure of the Merkle tree, combining
/// the hashes of their children. They use a 0x01 domain separator
/// to distinguish their hashes from leaf nodes.
#[derive(Clone)]
pub struct InternalNode {
    left: Arc<Node>,
    right: Arc<Node>,
    hash_value: [u8; 32],
}

impl InternalNode {
    /// Create a new internal node from two children using the provided hasher.
    pub fn new<H: Hasher>(left: Arc<Node>, right: Arc<Node>, hasher: &H) -> Self {
        let hash_value = Self::compute_hash(&left, &right, hasher);
        InternalNode {
            left,
            right,
            hash_value,
        }
    }

    /// Get the left child.
    pub fn left(&self) -> &Node {
        &self.left
    }

    /// Get the right child.
    pub fn right(&self) -> &Node {
        &self.right
    }

    /// Compute the hash for this internal node (0x01 domain separator).
    fn compute_hash<H: Hasher>(left: &Node, right: &Node, hasher: &H) -> [u8; 32] {
        let mut to_hash = Vec::with_capacity(65); // 1 + 32 + 32
        to_hash.push(0x01);
        to_hash.extend_from_slice(left.hash());
        to_hash.extend_from_slice(right.hash());
        hasher.hash_bytes(&to_hash)
    }
}

impl Hash for InternalNode {
    fn hash(&self) -> &[u8] {
        &self.hash_value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{Sha256Hasher, SimpleHasher};

    #[test]
    fn test_internal_creation() {
        let hasher = SimpleHasher::new();
        let left = Arc::new(Node::leaf(b"left".to_vec(), &hasher));
        let right = Arc::new(Node::leaf(b"right".to_vec(), &hasher));
        let internal = InternalNode::new(left, right, &hasher);
        assert!(!internal.hash().is_empty());
    }

    #[test]
    fn test_internal_children_accessible() {
        let hasher = SimpleHasher::new();
        let left = Arc::new(Node::leaf(b"left".to_vec(), &hasher));
        let right = Arc::new(Node::leaf(b"right".to_vec(), &hasher));
        let left_hash = Arc::clone(&left).hash().to_vec();
        let right_hash = Arc::clone(&right).hash().to_vec();

        let internal = InternalNode::new(left, right, &hasher);
        assert_eq!(internal.left().hash(), left_hash.as_slice());
        assert_eq!(internal.right().hash(), right_hash.as_slice());
    }

    #[test]
    fn test_order_matters() {
        let hasher = Sha256Hasher::new();
        let a = Arc::new(Node::leaf(b"a".to_vec(), &hasher));
        let b = Arc::new(Node::leaf(b"b".to_vec(), &hasher));
        let internal1 = InternalNode::new(a, b, &hasher);

        let a = Arc::new(Node::leaf(b"a".to_vec(), &hasher));
        let b = Arc::new(Node::leaf(b"b".to_vec(), &hasher));
        let internal2 = InternalNode::new(b, a, &hasher);

        // Swapping left/right should produce different hash
        assert_ne!(internal1.hash(), internal2.hash());
    }
}

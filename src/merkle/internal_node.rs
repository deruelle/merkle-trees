use crate::hasher::Hasher;
use crate::merkle::hash::Hash;
use crate::merkle::node::Node;

/// An internal node with left and right children.
///
/// InternalNode nodes form the structure of the Merkle tree, combining
/// the hashes of their children. They use a 0x01 domain separator
/// to distinguish their hashes from leaf nodes.
pub struct InternalNode<H: Hasher> {
    left: Box<Node<H>>,
    right: Box<Node<H>>,
    hash_value: String,
}

impl<H: Hasher> InternalNode<H> {
    /// Create a new internal node from two children.
    pub fn new(left: Node<H>, right: Node<H>) -> Self {
        let mut internal = InternalNode {
            left: Box::new(left),
            right: Box::new(right),
            hash_value: String::new(),
        };
        internal.hash_value = internal.compute_hash();
        internal
    }

    /// Get the left child.
    pub fn left(&self) -> &Node<H> {
        &self.left
    }

    /// Get the right child.
    pub fn right(&self) -> &Node<H> {
        &self.right
    }

    /// Compute the hash for this internal node (0x01 domain separator).
    fn compute_hash(&self) -> String {
        let mut to_hash = vec![0x01];
        to_hash.extend_from_slice(self.left.hash().as_bytes());
        to_hash.extend_from_slice(self.right.hash().as_bytes());
        H::hash_bytes(&to_hash)
    }
}

impl<H: Hasher> Hash for InternalNode<H> {
    fn hash(&self) -> String {
        self.hash_value.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Sha256Hasher, hasher::SimpleHasher};

    #[test]
    fn test_internal_creation() {
        let left = Node::<SimpleHasher>::leaf(b"left".to_vec());
        let right = Node::<SimpleHasher>::leaf(b"right".to_vec());
        let internal = InternalNode::new(left, right);
        assert!(!internal.hash().is_empty());
    }

    #[test]
    fn test_internal_children_accessible() {
        let left = Node::<SimpleHasher>::leaf(b"left".to_vec());
        let right = Node::<SimpleHasher>::leaf(b"right".to_vec());
        let left_hash = left.hash();
        let right_hash = right.hash();

        let internal = InternalNode::new(left, right);
        assert_eq!(internal.left().hash(), left_hash);
        assert_eq!(internal.right().hash(), right_hash);
    }

    #[test]
    fn test_order_matters() {
        let a = Node::<Sha256Hasher>::leaf(b"a".to_vec());
        let b = Node::<Sha256Hasher>::leaf(b"b".to_vec());
        let internal1 = InternalNode::new(a, b);

        let a = Node::<Sha256Hasher>::leaf(b"a".to_vec());
        let b = Node::<Sha256Hasher>::leaf(b"b".to_vec());
        let internal2 = InternalNode::new(b, a);

        // Swapping left/right should produce different hash
        assert_ne!(internal1.hash(), internal2.hash());
    }
}

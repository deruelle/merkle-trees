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
    left: Box<Node>,
    right: Box<Node>,
    hash_value: String,
}

impl InternalNode {
    /// Create a new internal node from two children using the provided hasher.
    pub fn new<H: Hasher>(left: Node, right: Node, hasher: &H) -> Self {
        let hash_value = Self::compute_hash(&left, &right, hasher);
        InternalNode {
            left: Box::new(left),
            right: Box::new(right),
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
    fn compute_hash<H: Hasher>(left: &Node, right: &Node, hasher: &H) -> String {
        let mut to_hash = vec![0x01];
        to_hash.extend_from_slice(left.hash().as_bytes());
        to_hash.extend_from_slice(right.hash().as_bytes());
        hasher.hash_bytes(&to_hash)
    }
}

impl Hash for InternalNode {
    fn hash(&self) -> String {
        self.hash_value.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{Sha256Hasher, SimpleHasher};

    #[test]
    fn test_internal_creation() {
        let hasher = SimpleHasher::new();
        let left = Node::leaf(b"left".to_vec(), &hasher);
        let right = Node::leaf(b"right".to_vec(), &hasher);
        let internal = InternalNode::new(left, right, &hasher);
        assert!(!internal.hash().is_empty());
    }

    #[test]
    fn test_internal_children_accessible() {
        let hasher = SimpleHasher::new();
        let left = Node::leaf(b"left".to_vec(), &hasher);
        let right = Node::leaf(b"right".to_vec(), &hasher);
        let left_hash = left.hash();
        let right_hash = right.hash();

        let internal = InternalNode::new(left, right, &hasher);
        assert_eq!(internal.left().hash(), left_hash);
        assert_eq!(internal.right().hash(), right_hash);
    }

    #[test]
    fn test_order_matters() {
        let hasher = Sha256Hasher::new();
        let a = Node::leaf(b"a".to_vec(), &hasher);
        let b = Node::leaf(b"b".to_vec(), &hasher);
        let internal1 = InternalNode::new(a, b, &hasher);

        let a = Node::leaf(b"a".to_vec(), &hasher);
        let b = Node::leaf(b"b".to_vec(), &hasher);
        let internal2 = InternalNode::new(b, a, &hasher);

        // Swapping left/right should produce different hash
        assert_ne!(internal1.hash(), internal2.hash());
    }
}

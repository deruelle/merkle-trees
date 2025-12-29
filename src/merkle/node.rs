use crate::hasher::Hasher;
use crate::merkle::hash::Hash;
use crate::merkle::internal_node::InternalNode;
use crate::merkle::leaf_node::LeafNode;

/// A node in the Merkle tree - either a Leaf or an Internal node.
///
/// This enum provides a unified interface while each inner type
/// handles its own hashing logic.
pub enum Node<H: Hasher> {
    Leaf(LeafNode<H>),
    Internal(InternalNode<H>),
}

impl<H: Hasher> Node<H> {
    /// Create a leaf node (convenience method).
    pub fn leaf(data: Vec<u8>) -> Self {
        Node::Leaf(LeafNode::new(data))
    }

    /// Create an internal node (convenience method).
    pub fn internal(left: Node<H>, right: Node<H>) -> Self {
        Node::Internal(InternalNode::new(left, right))
    }

    /// Check if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        matches!(self, Node::Leaf(_))
    }

    /// Get the data if this is a leaf.
    pub fn get_data(&self) -> Option<&[u8]> {
        match self {
            Node::Leaf(leaf) => Some(leaf.data()),
            Node::Internal(_) => None,
        }
    }
}

/// Node delegates to the inner type's Hash implementation.
impl<H: Hasher> Hash for Node<H> {
    fn hash(&self) -> String {
        match self {
            Node::Leaf(leaf) => leaf.hash(),
            Node::Internal(internal) => internal.hash(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{Sha256Hasher, SimpleHasher};

    #[test]
    fn test_node_leaf() {
        let node = Node::<SimpleHasher>::leaf(b"test".to_vec());
        assert!(node.is_leaf());
        assert_eq!(node.get_data(), Some(b"test".as_slice()));
    }

    #[test]
    fn test_node_internal() {
        let left = Node::<SimpleHasher>::leaf(b"left".to_vec());
        let right = Node::<SimpleHasher>::leaf(b"right".to_vec());
        let internal = Node::internal(left, right);

        assert!(!internal.is_leaf());
        assert!(internal.get_data().is_none());
    }

    #[test]
    fn test_node_delegates_hash() {
        let node = Node::<Sha256Hasher>::leaf(b"test".to_vec());
        assert_eq!(node.hash().len(), 64);
    }

    #[test]
    fn test_different_hashers() {
        let simple = Node::<SimpleHasher>::leaf(b"test".to_vec());
        let sha256 = Node::<Sha256Hasher>::leaf(b"test".to_vec());
        assert_ne!(simple.hash(), sha256.hash());
    }
}

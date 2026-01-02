use std::sync::Arc;

use crate::hasher::Hasher;
use crate::merkle::hash::Hash;
use crate::merkle::internal_node::InternalNode;
use crate::merkle::leaf_node::LeafNode;

/// A node in the Merkle tree - either a Leaf or an Internal node.
///
/// This enum provides a unified interface while each inner type
/// handles its own hashing logic.
#[derive(Clone)]
pub enum Node {
    Leaf(LeafNode),
    Internal(InternalNode),
}

impl Node {
    /// Create a leaf node using the provided hasher.
    pub fn leaf<H: Hasher>(data: Vec<u8>, hasher: &H) -> Self {
        Node::Leaf(LeafNode::new(data, hasher))
    }

    /// Create an internal node using the provided hasher.
    pub fn internal<H: Hasher>(left: Arc<Node>, right: Arc<Node>, hasher: &H) -> Self {
        Node::Internal(InternalNode::new(left, right, hasher))
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
impl Hash for Node {
    fn hash(&self) -> &[u8] {
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
        let hasher = SimpleHasher::new();
        let node = Node::leaf(b"test".to_vec(), &hasher);
        assert!(node.is_leaf());
        assert_eq!(node.get_data(), Some(b"test".as_slice()));
    }

    #[test]
    fn test_node_internal() {
        let hasher = SimpleHasher::new();
        let left = Arc::new(Node::leaf(b"left".to_vec(), &hasher));
        let right = Arc::new(Node::leaf(b"right".to_vec(), &hasher));
        let internal = Node::internal(left, right, &hasher);

        assert!(!internal.is_leaf());
        assert!(internal.get_data().is_none());
    }

    #[test]
    fn test_node_delegates_hash() {
        let hasher = Sha256Hasher::new();
        let node = Node::leaf(b"test".to_vec(), &hasher);
        assert_eq!(node.hash().len(), 32);
    }

    #[test]
    fn test_different_hashers() {
        let simple = SimpleHasher::new();
        let sha256 = Sha256Hasher::new();
        let node_simple = Node::leaf(b"test".to_vec(), &simple);
        let node_sha256 = Node::leaf(b"test".to_vec(), &sha256);
        assert_ne!(node_simple.hash(), node_sha256.hash());
    }
}

pub mod hasher;
pub mod merkle;

// Re-export main types at crate root for convenience
pub use hasher::{Hasher, Sha256Hasher, SimpleHasher};
pub use merkle::{Hash, InternalNode, LeafNode, Node};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_node() {
        let leaf: LeafNode<Sha256Hasher> = LeafNode::new(b"hello".to_vec());
        assert_eq!(leaf.hash().len(), 64);
    }

    #[test]
    fn test_internal_node() {
        let left = Node::<Sha256Hasher>::leaf(b"a".to_vec());
        let right = Node::<Sha256Hasher>::leaf(b"b".to_vec());
        let internal = InternalNode::new(left, right);
        assert_eq!(internal.hash().len(), 64);
    }
}

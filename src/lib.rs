pub mod hasher;
pub mod merkle;

// Re-export main types at crate root for convenience
pub use hasher::{Hasher, Sha256Hasher, SimpleHasher};
pub use merkle::{
    Hash, InternalNode, LeafNode, MerkleTree, MerkleTreeError, Node, SimpleMerkleTree,
};

/// Convert bytes to a hexadecimal string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // =========================================================================
    // LeafNode Tests
    // =========================================================================

    #[test]
    fn test_leaf_node_creation() {
        let hasher = Sha256Hasher::new();
        let leaf = LeafNode::new(b"hello".to_vec(), &hasher);
        assert_eq!(leaf.data(), b"hello");
        assert_eq!(leaf.hash().len(), 32);
    }

    #[test]
    fn test_leaf_node_with_simple_hasher() {
        let hasher = SimpleHasher::new();
        let leaf = LeafNode::new(b"hello".to_vec(), &hasher);
        assert!(!leaf.hash().is_empty());
    }

    #[test]
    fn test_leaf_node_empty_data() {
        let hasher = Sha256Hasher::new();
        let leaf = LeafNode::new(vec![], &hasher);
        assert_eq!(leaf.data(), &[] as &[u8]);
        assert_eq!(leaf.hash().len(), 32);
    }

    #[test]
    fn test_leaf_node_deterministic_hash() {
        let hasher = Sha256Hasher::new();
        let leaf1 = LeafNode::new(b"test".to_vec(), &hasher);
        let leaf2 = LeafNode::new(b"test".to_vec(), &hasher);
        assert_eq!(leaf1.hash(), leaf2.hash());
    }

    #[test]
    fn test_leaf_node_different_data_different_hash() {
        let hasher = Sha256Hasher::new();
        let leaf1 = LeafNode::new(b"hello".to_vec(), &hasher);
        let leaf2 = LeafNode::new(b"world".to_vec(), &hasher);
        assert_ne!(leaf1.hash(), leaf2.hash());
    }

    // =========================================================================
    // InternalNode Tests
    // =========================================================================

    #[test]
    fn test_internal_node_creation() {
        let hasher = Sha256Hasher::new();
        let left = Arc::new(Node::leaf(b"a".to_vec(), &hasher));
        let right = Arc::new(Node::leaf(b"b".to_vec(), &hasher));
        let internal = InternalNode::new(left, right, &hasher);
        assert_eq!(internal.hash().len(), 32);
    }

    #[test]
    fn test_internal_node_children_accessible() {
        let hasher = Sha256Hasher::new();
        let left = Arc::new(Node::leaf(b"left".to_vec(), &hasher));
        let right = Arc::new(Node::leaf(b"right".to_vec(), &hasher));
        let left_hash = Arc::clone(&left).hash().to_vec();
        let right_hash = Arc::clone(&right).hash().to_vec();

        let internal = InternalNode::new(left, right, &hasher);
        assert_eq!(internal.left().hash(), left_hash.as_slice());
        assert_eq!(internal.right().hash(), right_hash.as_slice());
    }

    #[test]
    fn test_internal_node_order_matters() {
        let hasher = Sha256Hasher::new();
        let a = Arc::new(Node::leaf(b"a".to_vec(), &hasher));
        let b = Arc::new(Node::leaf(b"b".to_vec(), &hasher));
        let internal1 = InternalNode::new(a, b, &hasher);

        let a = Arc::new(Node::leaf(b"a".to_vec(), &hasher));
        let b = Arc::new(Node::leaf(b"b".to_vec(), &hasher));
        let internal2 = InternalNode::new(b, a, &hasher);

        // Swapping left/right produces different hash
        assert_ne!(internal1.hash(), internal2.hash());
    }

    #[test]
    fn test_internal_node_deterministic_hash() {
        let hasher = Sha256Hasher::new();
        let internal1 = InternalNode::new(
            Arc::new(Node::leaf(b"left".to_vec(), &hasher)),
            Arc::new(Node::leaf(b"right".to_vec(), &hasher)),
            &hasher,
        );
        let internal2 = InternalNode::new(
            Arc::new(Node::leaf(b"left".to_vec(), &hasher)),
            Arc::new(Node::leaf(b"right".to_vec(), &hasher)),
            &hasher,
        );
        assert_eq!(internal1.hash(), internal2.hash());
    }

    // =========================================================================
    // Node Enum Tests
    // =========================================================================

    #[test]
    fn test_node_leaf_is_leaf() {
        let hasher = Sha256Hasher::new();
        let node = Node::leaf(b"test".to_vec(), &hasher);
        assert!(node.is_leaf());
    }

    #[test]
    fn test_node_internal_is_not_leaf() {
        let hasher = Sha256Hasher::new();
        let left = Arc::new(Node::leaf(b"a".to_vec(), &hasher));
        let right = Arc::new(Node::leaf(b"b".to_vec(), &hasher));
        let node = Node::internal(left, right, &hasher);
        assert!(!node.is_leaf());
    }

    #[test]
    fn test_node_get_data_for_leaf() {
        let hasher = Sha256Hasher::new();
        let node = Node::leaf(b"hello".to_vec(), &hasher);
        assert_eq!(node.get_data(), Some(b"hello".as_slice()));
    }

    #[test]
    fn test_node_get_data_for_internal_returns_none() {
        let hasher = Sha256Hasher::new();
        let left = Arc::new(Node::leaf(b"a".to_vec(), &hasher));
        let right = Arc::new(Node::leaf(b"b".to_vec(), &hasher));
        let node = Node::internal(left, right, &hasher);
        assert_eq!(node.get_data(), None);
    }

    // =========================================================================
    // Domain Separation Tests
    // =========================================================================

    #[test]
    fn test_domain_separation_leaf_vs_internal() {
        let hasher = Sha256Hasher::new();
        // A leaf with data "ab" should have a different hash than
        // an internal node whose children happen to produce "ab" when concatenated
        let leaf = Node::leaf(b"ab".to_vec(), &hasher);

        let a = Arc::new(Node::leaf(b"a".to_vec(), &hasher));
        let b = Arc::new(Node::leaf(b"b".to_vec(), &hasher));
        let internal = Node::internal(a, b, &hasher);

        // These must be different due to domain separation (0x00 vs 0x01 prefix)
        assert_ne!(leaf.hash(), internal.hash());
    }

    // =========================================================================
    // Multi-Level Tree Tests
    // =========================================================================

    #[test]
    fn test_three_level_tree() {
        let hasher = Sha256Hasher::new();
        // Build a tree with 4 leaves (3 levels: leaves, level 1, root)
        //
        //              root
        //            /      \
        //         n1          n2
        //        /  \        /  \
        //       L0  L1      L2  L3

        let l0 = Arc::new(Node::leaf(b"leaf0".to_vec(), &hasher));
        let l1 = Arc::new(Node::leaf(b"leaf1".to_vec(), &hasher));
        let l2 = Arc::new(Node::leaf(b"leaf2".to_vec(), &hasher));
        let l3 = Arc::new(Node::leaf(b"leaf3".to_vec(), &hasher));

        let n1 = Arc::new(Node::internal(l0, l1, &hasher));
        let n2 = Arc::new(Node::internal(l2, l3, &hasher));
        let root = Node::internal(n1, n2, &hasher);

        assert!(!root.is_leaf());
        assert_eq!(root.hash().len(), 32);
    }

    #[test]
    fn test_tree_root_changes_when_leaf_changes() {
        let hasher = Sha256Hasher::new();
        // Same tree structure, different leaf data -> different root
        let tree1 = Node::internal(
            Arc::new(Node::internal(
                Arc::new(Node::leaf(b"a".to_vec(), &hasher)),
                Arc::new(Node::leaf(b"b".to_vec(), &hasher)),
                &hasher,
            )),
            Arc::new(Node::internal(
                Arc::new(Node::leaf(b"c".to_vec(), &hasher)),
                Arc::new(Node::leaf(b"d".to_vec(), &hasher)),
                &hasher,
            )),
            &hasher,
        );

        let tree2 = Node::internal(
            Arc::new(Node::internal(
                Arc::new(Node::leaf(b"a".to_vec(), &hasher)),
                Arc::new(Node::leaf(b"b".to_vec(), &hasher)),
                &hasher,
            )),
            Arc::new(Node::internal(
                Arc::new(Node::leaf(b"c".to_vec(), &hasher)),
                Arc::new(Node::leaf(b"CHANGED".to_vec(), &hasher)), // Different!
                &hasher,
            )),
            &hasher,
        );

        assert_ne!(tree1.hash(), tree2.hash());
    }

    #[test]
    fn test_identical_trees_have_same_root() {
        let hasher = Sha256Hasher::new();
        let tree1 = Node::internal(
            Arc::new(Node::leaf(b"left".to_vec(), &hasher)),
            Arc::new(Node::leaf(b"right".to_vec(), &hasher)),
            &hasher,
        );

        let tree2 = Node::internal(
            Arc::new(Node::leaf(b"left".to_vec(), &hasher)),
            Arc::new(Node::leaf(b"right".to_vec(), &hasher)),
            &hasher,
        );

        assert_eq!(tree1.hash(), tree2.hash());
    }

    // =========================================================================
    // Hasher Interchangeability Tests
    // =========================================================================

    #[test]
    fn test_different_hashers_produce_different_results() {
        let simple = SimpleHasher::new();
        let sha256 = Sha256Hasher::new();
        let node_simple = Node::leaf(b"test".to_vec(), &simple);
        let node_sha256 = Node::leaf(b"test".to_vec(), &sha256);
        assert_ne!(node_simple.hash(), node_sha256.hash());
    }

    #[test]
    fn test_simple_hasher_tree() {
        let hasher = SimpleHasher::new();
        let left = Arc::new(Node::leaf(b"a".to_vec(), &hasher));
        let right = Arc::new(Node::leaf(b"b".to_vec(), &hasher));
        let root = Node::internal(left, right, &hasher);
        assert!(!root.hash().is_empty());
    }

    // =========================================================================
    // SimpleMerkleTree Tests
    // =========================================================================

    #[test]
    fn test_simple_merkle_tree_creation() {
        let tree = SimpleMerkleTree::new(Sha256Hasher::new());
        assert_eq!(tree.get_size(), 0);
        assert!(tree.get_root().is_none());
    }

    #[test]
    fn test_simple_merkle_tree_add_leaves() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"hello").unwrap();
        tree.add_leaf(b"world").unwrap();
        assert_eq!(tree.get_size(), 2);
        assert!(tree.get_root().is_some());
    }

    #[test]
    fn test_simple_merkle_tree_deterministic() {
        let mut tree1 = SimpleMerkleTree::new(Sha256Hasher::new());
        tree1.add_leaf(b"a").unwrap();
        tree1.add_leaf(b"b").unwrap();

        let mut tree2 = SimpleMerkleTree::new(Sha256Hasher::new());
        tree2.add_leaf(b"a").unwrap();
        tree2.add_leaf(b"b").unwrap();

        assert_eq!(tree1.get_root(), tree2.get_root());
    }
}

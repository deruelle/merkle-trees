pub mod hasher;
pub mod merkle;

// Re-export main types at crate root for convenience
pub use hasher::{Hasher, Sha256Hasher, SimpleHasher};
pub use merkle::{Hash, InternalNode, LeafNode, Node};

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // LeafNode Tests
    // =========================================================================

    #[test]
    fn test_leaf_node_creation() {
        let leaf: LeafNode<Sha256Hasher> = LeafNode::new(b"hello".to_vec());
        assert_eq!(leaf.data(), b"hello");
        assert_eq!(leaf.hash().len(), 64);
    }

    #[test]
    fn test_leaf_node_with_simple_hasher() {
        let leaf: LeafNode<SimpleHasher> = LeafNode::new(b"hello".to_vec());
        assert!(!leaf.hash().is_empty());
    }

    #[test]
    fn test_leaf_node_empty_data() {
        let leaf: LeafNode<Sha256Hasher> = LeafNode::new(vec![]);
        assert_eq!(leaf.data(), &[] as &[u8]);
        assert_eq!(leaf.hash().len(), 64);
    }

    #[test]
    fn test_leaf_node_deterministic_hash() {
        let leaf1: LeafNode<Sha256Hasher> = LeafNode::new(b"test".to_vec());
        let leaf2: LeafNode<Sha256Hasher> = LeafNode::new(b"test".to_vec());
        assert_eq!(leaf1.hash(), leaf2.hash());
    }

    #[test]
    fn test_leaf_node_different_data_different_hash() {
        let leaf1: LeafNode<Sha256Hasher> = LeafNode::new(b"hello".to_vec());
        let leaf2: LeafNode<Sha256Hasher> = LeafNode::new(b"world".to_vec());
        assert_ne!(leaf1.hash(), leaf2.hash());
    }

    // =========================================================================
    // InternalNode Tests
    // =========================================================================

    #[test]
    fn test_internal_node_creation() {
        let left = Node::<Sha256Hasher>::leaf(b"a".to_vec());
        let right = Node::<Sha256Hasher>::leaf(b"b".to_vec());
        let internal = InternalNode::new(left, right);
        assert_eq!(internal.hash().len(), 64);
    }

    #[test]
    fn test_internal_node_children_accessible() {
        let left = Node::<Sha256Hasher>::leaf(b"left".to_vec());
        let right = Node::<Sha256Hasher>::leaf(b"right".to_vec());
        let left_hash = left.hash();
        let right_hash = right.hash();

        let internal = InternalNode::new(left, right);
        assert_eq!(internal.left().hash(), left_hash);
        assert_eq!(internal.right().hash(), right_hash);
    }

    #[test]
    fn test_internal_node_order_matters() {
        let a = Node::<Sha256Hasher>::leaf(b"a".to_vec());
        let b = Node::<Sha256Hasher>::leaf(b"b".to_vec());
        let internal1 = InternalNode::new(a, b);

        let a = Node::<Sha256Hasher>::leaf(b"a".to_vec());
        let b = Node::<Sha256Hasher>::leaf(b"b".to_vec());
        let internal2 = InternalNode::new(b, a);

        // Swapping left/right produces different hash
        assert_ne!(internal1.hash(), internal2.hash());
    }

    #[test]
    fn test_internal_node_deterministic_hash() {
        let internal1 = InternalNode::new(
            Node::<Sha256Hasher>::leaf(b"left".to_vec()),
            Node::<Sha256Hasher>::leaf(b"right".to_vec()),
        );
        let internal2 = InternalNode::new(
            Node::<Sha256Hasher>::leaf(b"left".to_vec()),
            Node::<Sha256Hasher>::leaf(b"right".to_vec()),
        );
        assert_eq!(internal1.hash(), internal2.hash());
    }

    // =========================================================================
    // Node Enum Tests
    // =========================================================================

    #[test]
    fn test_node_leaf_is_leaf() {
        let node = Node::<Sha256Hasher>::leaf(b"test".to_vec());
        assert!(node.is_leaf());
    }

    #[test]
    fn test_node_internal_is_not_leaf() {
        let left = Node::<Sha256Hasher>::leaf(b"a".to_vec());
        let right = Node::<Sha256Hasher>::leaf(b"b".to_vec());
        let node = Node::internal(left, right);
        assert!(!node.is_leaf());
    }

    #[test]
    fn test_node_get_data_for_leaf() {
        let node = Node::<Sha256Hasher>::leaf(b"hello".to_vec());
        assert_eq!(node.get_data(), Some(b"hello".as_slice()));
    }

    #[test]
    fn test_node_get_data_for_internal_returns_none() {
        let left = Node::<Sha256Hasher>::leaf(b"a".to_vec());
        let right = Node::<Sha256Hasher>::leaf(b"b".to_vec());
        let node = Node::internal(left, right);
        assert_eq!(node.get_data(), None);
    }

    // =========================================================================
    // Domain Separation Tests
    // =========================================================================

    #[test]
    fn test_domain_separation_leaf_vs_internal() {
        // A leaf with data "ab" should have a different hash than
        // an internal node whose children happen to produce "ab" when concatenated
        let leaf = Node::<Sha256Hasher>::leaf(b"ab".to_vec());

        let a = Node::<Sha256Hasher>::leaf(b"a".to_vec());
        let b = Node::<Sha256Hasher>::leaf(b"b".to_vec());
        let internal = Node::internal(a, b);

        // These must be different due to domain separation (0x00 vs 0x01 prefix)
        assert_ne!(leaf.hash(), internal.hash());
    }

    // =========================================================================
    // Multi-Level Tree Tests
    // =========================================================================

    #[test]
    fn test_three_level_tree() {
        // Build a tree with 4 leaves (3 levels: leaves, level 1, root)
        //
        //              root
        //            /      \
        //         n1          n2
        //        /  \        /  \
        //       L0  L1      L2  L3

        let l0 = Node::<Sha256Hasher>::leaf(b"leaf0".to_vec());
        let l1 = Node::<Sha256Hasher>::leaf(b"leaf1".to_vec());
        let l2 = Node::<Sha256Hasher>::leaf(b"leaf2".to_vec());
        let l3 = Node::<Sha256Hasher>::leaf(b"leaf3".to_vec());

        let n1 = Node::internal(l0, l1);
        let n2 = Node::internal(l2, l3);
        let root = Node::internal(n1, n2);

        assert!(!root.is_leaf());
        assert_eq!(root.hash().len(), 64);
    }

    #[test]
    fn test_tree_root_changes_when_leaf_changes() {
        // Same tree structure, different leaf data -> different root
        let tree1 = Node::internal(
            Node::internal(
                Node::<Sha256Hasher>::leaf(b"a".to_vec()),
                Node::<Sha256Hasher>::leaf(b"b".to_vec()),
            ),
            Node::internal(
                Node::<Sha256Hasher>::leaf(b"c".to_vec()),
                Node::<Sha256Hasher>::leaf(b"d".to_vec()),
            ),
        );

        let tree2 = Node::internal(
            Node::internal(
                Node::<Sha256Hasher>::leaf(b"a".to_vec()),
                Node::<Sha256Hasher>::leaf(b"b".to_vec()),
            ),
            Node::internal(
                Node::<Sha256Hasher>::leaf(b"c".to_vec()),
                Node::<Sha256Hasher>::leaf(b"CHANGED".to_vec()), // Different!
            ),
        );

        assert_ne!(tree1.hash(), tree2.hash());
    }

    #[test]
    fn test_identical_trees_have_same_root() {
        let tree1 = Node::internal(
            Node::<Sha256Hasher>::leaf(b"left".to_vec()),
            Node::<Sha256Hasher>::leaf(b"right".to_vec()),
        );

        let tree2 = Node::internal(
            Node::<Sha256Hasher>::leaf(b"left".to_vec()),
            Node::<Sha256Hasher>::leaf(b"right".to_vec()),
        );

        assert_eq!(tree1.hash(), tree2.hash());
    }

    // =========================================================================
    // Hasher Interchangeability Tests
    // =========================================================================

    #[test]
    fn test_different_hashers_produce_different_results() {
        let simple = Node::<SimpleHasher>::leaf(b"test".to_vec());
        let sha256 = Node::<Sha256Hasher>::leaf(b"test".to_vec());
        assert_ne!(simple.hash(), sha256.hash());
    }

    #[test]
    fn test_simple_hasher_tree() {
        let left = Node::<SimpleHasher>::leaf(b"a".to_vec());
        let right = Node::<SimpleHasher>::leaf(b"b".to_vec());
        let root = Node::internal(left, right);
        assert!(!root.hash().is_empty());
    }
}

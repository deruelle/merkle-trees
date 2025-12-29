use std::sync::Arc;

use crate::hasher::Hasher;
use crate::merkle::MerkleTreeError;
use crate::merkle::hash::Hash;
use crate::merkle::leaf_node::LeafNode;
use crate::merkle::node::Node;

/// A Merkle tree implementation.
pub struct SimpleMerkleTree<H: Hasher> {
    leaves: Vec<LeafNode>,
    root: Option<Node>,
    hasher: H,
}

impl<H: Hasher> SimpleMerkleTree<H> {
    pub fn new(hasher: H) -> Self {
        Self {
            leaves: Vec::new(),
            root: None,
            hasher,
        }
    }

    pub fn add_leaf(&mut self, data: &[u8]) -> Result<(), MerkleTreeError> {
        if data.is_empty() {
            return Err(MerkleTreeError::EmptyInput);
        }

        let leaf = LeafNode::new(data.to_vec(), &self.hasher);
        self.leaves.push(leaf);
        self.rebuild_tree();
        self.print_tree();
        Ok(())
    }

    pub fn get_root(&self) -> Option<String> {
        self.root.as_ref().map(|r| r.hash())
    }

    pub fn get_data(&self, index: usize) -> Option<&[u8]> {
        self.leaves.get(index).map(|leaf| leaf.data())
    }

    pub fn get_size(&self) -> usize {
        self.leaves.len()
    }

    /// Rebuild the tree from the current leaves.
    fn rebuild_tree(&mut self) {
        // Wrap leaves in Arc
        let mut current_level: Vec<Arc<Node>> = self
            .leaves
            .iter()
            .map(|leaf| Arc::new(Node::Leaf(leaf.clone())))
            .collect();

        while current_level.len() > 1 {
            let mut next_level =
                Vec::with_capacity(current_level.len().div_ceil(2) + (current_level.len() % 2));

            for chunk in current_level.chunks(2) {
                let left = Arc::clone(&chunk[0]);
                let right = if chunk.len() > 1 {
                    Arc::clone(&chunk[1])
                } else {
                    // Just clone the Arc pointer - no deep copy!
                    Arc::clone(&chunk[0])
                };
                next_level.push(Arc::new(Node::internal(left, right, &self.hasher)));
            }

            current_level = next_level;
        }

        self.root = current_level
            .into_iter()
            .next()
            .map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|arc| (*arc).clone()));
    }

    fn print_tree(&self) {
        println!("Merkle tree:");
        println!("Root: {}", self.get_root().unwrap());
        println!("Leaves: {}", self.leaves.len());
        println!("Size: {}", self.get_size());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{Sha256Hasher, SimpleHasher};

    #[test]
    fn test_empty_tree() {
        let tree: SimpleMerkleTree<SimpleHasher> = SimpleMerkleTree::new(SimpleHasher::new());
        assert_eq!(tree.get_size(), 0);
        assert!(tree.get_root().is_none());
    }

    #[test]
    fn test_single_leaf() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"hello").unwrap();
        assert_eq!(tree.get_size(), 1);
        assert!(tree.get_root().is_some());
        assert_eq!(tree.get_data(0), Some(b"hello".as_slice()));
    }

    #[test]
    fn test_multiple_leaves() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();
        tree.add_leaf(b"c").unwrap();
        assert_eq!(tree.get_size(), 3);
        assert!(tree.get_root().is_some());
    }

    #[test]
    fn test_empty_data_rejected() {
        let mut tree = SimpleMerkleTree::new(SimpleHasher::new());
        assert!(tree.add_leaf(b"").is_err());
    }

    #[test]
    fn test_deterministic_root() {
        let mut tree1 = SimpleMerkleTree::new(Sha256Hasher::new());
        tree1.add_leaf(b"a").unwrap();
        tree1.add_leaf(b"b").unwrap();

        let mut tree2 = SimpleMerkleTree::new(Sha256Hasher::new());
        tree2.add_leaf(b"a").unwrap();
        tree2.add_leaf(b"b").unwrap();

        assert_eq!(tree1.get_root(), tree2.get_root());
    }
}

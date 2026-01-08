use std::sync::Arc;

use crate::bytes_to_hex;
use crate::hasher::Hasher;
use crate::merkle::MerkleTree;
use crate::merkle::MerkleTreeError;
use crate::merkle::hash::Hash;
use crate::merkle::leaf_node::LeafNode;
use crate::merkle::node::Node;
use crate::merkle::proof::{Proof, ProofStep, SiblingPosition, verify_proof};

/// A Merkle tree implementation.
pub struct SimpleMerkleTree<H: Hasher> {
    leaves: Vec<LeafNode>,
    root: Option<Node>,
    hasher: H,
}

// Trait implementation (public interface) for SimpleMerkleTree
impl<H: Hasher> MerkleTree<H> for SimpleMerkleTree<H> {
    fn add_leaf(&mut self, data: &[u8]) -> Result<(), MerkleTreeError> {
        if data.is_empty() {
            return Err(MerkleTreeError::EmptyInput);
        }

        let leaf = LeafNode::new(data.to_vec(), &self.hasher);
        self.leaves.push(leaf);
        self.rebuild_tree();
        Ok(())
    }

    fn get_root(&self) -> Option<String> {
        self.root.as_ref().map(|r| bytes_to_hex(r.hash()))
    }

    fn get_root_bytes(&self) -> Option<[u8; 32]> {
        self.root.as_ref().map(|r| {
            let hash = r.hash();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(hash);
            bytes
        })
    }

    fn get_data(&self, index: usize) -> Option<&[u8]> {
        self.leaves.get(index).map(|leaf| leaf.data())
    }

    fn get_size(&self) -> usize {
        self.leaves.len()
    }

    fn prove(&self, index: usize) -> Result<Proof, MerkleTreeError> {
        // Validate index
        if index >= self.leaves.len() {
            return Err(MerkleTreeError::IndexOutOfBounds {
                index,
                size: self.leaves.len(),
            });
        }

        // Get the leaf hash
        let leaf_hash: [u8; 32] = self.leaves[index].hash().try_into().unwrap();

        // If only one leaf, the proof has no steps (leaf hash == root)
        if self.leaves.len() == 1 {
            return Ok(Proof {
                leaf_index: index,
                leaf_hash,
                steps: vec![],
            });
        }

        // Build level hashes similar to rebuild_tree, but collect sibling info
        let mut current_level: Vec<[u8; 32]> = self
            .leaves
            .iter()
            .map(|leaf| leaf.hash().try_into().unwrap())
            .collect();

        let mut current_index = index;
        let mut steps = Vec::new();

        while current_level.len() > 1 {
            // Determine sibling index and position
            let (sibling_index, position) = if current_index.is_multiple_of(2) {
                // Current is even (left child), sibling is on right
                (current_index + 1, SiblingPosition::Right)
            } else {
                // Current is odd (right child), sibling is on left
                (current_index - 1, SiblingPosition::Left)
            };

            // Get sibling hash (handle odd number of nodes by duplicating last)
            let sibling_hash = if sibling_index < current_level.len() {
                current_level[sibling_index]
            } else {
                // Duplicate the last node (which is current_index)
                current_level[current_index]
            };

            steps.push(ProofStep {
                sibling_hash,
                position,
            });

            // Build next level
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };

                // Hash: H(0x01 || left || right)
                let mut to_hash = Vec::with_capacity(65);
                to_hash.push(0x01);
                to_hash.extend_from_slice(&left);
                to_hash.extend_from_slice(&right);
                next_level.push(self.hasher.hash_bytes(&to_hash));
            }

            current_level = next_level;
            current_index /= 2;
        }

        Ok(Proof {
            leaf_index: index,
            leaf_hash,
            steps,
        })
    }

    fn verify(&self, proof: &Proof, expected_root: &[u8]) -> bool {
        verify_proof(proof, expected_root, &self.hasher)
    }
}

// Private implementation details for SimpleMerkleTree
impl<H: Hasher> SimpleMerkleTree<H> {
    pub fn new(hasher: H) -> Self {
        Self {
            leaves: Vec::new(),
            root: None,
            hasher,
        }
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
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));

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

    // =========================================================================
    // Proof Generation Tests
    // =========================================================================

    #[test]
    fn test_prove_single_leaf() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"hello").unwrap();

        let proof = tree.prove(0).unwrap();
        assert_eq!(proof.leaf_index, 0);
        assert!(proof.steps.is_empty()); // Single leaf: no siblings
        assert_eq!(proof.leaf_hash.as_slice(), tree.get_root_bytes().unwrap());
    }

    #[test]
    fn test_prove_two_leaves() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();

        // Proof for first leaf
        let proof0 = tree.prove(0).unwrap();
        assert_eq!(proof0.leaf_index, 0);
        assert_eq!(proof0.steps.len(), 1);
        assert_eq!(proof0.steps[0].position, SiblingPosition::Right);

        // Proof for second leaf
        let proof1 = tree.prove(1).unwrap();
        assert_eq!(proof1.leaf_index, 1);
        assert_eq!(proof1.steps.len(), 1);
        assert_eq!(proof1.steps[0].position, SiblingPosition::Left);
    }

    #[test]
    fn test_prove_four_leaves() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();
        tree.add_leaf(b"c").unwrap();
        tree.add_leaf(b"d").unwrap();

        // Each leaf should have 2 steps (log2(4) = 2)
        for i in 0..4 {
            let proof = tree.prove(i).unwrap();
            assert_eq!(proof.leaf_index, i);
            assert_eq!(proof.steps.len(), 2);
        }

        // Check positions for leaf 0: sibling at level 0 is on right, sibling at level 1 is on right
        let proof0 = tree.prove(0).unwrap();
        assert_eq!(proof0.steps[0].position, SiblingPosition::Right);
        assert_eq!(proof0.steps[1].position, SiblingPosition::Right);

        // Check positions for leaf 3: sibling at level 0 is on left, sibling at level 1 is on left
        let proof3 = tree.prove(3).unwrap();
        assert_eq!(proof3.steps[0].position, SiblingPosition::Left);
        assert_eq!(proof3.steps[1].position, SiblingPosition::Left);
    }

    #[test]
    fn test_prove_odd_leaves() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();
        tree.add_leaf(b"c").unwrap();

        // Tree structure with 3 leaves:
        //           root
        //          /    \
        //      H(a,b)   H(c,c)  <- c is duplicated
        //      /   \    /   \
        //     a     b  c     c
        //
        // Proof for leaf 2 (c) should have 2 steps

        let proof = tree.prove(2).unwrap();
        assert_eq!(proof.leaf_index, 2);
        assert_eq!(proof.steps.len(), 2);

        // At level 0: c is at index 2 (even), sibling is at index 3 but doesn't exist,
        // so sibling is itself (duplicated), position is Right
        assert_eq!(proof.steps[0].position, SiblingPosition::Right);
        assert_eq!(proof.steps[0].sibling_hash, proof.leaf_hash); // Same as leaf hash!
    }

    #[test]
    fn test_prove_invalid_index() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();

        let result = tree.prove(5);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            MerkleTreeError::IndexOutOfBounds { index: 5, size: 2 }
        );
    }

    #[test]
    fn test_prove_empty_tree() {
        let tree: SimpleMerkleTree<Sha256Hasher> = SimpleMerkleTree::new(Sha256Hasher::new());

        let result = tree.prove(0);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            MerkleTreeError::IndexOutOfBounds { index: 0, size: 0 }
        );
    }

    // =========================================================================
    // Proof Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_valid_proof() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();
        tree.add_leaf(b"c").unwrap();
        tree.add_leaf(b"d").unwrap();

        let root = tree.get_root_bytes().unwrap();

        // Verify proof for each leaf
        for i in 0..4 {
            let proof = tree.prove(i).unwrap();
            assert!(tree.verify(&proof, &root));
        }
    }

    #[test]
    fn test_verify_single_leaf() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"hello").unwrap();

        let proof = tree.prove(0).unwrap();
        let root = tree.get_root_bytes().unwrap();
        assert!(tree.verify(&proof, &root));
    }

    #[test]
    fn test_verify_wrong_root() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();

        let proof = tree.prove(0).unwrap();
        let wrong_root = [0xFFu8; 32];
        assert!(!tree.verify(&proof, &wrong_root));
    }

    #[test]
    fn test_verify_tampered_sibling_hash() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();

        let mut proof = tree.prove(0).unwrap();
        let root = tree.get_root_bytes().unwrap();

        // Tamper with the sibling hash
        proof.steps[0].sibling_hash[0] ^= 0xFF;

        assert!(!tree.verify(&proof, &root));
    }

    #[test]
    fn test_verify_tampered_leaf_hash() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();

        let mut proof = tree.prove(0).unwrap();
        let root = tree.get_root_bytes().unwrap();

        // Tamper with the leaf hash
        proof.leaf_hash[0] ^= 0xFF;

        assert!(!tree.verify(&proof, &root));
    }

    #[test]
    fn test_verify_wrong_position() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();

        let mut proof = tree.prove(0).unwrap();
        let root = tree.get_root_bytes().unwrap();

        // Swap the position
        proof.steps[0].position = SiblingPosition::Left;

        assert!(!tree.verify(&proof, &root));
    }

    #[test]
    fn test_verify_odd_leaves() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();
        tree.add_leaf(b"c").unwrap();
        tree.add_leaf(b"d").unwrap();
        tree.add_leaf(b"e").unwrap();

        let root = tree.get_root_bytes().unwrap();

        // Verify proof for each leaf, especially the last one
        for i in 0..5 {
            let proof = tree.prove(i).unwrap();
            assert!(tree.verify(&proof, &root), "Failed for leaf {}", i);
        }
    }

    // =========================================================================
    // Proof Serialization Integration Tests
    // =========================================================================

    #[test]
    fn test_serialization_roundtrip_integration() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"alpha").unwrap();
        tree.add_leaf(b"beta").unwrap();
        tree.add_leaf(b"gamma").unwrap();

        let root = tree.get_root_bytes().unwrap();

        for i in 0..3 {
            let proof = tree.prove(i).unwrap();

            // Serialize and deserialize
            let bytes = proof.to_bytes();
            let restored = Proof::from_bytes(&bytes).unwrap();

            // Verify the restored proof still works
            assert!(tree.verify(&restored, &root));
            assert_eq!(proof, restored);
        }
    }
}

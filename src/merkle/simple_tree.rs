use std::sync::Arc;

use crate::bytes_to_hex;
use crate::hasher::Hasher;
use crate::merkle::MerkleTree;
use crate::merkle::MerkleTreeError;
use crate::merkle::hash::Hash;
use crate::merkle::leaf_node::LeafNode;
use crate::merkle::node::Node;
use crate::merkle::proof::Proof;

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

    fn get_data(&self, index: u64) -> Option<&[u8]> {
        self.leaves.get(index as usize).map(|leaf| leaf.data())
    }

    fn get_size(&self) -> u64 {
        self.leaves.len() as u64
    }

    fn prove(&self, index: u64) -> Result<Proof, MerkleTreeError> {
        let tree_size = self.leaves.len() as u64;

        // Handle empty tree or out of bounds index
        if tree_size == 0 || index >= tree_size {
            return Err(MerkleTreeError::InvalidIndex { index, tree_size });
        }

        // Single-leaf tree: empty sibling list
        if tree_size == 1 {
            return Ok(Proof::new(index, vec![]));
        }

        // Build level-by-level hash arrays and collect siblings
        let siblings = self.collect_siblings(index);

        Ok(Proof::new(index, siblings))
    }

    fn verify(&self, proof: &Proof, leaf_data: &[u8], expected_root: &[u8; 32]) -> bool {
        verify_proof(leaf_data, proof, expected_root, &self.hasher)
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

    /// Collect sibling hashes from leaf level to root.
    ///
    /// Uses the same duplication logic as tree construction:
    /// when there's an odd number of nodes at a level, the last node
    /// is duplicated (its sibling is itself).
    fn collect_siblings(&self, leaf_index: u64) -> Vec<[u8; 32]> {
        let mut siblings = Vec::new();
        let mut current_level: Vec<[u8; 32]> = self
            .leaves
            .iter()
            .map(|leaf| {
                let hash = leaf.hash();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(hash);
                arr
            })
            .collect();

        let mut idx = leaf_index as usize;

        while current_level.len() > 1 {
            // Find sibling index
            let sibling_idx = if idx.is_multiple_of(2) {
                // Even index: sibling is on the right
                if idx + 1 < current_level.len() {
                    idx + 1
                } else {
                    // Odd number of nodes: last node is duplicated
                    idx
                }
            } else {
                // Odd index: sibling is on the left
                idx - 1
            };

            siblings.push(current_level[sibling_idx]);

            // Build next level
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            for chunk in current_level.chunks(2) {
                let left = &chunk[0];
                let right = if chunk.len() > 1 {
                    &chunk[1]
                } else {
                    &chunk[0]
                };
                next_level.push(compute_internal_hash(left, right, &self.hasher));
            }

            // Move to parent index
            idx /= 2;
            current_level = next_level;
        }

        siblings
    }
}

/// Compute the hash of an internal node using domain separation (0x01 prefix).
fn compute_internal_hash<H: Hasher>(left: &[u8; 32], right: &[u8; 32], hasher: &H) -> [u8; 32] {
    let mut to_hash = Vec::with_capacity(1 + 32 + 32);
    to_hash.push(0x01);
    to_hash.extend_from_slice(left);
    to_hash.extend_from_slice(right);
    hasher.hash_bytes(&to_hash)
}

/// Compute the leaf hash using domain separation (0x00 prefix).
fn compute_leaf_hash<H: Hasher>(data: &[u8], hasher: &H) -> [u8; 32] {
    let mut to_hash = Vec::with_capacity(1 + data.len());
    to_hash.push(0x00);
    to_hash.extend_from_slice(data);
    hasher.hash_bytes(&to_hash)
}

/// Verify a Merkle proof without requiring access to the original tree.
///
/// This standalone function verifies that a leaf belongs to a Merkle tree
/// by recomputing the root hash using the proof's authentication path
/// and comparing it to the expected root.
///
/// # Arguments
///
/// * `leaf_data` - The raw data of the leaf being verified
/// * `proof` - The Merkle proof containing the leaf index and sibling hashes
/// * `expected_root` - The expected root hash of the tree
/// * `hasher` - The hasher to use for computing hashes
///
/// # Returns
///
/// `true` if the proof is valid (computed root matches expected root),
/// `false` otherwise.
///
/// # Security Properties
///
/// - Uses domain separation (0x00 for leaf, 0x01 for internal nodes)
/// - Uses constant-time comparison for root hash to prevent timing attacks
/// - Verification complexity is O(log n) hash operations
///
/// # Example
///
/// ```
/// use merkle_trees::merkle::simple_tree::verify_proof;
/// use merkle_trees::merkle::proof::Proof;
/// use merkle_trees::hasher::Sha256Hasher;
///
/// let hasher = Sha256Hasher::new();
/// let proof = Proof::new(0, vec![]);
/// let leaf_data = b"test";
/// let expected_root = [0u8; 32]; // placeholder
///
/// let is_valid = verify_proof(leaf_data, &proof, &expected_root, &hasher);
/// ```
pub fn verify_proof<H: Hasher>(
    leaf_data: &[u8],
    proof: &Proof,
    expected_root: &[u8; 32],
    hasher: &H,
) -> bool {
    // Compute the leaf hash with domain separation
    let mut current_hash = compute_leaf_hash(leaf_data, hasher);
    let mut index = proof.index();

    // Walk up the tree, combining with siblings
    for sibling in proof.siblings() {
        if index.is_multiple_of(2) {
            // Even index: current is left child, sibling is on right
            current_hash = compute_internal_hash(&current_hash, sibling, hasher);
        } else {
            // Odd index: current is right child, sibling is on left
            current_hash = compute_internal_hash(sibling, &current_hash, hasher);
        }
        // Advance to parent level
        index /= 2;
    }

    // Constant-time comparison to prevent timing attacks
    constant_time_compare(&current_hash, expected_root)
}

/// Constant-time byte array comparison to prevent timing attacks.
///
/// This function always compares all 32 bytes regardless of where a mismatch
/// occurs, preventing attackers from inferring hash values through timing analysis.
#[inline]
fn constant_time_compare(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0u8;
    for i in 0..32 {
        result |= a[i] ^ b[i];
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{Sha256Hasher, SimpleHasher};

    // =========================================================================
    // Basic Tree Tests
    // =========================================================================

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
    // Proof Generation Tests - Tree Sizes
    // =========================================================================

    #[test]
    fn test_prove_empty_tree_returns_invalid_index() {
        let tree: SimpleMerkleTree<SimpleHasher> = SimpleMerkleTree::new(SimpleHasher::new());
        let result = tree.prove(0);
        assert_eq!(
            result,
            Err(MerkleTreeError::InvalidIndex {
                index: 0,
                tree_size: 0
            })
        );
    }

    #[test]
    fn test_prove_single_leaf_returns_empty_siblings() {
        let mut tree = SimpleMerkleTree::new(SimpleHasher::new());
        tree.add_leaf(b"only").unwrap();

        let proof = tree.prove(0).unwrap();
        assert_eq!(proof.index(), 0);
        assert!(proof.siblings().is_empty());
    }

    #[test]
    fn test_prove_two_leaves_returns_one_sibling() {
        let mut tree = SimpleMerkleTree::new(SimpleHasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();

        let proof0 = tree.prove(0).unwrap();
        assert_eq!(proof0.siblings().len(), 1);

        let proof1 = tree.prove(1).unwrap();
        assert_eq!(proof1.siblings().len(), 1);
    }

    #[test]
    fn test_prove_three_leaves_returns_two_siblings() {
        let mut tree = SimpleMerkleTree::new(SimpleHasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();
        tree.add_leaf(b"c").unwrap();

        for i in 0..3 {
            let proof = tree.prove(i).unwrap();
            assert_eq!(proof.siblings().len(), 2);
        }
    }

    #[test]
    fn test_prove_four_leaves_returns_two_siblings() {
        let mut tree = SimpleMerkleTree::new(SimpleHasher::new());
        for data in [b"a", b"b", b"c", b"d"] {
            tree.add_leaf(data).unwrap();
        }

        for i in 0..4 {
            let proof = tree.prove(i).unwrap();
            assert_eq!(proof.siblings().len(), 2); // log2(4) = 2
        }
    }

    #[test]
    fn test_prove_eight_leaves_returns_three_siblings() {
        let mut tree = SimpleMerkleTree::new(SimpleHasher::new());
        for i in 0..8 {
            tree.add_leaf(&[i as u8]).unwrap();
        }

        for i in 0..8 {
            let proof = tree.prove(i).unwrap();
            assert_eq!(proof.siblings().len(), 3); // log2(8) = 3
        }
    }

    #[test]
    fn test_prove_invalid_index_returns_error() {
        let mut tree = SimpleMerkleTree::new(SimpleHasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();

        let result = tree.prove(2); // Index 2 is out of bounds for 2 leaves
        assert_eq!(
            result,
            Err(MerkleTreeError::InvalidIndex {
                index: 2,
                tree_size: 2
            })
        );
    }

    // =========================================================================
    // Proof Generation Tests - Edge Cases
    // =========================================================================

    #[test]
    fn test_prove_last_leaf_odd_tree_has_self_as_sibling() {
        let mut tree = SimpleMerkleTree::new(SimpleHasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();
        tree.add_leaf(b"c").unwrap();

        let leaf_hash = compute_leaf_hash(b"c", &SimpleHasher::new());
        let proof = tree.prove(2).unwrap();

        // At level 0, leaf 2's sibling is itself (duplicated)
        assert_eq!(proof.siblings()[0], leaf_hash);
    }

    #[test]
    fn test_prove_five_leaves_multi_level_duplication() {
        let mut tree = SimpleMerkleTree::new(SimpleHasher::new());
        for data in [b"a", b"b", b"c", b"d", b"e"] {
            tree.add_leaf(data).unwrap();
        }

        // For 5 leaves, index 4 has duplication at level 0
        let proof = tree.prove(4).unwrap();
        assert_eq!(proof.siblings().len(), 3); // ceil(log2(5)) = 3

        let leaf_hash = compute_leaf_hash(b"e", &SimpleHasher::new());
        // Level 0 sibling is the leaf's own hash (duplicated)
        assert_eq!(proof.siblings()[0], leaf_hash);
    }

    #[test]
    fn test_prove_all_left_path() {
        // Index 0 in an 8-leaf tree: all siblings on right
        let mut tree = SimpleMerkleTree::new(SimpleHasher::new());
        for i in 0..8 {
            tree.add_leaf(&[i as u8]).unwrap();
        }

        let proof = tree.prove(0).unwrap();

        // Verify the path is correct by checking siblings match
        // At each level, index 0 is even, so sibling is index 1
        let leaf1_hash = compute_leaf_hash(&[1u8], &SimpleHasher::new());
        assert_eq!(proof.siblings()[0], leaf1_hash);
    }

    #[test]
    fn test_prove_all_right_path() {
        // Index 7 in an 8-leaf tree: all siblings on left
        let mut tree = SimpleMerkleTree::new(SimpleHasher::new());
        for i in 0..8 {
            tree.add_leaf(&[i as u8]).unwrap();
        }

        let proof = tree.prove(7).unwrap();

        // At level 0, index 7 is odd, sibling is index 6
        let leaf6_hash = compute_leaf_hash(&[6u8], &SimpleHasher::new());
        assert_eq!(proof.siblings()[0], leaf6_hash);
    }

    #[test]
    fn test_siblings_ordered_leaf_to_root() {
        let mut tree = SimpleMerkleTree::new(SimpleHasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();
        tree.add_leaf(b"c").unwrap();
        tree.add_leaf(b"d").unwrap();

        let proof = tree.prove(0).unwrap();
        let hasher = SimpleHasher::new();

        // First sibling should be leaf 1's hash (sibling at level 0)
        let leaf1_hash = compute_leaf_hash(b"b", &hasher);
        assert_eq!(proof.siblings()[0], leaf1_hash);

        // Second sibling should be H(leaf2, leaf3) - sibling at level 1
        let leaf2_hash = compute_leaf_hash(b"c", &hasher);
        let leaf3_hash = compute_leaf_hash(b"d", &hasher);
        let level1_sibling = compute_internal_hash(&leaf2_hash, &leaf3_hash, &hasher);
        assert_eq!(proof.siblings()[1], level1_sibling);
    }

    // =========================================================================
    // Proof Verification Tests - Valid Cases
    // =========================================================================

    #[test]
    fn test_verify_valid_proof_round_trip() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"hello").unwrap();
        tree.add_leaf(b"world").unwrap();

        let root = tree.get_root_bytes().unwrap();

        // Generate and verify proof for each leaf
        for (i, data) in [b"hello".as_slice(), b"world".as_slice()]
            .iter()
            .enumerate()
        {
            let proof = tree.prove(i as u64).unwrap();
            assert!(tree.verify(&proof, data, &root));
        }
    }

    #[test]
    fn test_verify_single_leaf_tree() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"only").unwrap();

        let root = tree.get_root_bytes().unwrap();
        let proof = tree.prove(0).unwrap();

        assert!(tree.verify(&proof, b"only", &root));
    }

    #[test]
    fn test_verify_two_leaf_tree() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();

        let root = tree.get_root_bytes().unwrap();

        let proof0 = tree.prove(0).unwrap();
        assert!(tree.verify(&proof0, b"a", &root));

        let proof1 = tree.prove(1).unwrap();
        assert!(tree.verify(&proof1, b"b", &root));
    }

    #[test]
    fn test_verify_balanced_tree() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        for data in [b"a", b"b", b"c", b"d"] {
            tree.add_leaf(data).unwrap();
        }

        let root = tree.get_root_bytes().unwrap();

        for (i, data) in [b"a".as_slice(), b"b", b"c", b"d"].iter().enumerate() {
            let proof = tree.prove(i as u64).unwrap();
            assert!(tree.verify(&proof, data, &root));
        }
    }

    #[test]
    fn test_verify_odd_count_tree() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        for data in [b"a", b"b", b"c"] {
            tree.add_leaf(data).unwrap();
        }

        let root = tree.get_root_bytes().unwrap();

        for (i, data) in [b"a".as_slice(), b"b", b"c"].iter().enumerate() {
            let proof = tree.prove(i as u64).unwrap();
            assert!(tree.verify(&proof, data, &root));
        }
    }

    #[test]
    fn test_verify_five_leaves_multi_level_duplication() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        for data in [b"a", b"b", b"c", b"d", b"e"] {
            tree.add_leaf(data).unwrap();
        }

        let root = tree.get_root_bytes().unwrap();

        for (i, data) in [b"a".as_slice(), b"b", b"c", b"d", b"e"].iter().enumerate() {
            let proof = tree.prove(i as u64).unwrap();
            assert!(
                tree.verify(&proof, data, &root),
                "Failed for leaf {} at index {}",
                String::from_utf8_lossy(data),
                i
            );
        }
    }

    // =========================================================================
    // Proof Verification Tests - Security Rejection
    // =========================================================================

    #[test]
    fn test_verify_rejects_tampered_leaf() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"hello").unwrap();
        tree.add_leaf(b"world").unwrap();

        let root = tree.get_root_bytes().unwrap();
        let proof = tree.prove(0).unwrap();

        // Try to verify with wrong leaf data
        assert!(!tree.verify(&proof, b"TAMPERED", &root));
    }

    #[test]
    fn test_verify_rejects_wrong_root() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"hello").unwrap();
        tree.add_leaf(b"world").unwrap();

        let proof = tree.prove(0).unwrap();
        let wrong_root = [0xffu8; 32];

        assert!(!tree.verify(&proof, b"hello", &wrong_root));
    }

    #[test]
    fn test_verify_rejects_manipulated_index() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();

        let root = tree.get_root_bytes().unwrap();
        let proof = tree.prove(0).unwrap();

        // Create proof with wrong index but same siblings
        let tampered_proof = Proof::new(1, proof.siblings().to_vec());

        // Verifying "a" with index 1 should fail
        assert!(!tree.verify(&tampered_proof, b"a", &root));
    }

    #[test]
    fn test_verify_rejects_missing_siblings() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        for data in [b"a", b"b", b"c", b"d"] {
            tree.add_leaf(data).unwrap();
        }

        let root = tree.get_root_bytes().unwrap();
        let proof = tree.prove(0).unwrap();

        // Remove a sibling
        let truncated_siblings = vec![proof.siblings()[0]];
        let truncated_proof = Proof::new(0, truncated_siblings);

        assert!(!tree.verify(&truncated_proof, b"a", &root));
    }

    #[test]
    fn test_verify_rejects_extra_siblings() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();

        let root = tree.get_root_bytes().unwrap();
        let proof = tree.prove(0).unwrap();

        // Add an extra sibling
        let mut extended_siblings = proof.siblings().to_vec();
        extended_siblings.push([0xffu8; 32]);
        let extended_proof = Proof::new(0, extended_siblings);

        assert!(!tree.verify(&extended_proof, b"a", &root));
    }

    #[test]
    fn test_verify_rejects_cross_tree_proof() {
        let mut tree1 = SimpleMerkleTree::new(Sha256Hasher::new());
        tree1.add_leaf(b"a").unwrap();
        tree1.add_leaf(b"b").unwrap();

        let mut tree2 = SimpleMerkleTree::new(Sha256Hasher::new());
        tree2.add_leaf(b"x").unwrap();
        tree2.add_leaf(b"y").unwrap();

        let root1 = tree1.get_root_bytes().unwrap();
        let proof_from_tree2 = tree2.prove(0).unwrap();

        // Proof from tree2 should not verify against tree1's root
        assert!(!tree1.verify(&proof_from_tree2, b"x", &root1));
    }

    #[test]
    fn test_verify_rejects_corrupted_sibling() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"a").unwrap();
        tree.add_leaf(b"b").unwrap();

        let root = tree.get_root_bytes().unwrap();
        let proof = tree.prove(0).unwrap();

        // Corrupt a single bit in the sibling
        let mut corrupted_sibling = proof.siblings()[0];
        corrupted_sibling[0] ^= 0x01;
        let corrupted_proof = Proof::new(0, vec![corrupted_sibling]);

        assert!(!tree.verify(&corrupted_proof, b"a", &root));
    }

    // =========================================================================
    // Domain Separation Tests
    // =========================================================================

    #[test]
    fn test_domain_separation_leaf_vs_internal() {
        let hasher = Sha256Hasher::new();

        // Create data that looks like an internal node input
        let fake_internal_data = {
            let mut data = vec![0x01];
            data.extend_from_slice(&[0u8; 32]);
            data.extend_from_slice(&[0u8; 32]);
            data
        };

        let leaf_hash = compute_leaf_hash(&fake_internal_data, &hasher);
        let internal_hash = compute_internal_hash(&[0u8; 32], &[0u8; 32], &hasher);

        // Domain separation ensures these are different
        assert_ne!(leaf_hash, internal_hash);
    }

    #[test]
    fn test_prove_and_verify_use_consistent_domain_separation() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        tree.add_leaf(b"test").unwrap();
        tree.add_leaf(b"data").unwrap();

        let root = tree.get_root_bytes().unwrap();
        let proof = tree.prove(0).unwrap();

        // If domain separation were inconsistent, this would fail
        assert!(tree.verify(&proof, b"test", &root));
    }

    // =========================================================================
    // Index-Based Direction Tests
    // =========================================================================

    #[test]
    fn test_even_index_places_current_on_left() {
        let hasher = SimpleHasher::new();

        // For index 0, current should be on left, sibling on right
        let left = compute_leaf_hash(b"left", &hasher);
        let right = compute_leaf_hash(b"right", &hasher);
        let expected_parent = compute_internal_hash(&left, &right, &hasher);

        let proof = Proof::new(0, vec![right]);
        let mut current = left;
        let index = proof.index();

        if index % 2 == 0 {
            current = compute_internal_hash(&current, &proof.siblings()[0], &hasher);
        } else {
            current = compute_internal_hash(&proof.siblings()[0], &current, &hasher);
        }

        assert_eq!(current, expected_parent);
    }

    #[test]
    fn test_odd_index_places_current_on_right() {
        let hasher = SimpleHasher::new();

        // For index 1, current should be on right, sibling on left
        let left = compute_leaf_hash(b"left", &hasher);
        let right = compute_leaf_hash(b"right", &hasher);
        let expected_parent = compute_internal_hash(&left, &right, &hasher);

        let proof = Proof::new(1, vec![left]);
        let mut current = right;
        let index = proof.index();

        if index % 2 == 0 {
            current = compute_internal_hash(&current, &proof.siblings()[0], &hasher);
        } else {
            current = compute_internal_hash(&proof.siblings()[0], &current, &hasher);
        }

        assert_eq!(current, expected_parent);
    }

    #[test]
    fn test_index_advances_by_integer_division() {
        // Verify index / 2 at each level
        let mut index: u64 = 7;
        let expected_sequence = [7, 3, 1, 0]; // 7 / 2 = 3, 3 / 2 = 1, 1 / 2 = 0

        for expected in expected_sequence {
            assert_eq!(index, expected);
            index /= 2;
        }
    }

    // =========================================================================
    // Timing Attack Prevention Tests
    // =========================================================================

    #[test]
    fn test_constant_time_compare_equal() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        assert!(constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_first_byte_differs() {
        let a = [0x00u8; 32];
        let mut b = [0x00u8; 32];
        b[0] = 0x01;
        assert!(!constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_last_byte_differs() {
        let a = [0x00u8; 32];
        let mut b = [0x00u8; 32];
        b[31] = 0x01;
        assert!(!constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_all_bytes_differ() {
        let a = [0x00u8; 32];
        let b = [0xffu8; 32];
        assert!(!constant_time_compare(&a, &b));
    }

    // =========================================================================
    // Proof Structure Validation Tests
    // =========================================================================

    #[test]
    fn test_verify_empty_siblings_only_for_single_leaf() {
        let hasher = Sha256Hasher::new();
        let leaf_hash = compute_leaf_hash(b"only", &hasher);

        // Empty siblings is only valid when leaf hash equals root
        let proof = Proof::new(0, vec![]);
        assert!(verify_proof(b"only", &proof, &leaf_hash, &hasher));

        // Empty siblings with wrong root should fail
        assert!(!verify_proof(b"only", &proof, &[0xffu8; 32], &hasher));
    }

    #[test]
    fn test_wrong_sibling_count_detected_via_root() {
        let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());
        for data in [b"a", b"b", b"c", b"d"] {
            tree.add_leaf(data).unwrap();
        }

        let root = tree.get_root_bytes().unwrap();

        // Create proof with wrong number of siblings
        let wrong_proof = Proof::new(0, vec![[0u8; 32]]);

        // Verification fails because computed root won't match
        assert!(!tree.verify(&wrong_proof, b"a", &root));
    }

    // =========================================================================
    // Scalability Tests
    // =========================================================================

    #[test]
    fn test_proof_size_is_log_n() {
        // Verify proof size is ceil(log2(n)) for various tree sizes
        let test_cases = [
            (1, 0),  // log2(1) = 0
            (2, 1),  // log2(2) = 1
            (3, 2),  // ceil(log2(3)) = 2
            (4, 2),  // log2(4) = 2
            (5, 3),  // ceil(log2(5)) = 3
            (7, 3),  // ceil(log2(7)) = 3
            (8, 3),  // log2(8) = 3
            (9, 4),  // ceil(log2(9)) = 4
            (16, 4), // log2(16) = 4
        ];

        for (leaf_count, expected_siblings) in test_cases {
            let mut tree = SimpleMerkleTree::new(SimpleHasher::new());
            for i in 0..leaf_count {
                tree.add_leaf(&[i as u8]).unwrap();
            }

            let proof = tree.prove(0).unwrap();
            assert_eq!(
                proof.siblings().len(),
                expected_siblings,
                "Failed for {} leaves: expected {} siblings, got {}",
                leaf_count,
                expected_siblings,
                proof.siblings().len()
            );
        }
    }

    // =========================================================================
    // Standalone verify_proof Tests
    // =========================================================================

    #[test]
    fn test_verify_proof_standalone() {
        let hasher = Sha256Hasher::new();

        // Build a simple 2-leaf tree manually
        let leaf0 = compute_leaf_hash(b"a", &hasher);
        let leaf1 = compute_leaf_hash(b"b", &hasher);
        let root = compute_internal_hash(&leaf0, &leaf1, &hasher);

        // Create proof for leaf 0 (sibling is leaf 1)
        let proof = Proof::new(0, vec![leaf1]);

        // Verify without tree instance
        assert!(verify_proof(b"a", &proof, &root, &hasher));

        // Wrong leaf should fail
        assert!(!verify_proof(b"wrong", &proof, &root, &hasher));
    }
}

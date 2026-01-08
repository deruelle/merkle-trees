/// A Merkle proof for verifying membership of a leaf in a Merkle tree.
///
/// The proof contains the leaf index and an ordered list of sibling hashes
/// from the leaf level toward the root. The sibling position (left or right)
/// is inferred from the leaf index at each level using the algorithm:
/// - `index % 2 == 0` → left child (sibling on right)
/// - `index % 2 == 1` → right child (sibling on left)
/// - `index = index / 2` to advance to the next level
///
/// # Security Properties
///
/// - Proof size is O(log n) - at most ceil(log2(n)) sibling hashes
/// - Verification complexity is O(log n) hash operations
/// - Domain separation prevents second-preimage attacks
/// - Security relies on the hash function's collision and preimage resistance
///
/// # Example
///
/// ```
/// use merkle_trees::merkle::proof::Proof;
///
/// // Create a proof for leaf at index 3 with two siblings
/// let siblings = vec![[0u8; 32], [1u8; 32]];
/// let proof = Proof::new(3, siblings);
///
/// assert_eq!(proof.index(), 3);
/// assert_eq!(proof.siblings().len(), 2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The index of the leaf in the tree (0-based).
    /// Using u64 for platform-independent 64-bit support (up to 2^64 leaves).
    index: u64,
    /// Sibling hashes ordered from leaf level toward the root.
    /// Each hash is exactly 32 bytes.
    siblings: Vec<[u8; 32]>,
}

impl Proof {
    /// Create a new proof for a leaf at the given index with the specified siblings.
    ///
    /// # Arguments
    ///
    /// * `index` - The 0-based index of the leaf in the tree
    /// * `siblings` - Sibling hashes ordered from leaf level toward the root
    ///
    /// # Example
    ///
    /// ```
    /// use merkle_trees::merkle::proof::Proof;
    ///
    /// let siblings = vec![[0u8; 32]];
    /// let proof = Proof::new(0, siblings);
    /// ```
    pub fn new(index: u64, siblings: Vec<[u8; 32]>) -> Self {
        Proof { index, siblings }
    }

    /// Returns the index of the leaf this proof is for.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Returns the sibling hashes ordered from leaf level toward the root.
    pub fn siblings(&self) -> &[[u8; 32]] {
        &self.siblings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_creation() {
        let siblings = vec![[1u8; 32], [2u8; 32]];
        let proof = Proof::new(5, siblings.clone());

        assert_eq!(proof.index(), 5);
        assert_eq!(proof.siblings(), siblings.as_slice());
    }

    #[test]
    fn test_proof_empty_siblings() {
        let proof = Proof::new(0, vec![]);

        assert_eq!(proof.index(), 0);
        assert!(proof.siblings().is_empty());
    }

    #[test]
    fn test_proof_large_index() {
        // Test with index > 2^32 to verify u64 support
        let large_index: u64 = 5_000_000_000;
        let proof = Proof::new(large_index, vec![[0u8; 32]]);

        assert_eq!(proof.index(), large_index);
    }

    #[test]
    fn test_proof_clone() {
        let siblings = vec![[1u8; 32]];
        let proof = Proof::new(10, siblings);
        let cloned = proof.clone();

        assert_eq!(proof, cloned);
    }

    #[test]
    fn test_proof_equality() {
        let siblings1 = vec![[1u8; 32]];
        let siblings2 = vec![[1u8; 32]];
        let proof1 = Proof::new(5, siblings1);
        let proof2 = Proof::new(5, siblings2);

        assert_eq!(proof1, proof2);
    }

    #[test]
    fn test_proof_inequality_index() {
        let siblings = vec![[1u8; 32]];
        let proof1 = Proof::new(5, siblings.clone());
        let proof2 = Proof::new(6, siblings);

        assert_ne!(proof1, proof2);
    }

    #[test]
    fn test_proof_inequality_siblings() {
        let proof1 = Proof::new(5, vec![[1u8; 32]]);
        let proof2 = Proof::new(5, vec![[2u8; 32]]);

        assert_ne!(proof1, proof2);
    }

    #[test]
    fn test_proof_does_not_hold_tree_reference() {
        // Proof is a standalone struct that can outlive the tree
        // This test verifies the proof contains owned data
        let proof = {
            let siblings = vec![[1u8; 32], [2u8; 32]];
            Proof::new(0, siblings)
        };

        // Proof is still valid after siblings vector goes out of scope
        assert_eq!(proof.siblings().len(), 2);
    }
}

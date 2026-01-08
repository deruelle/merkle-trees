pub mod hash;
pub mod internal_node;
pub mod leaf_node;
pub mod node;
pub mod proof;
pub mod simple_tree;

// Re-exports for convenience
pub use crate::hasher::Hasher;
pub use hash::Hash;
pub use internal_node::InternalNode;
pub use leaf_node::LeafNode;
pub use node::Node;
pub use proof::Proof;
pub use simple_tree::SimpleMerkleTree;

/// A Merkle tree is a binary tree in which every leaf node
/// is labelled with a data block and every non-leaf node
/// is labelled with the cryptographic hash of the labels of its child nodes.
/// This design makes them extremely efficient for data verification.
///
/// # Invariants
/// * A leaf Node is raw data that gets hashed inside the Merkle tree.
/// * Domain separation:
///     * Leaves: H(0x00 || leaf_bytes)
///     * Internal nodes: H(0x01 || left_hash || right_hash)
/// * Dealing with Odd Numbers of Nodes:
///     * Duplicate the last hash
/// * Empty Input
///     * Return an Error
///
/// # Basics
/// * Level 0 (leaves, hashed): h0, h1, h2
/// * Level 1: H(h0, h1), H(h2, h2)
/// * Level 2 (Merkle root): H( H(h0,h1), H(h2,h2) )
///
/// A hash is 32 bytes and a level is a vector of hashes
///
pub trait MerkleTree<H: Hasher> {
    /// Add a leaf to the tree with the given data.
    fn add_leaf(&mut self, data: &[u8]) -> Result<(), MerkleTreeError>;

    /// Get the root hash of the tree as a hex string, or None if empty.
    fn get_root(&self) -> Option<String>;

    /// Get the root hash as raw bytes, or None if empty.
    fn get_root_bytes(&self) -> Option<[u8; 32]>;

    /// Get the data at the given leaf index.
    fn get_data(&self, index: u64) -> Option<&[u8]>;

    /// Get the number of leaves in the tree.
    fn get_size(&self) -> u64;

    /// Generate a membership proof for the leaf at the given index.
    ///
    /// Returns `MerkleTreeError::InvalidIndex` if the index is out of bounds
    /// or the tree is empty.
    ///
    /// # Complexity
    ///
    /// - Time: O(log n) to collect sibling hashes
    /// - Space: O(log n) for the proof
    fn prove(&self, index: u64) -> Result<Proof, MerkleTreeError>;

    /// Verify that a leaf with the given data belongs to a tree with the expected root.
    ///
    /// This method requires a proof to have been generated and stored on the tree.
    /// For standalone verification without a tree instance, use `verify_proof()`.
    fn verify(&self, proof: &Proof, leaf_data: &[u8], expected_root: &[u8; 32]) -> bool;
}

/// Errors that can occur when working with a Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleTreeError {
    /// The input data was empty.
    EmptyInput,
    /// The provided index is out of bounds for this tree.
    InvalidIndex {
        /// The index that was requested.
        index: u64,
        /// The number of leaves in the tree.
        tree_size: u64,
    },
}

impl std::fmt::Display for MerkleTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MerkleTreeError::EmptyInput => write!(f, "empty input is not allowed"),
            MerkleTreeError::InvalidIndex { index, tree_size } => {
                write!(
                    f,
                    "index {} is out of bounds for tree with {} leaves",
                    index, tree_size
                )
            }
        }
    }
}

impl std::error::Error for MerkleTreeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_error_display_empty_input() {
        let err = MerkleTreeError::EmptyInput;
        assert_eq!(err.to_string(), "empty input is not allowed");
    }

    #[test]
    fn test_merkle_tree_error_display_invalid_index() {
        let err = MerkleTreeError::InvalidIndex {
            index: 5,
            tree_size: 3,
        };
        assert_eq!(
            err.to_string(),
            "index 5 is out of bounds for tree with 3 leaves"
        );
    }

    #[test]
    fn test_merkle_tree_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(MerkleTreeError::EmptyInput);
        assert!(err.to_string().contains("empty input"));
    }
}

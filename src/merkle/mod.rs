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
pub use proof::{Proof, ProofError, ProofStep, SiblingPosition, verify_proof};
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
    fn add_leaf(&mut self, data: &[u8]) -> Result<(), MerkleTreeError>;
    fn get_root(&self) -> Option<String>;
    fn get_root_bytes(&self) -> Option<[u8; 32]>;
    fn get_data(&self, index: usize) -> Option<&[u8]>;
    fn get_size(&self) -> usize;
    fn prove(&self, index: usize) -> Result<Proof, MerkleTreeError>;
    fn verify(&self, proof: &Proof, expected_root: &[u8]) -> bool;
}

/// Errors that can occur when working with a Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleTreeError {
    /// The input data was empty
    EmptyInput,
    /// The requested index is out of bounds
    IndexOutOfBounds { index: usize, size: usize },
}

impl std::fmt::Display for MerkleTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MerkleTreeError::EmptyInput => write!(f, "empty input not allowed"),
            MerkleTreeError::IndexOutOfBounds { index, size } => {
                write!(f, "index {} out of bounds for tree of size {}", index, size)
            }
        }
    }
}

impl std::error::Error for MerkleTreeError {}

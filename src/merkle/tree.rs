use crate::hasher::Hasher;
use crate::merkle::MerkleTreeError;
use crate::merkle::proof::Proof;

/// A trait for Merkle trees. This trait is implemented by the `SimpleMerkleTree` struct.
pub trait Tree<H: Hasher> {
    fn add_leaf(&mut self, data: &[u8]) -> Result<(), MerkleTreeError>;
    fn get_data(&self, index: usize) -> Option<&[u8]>;
    fn get_size(&self) -> usize;
    fn get_root(&self) -> Option<String>;
    fn prove(&self, index: usize) -> Result<Proof, MerkleTreeError>;
    fn verify(&self, leaf: impl AsRef<[u8]>, root: &str) -> bool;
}

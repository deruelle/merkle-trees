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
pub trait MerkleTree {
    
}

pub struct AbstractMerkleTree {
    size: usize,
    leaves: Vec<Leaf>,
    levels: Vec<Vec<Node>>,
    root: Hash,
}

impl MerkleTree for AbstractMerkleTree {
    
}
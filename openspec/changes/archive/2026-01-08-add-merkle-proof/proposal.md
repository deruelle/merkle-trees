# Change: Add Merkle Proof Generation and Verification

## Why

The `MerkleTree` trait defines `prove()` and `verify()` methods, but they are currently unimplemented (`todo!()` stubs). Merkle proofs are the primary value proposition of Merkle trees - they enable O(log n) membership verification without revealing the entire dataset. Without this capability, the tree can only compute root hashes but cannot be used for its intended blockchain verification use cases (Bitcoin SPV proofs, Ethereum state verification, etc.).

## What Changes

- Enhance the `Proof` struct to include sibling hashes along the authentication path
- Implement `prove(index)` to generate a membership proof for a leaf at the given index
- Implement `verify(leaf, root)` to verify that a leaf is part of a tree with the given root
- Add a standalone `verify_proof()` function for verifying proofs without a tree instance
- Add comprehensive error handling for invalid indices and malformed proofs

## Impact

- Affected specs: `merkle-proof` (new capability)
- Affected code:
  - `src/merkle/proof.rs` - Enhanced `Proof` struct with sibling hashes
  - `src/merkle/simple_tree.rs` - Implement `prove()` and `verify()` methods
  - `src/merkle/mod.rs` - Potentially add `MerkleTreeError::InvalidIndex` variant
  - `src/lib.rs` - Re-export new types/functions

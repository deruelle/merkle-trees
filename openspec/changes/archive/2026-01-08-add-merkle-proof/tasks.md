# Tasks: Add Merkle Proof Generation and Verification

## 1. Enhance Proof Structure

- [x] 1.1 Update `Proof` struct in `src/merkle/proof.rs`:
  - Change `index` type from `usize` to `u64` (platform-independent 64-bit)
  - Add `siblings: Vec<[u8; 32]>` field
- [x] 1.2 Add constructor `Proof::new(index: u64, siblings)` and accessor methods
- [x] 1.3 Add `index()` and `siblings()` getters
- [x] 1.4 Add unit tests for `Proof` struct creation and access

## 2. Add Error Variant

- [x] 2.1 Add `InvalidIndex` variant to `MerkleTreeError` in `src/merkle/mod.rs`
- [x] 2.2 Implement `Display` and `Error` traits for better error messages

## 3. Update MerkleTree Trait

- [x] 3.1 Change `prove(index: usize)` to `prove(index: u64)` in trait definition
- [x] 3.2 Update any other index parameters to use `u64` for consistency

## 4. Implement Proof Generation

- [x] 4.1 Implement `prove(index: u64)` in `SimpleMerkleTree`
- [x] 4.2 Collect sibling hashes from leaf level to root (bottom-up)
- [x] 4.3 Handle edge case: single-leaf tree (empty sibling list)
- [x] 4.4 Handle edge case: index out of bounds returns `InvalidIndex`
- [x] 4.5 Handle edge case: empty tree returns `InvalidIndex`
- [x] 4.6 Handle odd leaf counts (duplicated node siblings)

## 5. Implement Proof Verification

- [x] 5.1 Add standalone `verify_proof(leaf, proof, root, hasher)` function in `src/merkle/simple_tree.rs`
- [x] 5.2 Implement index-based direction computation:
  - `index % 2 == 0` → left child (sibling on right)
  - `index % 2 == 1` → right child (sibling on left)
  - `index = index / 2` to advance level
- [x] 5.3 Ensure domain separation (0x00 for leaf hash, 0x01 for internal combination)
- [x] 5.4 Use constant-time comparison for root hash (timing attack prevention)
- [x] 5.5 Implement `verify(leaf, root)` in `SimpleMerkleTree` (delegates to `verify_proof`)
- [x] 5.6 Handle empty sibling list (single-leaf tree: leaf hash must equal root)

## 6. Test Suite: Proof Generation - Tree Sizes

- [x] 6.1 Test: empty tree (0 leaves) returns `InvalidIndex`
- [x] 6.2 Test: single-leaf tree (1 leaf) returns empty sibling list
- [x] 6.3 Test: two-leaf tree (2 leaves) returns 1 sibling
- [x] 6.4 Test: three-leaf tree (3 leaves) returns 2 siblings with duplication
- [x] 6.5 Test: power-of-2 tree (4 leaves) returns log2(n) siblings
- [x] 6.6 Test: power-of-2 tree (8 leaves) returns 3 siblings
- [x] 6.7 Test: odd-count tree (5 leaves) handles multi-level duplication
- [x] 6.8 Test: invalid index (>= tree size) returns error

## 7. Test Suite: Proof Generation - Edge Cases

- [x] 7.1 Test: last leaf in odd-count tree has self as sibling at level 0
- [x] 7.2 Test: multi-level duplication (5 leaves, index 4) - sibling = self at multiple levels
- [x] 7.3 Test: all-left path (index 0 in 8-leaf tree) - all siblings on right
- [x] 7.4 Test: all-right path (index 7 in 8-leaf tree) - all siblings on left
- [x] 7.5 Test: alternating path (index 5 in 8-leaf tree) - mixed directions
- [x] 7.6 Test: siblings are ordered from leaf level toward root

## 8. Test Suite: Proof Verification - Valid Cases

- [x] 8.1 Test: valid proof verifies successfully (round-trip)
- [x] 8.2 Test: single-leaf tree proof verifies (empty siblings, leaf = root)
- [x] 8.3 Test: two-leaf tree proof verifies
- [x] 8.4 Test: balanced tree (4 leaves) proof verifies
- [x] 8.5 Test: odd-count tree (3 leaves) proof verifies
- [x] 8.6 Test: multi-level duplication (5 leaves) proof verifies
- [x] 8.7 Test: all-left path proof verifies
- [x] 8.8 Test: all-right path proof verifies
- [x] 8.9 Test: alternating path proof verifies

## 9. Test Suite: Proof Verification - Security Rejection

- [x] 9.1 Test: tampered leaf data rejected
- [x] 9.2 Test: wrong root hash rejected
- [x] 9.3 Test: manipulated index in proof rejected
- [x] 9.4 Test: missing sibling(s) rejected
- [x] 9.5 Test: extra sibling(s) appended rejected
- [x] 9.6 Test: cross-tree proof rejected (proof from tree A vs root of tree B)
- [x] 9.7 Test: corrupted sibling hash (single bit flip) rejected

## 10. Test Suite: Domain Separation Security

- [x] 10.1 Test: leaf with data matching internal node pattern produces different hash
- [x] 10.2 Test: verification uses 0x00 prefix for leaf hash
- [x] 10.3 Test: verification uses 0x01 prefix for internal combination
- [x] 10.4 Test: prove and verify use identical domain separation logic

## 11. Test Suite: Timing Attack Prevention

- [x] 11.1 Implement constant-time byte comparison (or use `subtle` crate)
- [x] 11.2 Test: comparison iterates all 32 bytes regardless of mismatch position

## 12. Test Suite: Index-Based Direction Computation

- [x] 12.1 Test: even index (0, 2, 4) places current hash on left
- [x] 12.2 Test: odd index (1, 3, 5) places current hash on right
- [x] 12.3 Test: index advances by integer division (index / 2) each level
- [x] 12.4 Test: direction sequence matches expected path through tree

## 13. Test Suite: Proof Structure Validation

- [x] 13.1 Test: verify on empty tree returns false
- [x] 13.2 Test: empty sibling list only succeeds when leaf hash equals root
- [x] 13.3 Test: wrong sibling count produces root mismatch (detected via hash)
- [x] 13.4 Test: index exceeds implied tree size (k >= 2^m) - verification fails or uses truncated index

## 14. Test Suite: Scalability

- [x] 14.1 Test: u64 index handles values > 2^32 (e.g., 5_000_000_000)
- [x] 14.2 Test: proof size is ceil(log2(n)) siblings for various n
- [x] 14.3 Test: verification performs exactly ceil(log2(n)) hash operations
- [x] 14.4 Test: proof does not hold reference to tree (can outlive tree)

## 15. Documentation

- [x] 15.1 Document cryptographic assumptions in module docs:
  - Security relies on hash function collision resistance
  - Security relies on hash function preimage resistance
- [x] 15.2 Add rustdoc examples to `prove()` and `verify_proof()`
- [x] 15.3 Document O(log n) complexity guarantees

## 16. Integration and Exports

- [x] 16.1 Re-export `verify_proof` from `src/lib.rs`
- [x] 16.2 Add integration test: generate proof, serialize, deserialize, verify
- [x] 16.3 Add integration test: prove all leaves in tree, verify each

## 17. Validation

- [x] 17.1 Run `cargo test` - all tests pass
- [x] 17.2 Run `cargo clippy` - no warnings
- [x] 17.3 Run `cargo fmt` - code formatted
- [x] 17.4 Run `cargo doc` - documentation builds without warnings

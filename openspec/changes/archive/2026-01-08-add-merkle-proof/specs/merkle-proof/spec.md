# Merkle Proof Capability

## ADDED Requirements

### Requirement: Proof Structure

The system SHALL represent a Merkle proof as the leaf index and an ordered list of sibling hashes from the leaf level to the root. The sibling position (left or right) SHALL be inferred from the leaf index at each level.

#### Scenario: Proof contains authentication path

- **WHEN** a proof is generated for any leaf in a tree
- **THEN** the proof contains the leaf index and ceil(log2(n)) sibling hashes
- **AND** sibling hashes are ordered from leaf level toward the root

#### Scenario: Direction inferred from index

- **WHEN** verifying a proof at any level
- **THEN** the direction is computed as `index % 2`
- **AND** even index means left child (sibling on right)
- **AND** odd index means right child (sibling on left)

### Requirement: Scalability and Complexity

The system SHALL support trees with up to 2^64 leaves and guarantee O(log n) proof size and verification complexity.

#### Scenario: Index supports 64-bit range

- **WHEN** storing the leaf index in a proof
- **THEN** the index type SHALL be `u64` (not `usize`)
- **AND** this supports up to 18 quintillion (2^64) leaves regardless of platform

#### Scenario: Proof size is O(log n)

- **WHEN** a proof is generated for a tree with n leaves
- **THEN** the proof contains at most ceil(log2(n)) sibling hashes
- **AND** proof size grows logarithmically with tree size

#### Scenario: Verification complexity is O(log n)

- **WHEN** verifying a proof for a tree with n leaves
- **THEN** verification performs at most ceil(log2(n)) hash operations
- **AND** verification time grows logarithmically with tree size

#### Scenario: Memory-efficient proof structure

- **WHEN** a proof is created for a tree of any size
- **THEN** the proof memory footprint is O(log n)
- **AND** the proof does not store or reference the full tree

### Requirement: Proof Generation

The system SHALL generate a valid membership proof for any leaf in the tree by collecting sibling hashes from the leaf to the root.

#### Scenario: Generate proof for valid index

- **WHEN** `prove(index)` is called with a valid leaf index
- **THEN** the system returns a `Proof` containing the leaf index and sibling hashes
- **AND** the proof can be used to verify the leaf's membership

#### Scenario: Reject invalid index

- **WHEN** `prove(index)` is called with an index >= tree size
- **THEN** the system returns `MerkleTreeError::InvalidIndex`

#### Scenario: Reject proof on empty tree

- **WHEN** `prove(index)` is called on a tree with zero leaves
- **THEN** the system returns `MerkleTreeError::InvalidIndex`

#### Scenario: Single-leaf tree returns empty proof

- **WHEN** `prove(0)` is called on a tree with exactly one leaf
- **THEN** the system returns a proof with an empty sibling list
- **AND** the leaf hash equals the root hash

#### Scenario: Two-leaf tree baseline

- **WHEN** `prove(index)` is called on a tree with 2 leaves
- **THEN** the proof contains exactly 1 sibling hash
- **AND** the sibling is the other leaf's hash

#### Scenario: Balanced tree with no duplication

- **WHEN** `prove(index)` is called on a tree with power-of-2 leaves
- **THEN** the proof contains exactly log2(n) sibling hashes
- **AND** each sibling is a distinct node in the tree

#### Scenario: Odd leaf count with duplication

- **WHEN** `prove(index)` is called on a tree with an odd number of leaves
- **THEN** the proof correctly accounts for duplicated nodes
- **AND** the proof still verifies correctly

#### Scenario: Last leaf in odd-count tree has self as sibling

- **WHEN** `prove(n-1)` is called on a tree with odd n leaves
- **THEN** the sibling at level 0 is the same hash as the leaf itself
- **AND** this is due to the duplication rule for odd node counts

#### Scenario: Multi-level duplication (5 leaves)

- **WHEN** `prove(4)` is called on a tree with 5 leaves
- **THEN** level 0 sibling is the leaf's own hash (leaf 4 duplicated)
- **AND** level 1 sibling is the parent's own hash (node duplicated)
- **AND** the proof still verifies correctly

#### Scenario: All-left path (index 0)

- **WHEN** `prove(0)` is called on a balanced tree
- **THEN** the index path is all zeros (all even, all left children)
- **AND** every sibling is on the right

#### Scenario: All-right path (last index in power-of-2 tree)

- **WHEN** `prove(n-1)` is called on a tree with power-of-2 leaves
- **THEN** the index path is all ones at each level (all odd, all right children)
- **AND** every sibling is on the left

### Requirement: Proof Verification

The system SHALL verify that a leaf belongs to a Merkle tree by recomputing the root hash using the proof's authentication path and comparing it to the expected root.

#### Scenario: Verify valid proof

- **WHEN** `verify(leaf_data, expected_root)` is called with valid leaf data and proof
- **THEN** the system returns `true`

#### Scenario: Reject tampered leaf data

- **WHEN** verification is attempted with modified leaf data
- **THEN** the system returns `false`

#### Scenario: Reject wrong root

- **WHEN** verification is attempted with an incorrect root hash
- **THEN** the system returns `false`

#### Scenario: Reject proof with manipulated index

- **WHEN** a proof's index is modified before verification
- **THEN** verification returns `false`
- **AND** this prevents index manipulation attacks

#### Scenario: Reject proof with missing siblings

- **WHEN** a proof has one or more siblings removed
- **THEN** verification returns `false`

#### Scenario: Reject proof with extra siblings

- **WHEN** a proof has additional sibling hashes appended
- **THEN** verification returns `false`

#### Scenario: Reject cross-tree proof

- **WHEN** a proof generated from one tree is verified against a different tree's root
- **THEN** verification returns `false`

#### Scenario: Reject proof with corrupted sibling

- **WHEN** any sibling hash in the proof is modified
- **THEN** verification returns `false`

### Requirement: Standalone Proof Verification

The system SHALL provide a standalone verification function that can verify a proof without requiring access to the original tree, using only the leaf data, proof, expected root, and a hasher.

#### Scenario: Verify proof without tree instance

- **WHEN** `verify_proof(leaf_data, proof, expected_root, hasher)` is called
- **AND** the proof is valid for the leaf and root
- **THEN** the function returns `true`

#### Scenario: Domain separation in verification

- **WHEN** verifying a proof
- **THEN** the verifier uses 0x00 prefix when hashing the leaf
- **AND** the verifier uses 0x01 prefix when combining with sibling hashes

### Requirement: Index-Based Direction Computation

The system SHALL compute sibling direction at each level using the current index: if `index % 2 == 0`, the current node is a left child (sibling on right); if `index % 2 == 1`, the current node is a right child (sibling on left). The index advances via `index = index / 2` for the next level.

#### Scenario: Even index means left child

- **WHEN** the current index is even
- **THEN** the current hash is placed on the left
- **AND** parent hash is computed as `H(0x01 || current_hash || sibling_hash)`

#### Scenario: Odd index means right child

- **WHEN** the current index is odd
- **THEN** the current hash is placed on the right
- **AND** parent hash is computed as `H(0x01 || sibling_hash || current_hash)`

#### Scenario: Index advances by integer division

- **WHEN** moving from one level to the next
- **THEN** the index for the next level is `index / 2`
- **AND** this continues until reaching the root

### Requirement: Domain Separation Security

The system SHALL use domain separation prefixes to prevent second-preimage attacks where an attacker could construct leaf data that produces the same hash as an internal node.

#### Scenario: Leaf prefix prevents internal node collision

- **WHEN** an attacker crafts leaf data matching an internal node's input pattern
- **THEN** the 0x00 leaf prefix ensures a different hash than the 0x01 internal prefix
- **AND** the attack fails

#### Scenario: Consistent prefixes between prove and verify

- **WHEN** a proof is generated and then verified
- **THEN** both operations use identical domain separation logic
- **AND** any prefix mismatch would cause verification to fail

### Requirement: Timing Attack Prevention

The system SHALL use constant-time comparison when comparing computed root hashes to prevent timing side-channel attacks.

#### Scenario: Constant-time root comparison

- **WHEN** comparing the computed root hash against the expected root
- **THEN** the comparison takes the same amount of time regardless of where bytes differ
- **AND** this prevents attackers from inferring hash values through timing analysis

#### Scenario: No early exit on mismatch

- **WHEN** root hashes differ at an early byte position
- **THEN** the comparison continues through all 32 bytes
- **AND** execution time does not reveal the mismatch position

### Requirement: Cryptographic Assumptions

The system SHALL document that its security guarantees depend on the cryptographic properties of the underlying hash function.

#### Scenario: Collision resistance dependency

- **WHEN** the system is deployed
- **THEN** security relies on the hash function being collision-resistant
- **AND** a hash function break would compromise proof integrity

#### Scenario: Preimage resistance dependency

- **WHEN** an attacker attempts to forge a proof
- **THEN** they cannot find leaf data that produces a target hash
- **AND** this relies on the hash function's preimage resistance

### Requirement: Proof Structure Validation

The system SHALL validate proof structure consistency and handle edge cases gracefully.

#### Scenario: Verify on empty tree returns false

- **WHEN** `verify()` is called on a tree with zero leaves
- **THEN** the system returns `false`
- **AND** no proof can be valid for an empty tree

#### Scenario: Empty sibling list only valid for single leaf

- **WHEN** a proof has an empty sibling list
- **THEN** verification only succeeds if leaf hash equals expected root directly
- **AND** this corresponds to a single-leaf tree where leaf = root

#### Scenario: Sibling count mismatch detected via root

- **WHEN** a proof has incorrect number of siblings for the actual tree
- **THEN** the computed root will not match the expected root
- **AND** verification returns `false`

#### Scenario: Index exceeds implied tree size

- **WHEN** a proof has index k and m siblings
- **AND** k >= 2^m (index too large for tree height)
- **THEN** verification may return `false` or behave as if higher bits are zero
- **AND** the computed root will not match unless the proof was crafted for that index

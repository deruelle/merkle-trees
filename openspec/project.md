# Project Context

## Purpose

A Merkle tree implementation in Rust, used for learning the language through implementing a data structure widely used in blockchains like Bitcoin and Ethereum. The goal is to build a correct, efficient, and well-tested implementation while exploring Rust idioms and patterns.

## Tech Stack

- **Language**: Rust (2024 edition)
- **Cryptography**: `sha2` crate for SHA-256 hashing
- **Build Tools**: Cargo, with `mold` linker for faster builds
- **Testing**: Built-in Rust test framework, `cargo-watch` for development, `cargo-llvm-cov` for coverage

## Project Conventions

### Code Style

- Follow standard Rust formatting (`cargo fmt`)
- Use `cargo clippy` for linting with all warnings addressed
- Prefer `&[u8]` references over owned `String` for hash output to minimize allocations
- Use raw byte arrays `[u8; 32]` instead of hex strings internally for performance
- Document public APIs with rustdoc comments

### Architecture Patterns

**Strategy Pattern for Hashing**
- The `Hasher` trait (`src/hasher/mod.rs`) allows pluggable hash algorithms
- Two implementations: `Sha256Hasher` (production) and `SimpleHasher` (testing)
- Hashers return `[u8; 32]` arrays for performance

**Domain Separation for Security**
- Leaf nodes: `H(0x00 || leaf_bytes)`
- Internal nodes: `H(0x01 || left_hash || right_hash)`
- This prevents collision attacks where different tree structures could produce the same root

**Arc-based Tree Structure**
- Nodes use `Arc<Node>` to avoid deep copying during tree construction
- `InternalNode` stores left/right children as `Arc<Node>`
- The `Hash` trait returns `&[u8]` (not owned `String`) to eliminate cloning

**Trait-based API**
- `MerkleTree` trait defines the public interface: `add_leaf`, `get_root`, `prove`, `verify`
- `SimpleMerkleTree` is the concrete implementation
- Allows future alternative implementations

### Testing Strategy

- Unit tests co-located with source code in `#[cfg(test)]` modules
- Integration tests in `src/lib.rs` covering cross-module behavior
- Tests use `SimpleHasher` for fast, deterministic testing when cryptographic strength isn't needed
- Tests use `Sha256Hasher` when verifying real cryptographic properties
- Run all tests: `cargo test`
- Watch mode: `cargo watch -x check -x test`
- Coverage: `cargo llvm-cov`

### Git Workflow

- Main branch: `main`
- Feature branches named: `feature/<description>`
- Pull requests merged to main
- Pre-commit hooks for linting and formatting
- Commit messages should be descriptive and concise

## Domain Context

### Merkle Trees

A Merkle tree is a binary tree where:
- Every leaf node contains a data block hash
- Every internal node contains the hash of its children's hashes
- The root hash uniquely represents all data in the tree

**Key Properties:**
- Efficient verification: O(log n) proof size
- Tamper detection: Any data change propagates to the root
- Used in: Bitcoin (transaction verification), Ethereum (state tries), Git (content addressing)

**Tree Construction:**
1. Hash all leaf data with domain prefix (0x00)
2. For each level, pair nodes and hash with domain prefix (0x01)
3. If odd number of nodes, duplicate the last node
4. Continue until one node remains (the root)

**Membership Proofs:**
- A proof consists of sibling hashes along the path from leaf to root
- Verifier recomputes the root using the leaf and proof
- If computed root matches known root, leaf is in the tree

## Important Constraints

1. **Hash Size**: All hashes are exactly 32 bytes (`[u8; 32]`)
2. **Empty Input Rejection**: Empty data returns `MerkleTreeError::EmptyInput`
3. **Domain Separation**: Prefix bytes (0x00 for leaves, 0x01 for internal) are mandatory for security
4. **Odd Node Handling**: Duplicate the last node when there's an odd count at any level
5. **Determinism**: Same inputs must always produce the same root hash

## External Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `sha2` | 0.10 | SHA-256 cryptographic hashing |

No external services or APIs required.

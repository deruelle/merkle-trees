# Merkle Trees

[![Rust](https://github.com/deruelle/merkle-trees/actions/workflows/rust.yml/badge.svg)](https://github.com/deruelle/merkle-trees/actions/workflows/rust.yml)
[![codecov](https://codecov.io/github/deruelle/merkle-trees/graph/badge.svg?token=MR8IGAENDM)](https://codecov.io/github/deruelle/merkle-trees)

A production-quality Merkle tree implementation in Rust, built as a learning
project to explore the language through a data structure fundamental to
blockchain technology.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [How Merkle Trees Work](#how-merkle-trees-work)
- [Merkle Proofs](#merkle-proofs)
- [Architecture](#architecture)
- [Development](#development)
- [Contributing](#contributing)

## Features

- **Pluggable hash algorithms** via the `Hasher` trait (SHA-256 included)
- **Merkle proof generation and verification** for efficient data integrity checks
- **Domain separation** to prevent collision attacks
- **Memory-efficient design** using `Arc` for node sharing
- **Zero-copy hash access** for optimal performance

## Quick Start

```rust
use merkle_trees::{SimpleMerkleTree, MerkleTree, Sha256Hasher};

// Create a new tree with SHA-256 hashing
let mut tree = SimpleMerkleTree::new(Sha256Hasher::new());

// Add data to the tree
tree.add_leaf(b"transaction1")?;
tree.add_leaf(b"transaction2")?;
tree.add_leaf(b"transaction3")?;

// Get the Merkle root (hex string)
let root = tree.get_root();

// Generate a proof for a specific leaf (index 0)
let proof = tree.prove(0)?;

// Verify the proof against the expected root
let expected_root = tree.get_root_bytes().unwrap();
let is_valid = tree.verify(&proof, b"transaction1", &expected_root);
```

## How Merkle Trees Work

![merkle](https://upload.wikimedia.org/wikipedia/commons/9/95/Hash_Tree.svg)

A Merkle tree is a hash-based data structure where:

- Every **leaf node** contains hashed data
- Every **internal node** contains the hash of its children
- The **root hash** represents the entire dataset

A tree with *n* leaves has height log₂(n), making verification extremely efficient.

### Design Invariants

| Invariant        | Implementation                       |
| ---------------- | ------------------------------------ |
| Leaf hashing     | `H(0x00 \|\| data)`                  |
| Internal hashing | `H(0x01 \|\| left \|\| right)`       |
| Odd node count   | Duplicate the last node              |
| Empty input      | Return `MerkleTreeError::EmptyInput` |
| Hash size        | Always 32 bytes                      |

The domain separation prefixes (`0x00` for leaves, `0x01` for internal nodes)
prevent second-preimage attacks where different tree structures could produce
identical roots.

## Merkle Proofs

A **Merkle proof** (or inclusion proof) allows you to prove that specific data
exists in the tree **without revealing the entire tree**. You only need the
sibling hashes along the path from the leaf to the root — O(log n) hashes.

### Adding Data to the Tree

```mermaid
flowchart TD
    subgraph Input
        U[User] -->|Raw Data| A[Add to Merkle Tree]
    end

    subgraph Leaf Creation
        A --> B[Apply Domain Prefix]
        B -->|0x00 + data| C[Hash the Leaf]
        C --> D[Create LeafNode]
    end

    subgraph Tree Reconstruction
        D --> E{Odd number of nodes?}
        E -->|Yes| F[Duplicate last node]
        E -->|No| G[Pair nodes]
        F --> G
        G --> H[Hash pairs with 0x01 prefix]
        H --> I[Create InternalNodes]
        I --> J{Only one node left?}
        J -->|No| E
        J -->|Yes| K[Root Node]
    end

    subgraph Output
        K --> L[New Merkle Root]
        L --> M[Store/Publish Root]
    end
```

### When Proofs Are Needed

```mermaid
flowchart TD
    subgraph Data Owner
        A[Holds Complete Tree]
        A --> B[Publishes Only Root Hash]
    end

    subgraph Verifier
        C[Knows Only Root Hash]
        C --> D{Wants to verify: Is data X in the tree?}
    end

    D -->|Option 1: Inefficient| E[Download Entire Tree]
    D -->|Option 2: Efficient| F[Request Merkle Proof]

    E --> G[Wastes bandwidth: Slow, Storage heavy]

    F --> H[Receive Small Proof! ~640 bytes for 1M items]
    H --> I[Verify Locally]
    I --> J{Computed root matches known root?}
    J -->|Yes| K[Data IS in tree]
    J -->|No| L[Data NOT in tree]
```

### Blockchain Transaction Lifecycle

```mermaid
sequenceDiagram
    participant User
    participant FullNode as Full Node
    participant Blockchain
    participant LightWallet as Light Wallet

    Note over User,Blockchain: Phase 1: Adding Data

    User->>FullNode: Submit transaction
    FullNode->>FullNode: Add TX to mempool
    FullNode->>FullNode: Build Merkle tree from all TXs
    FullNode->>Blockchain: Publish block with Merkle Root

    Note over Blockchain,LightWallet: Phase 2: Verification

    LightWallet->>Blockchain: Download block headers only
    User->>LightWallet: Did my TX get confirmed?
    LightWallet->>FullNode: Request Merkle proof for TX
    FullNode->>FullNode: Generate proof with sibling hashes
    FullNode->>LightWallet: Return proof ~20 hashes
    LightWallet->>LightWallet: Verify proof against Merkle root
    LightWallet->>User: TX confirmed in block N
```

### Proof Structure

For a tree with 8 leaves, proving leaf "B" requires siblings along the path:

```mermaid
flowchart LR
    subgraph Tree Structure
        Root[Root H of H01+H23]
        H01[H01 H of HA+HB]
        H23[H23 H of HC+HD]
        HA[HA H of A]
        HB[HB H of B]
        HC[HC H of C]
        HD[HD H of D]

        Root --- H01
        Root --- H23
        H01 --- HA
        H01 --- HB
        H23 --- HC
        H23 --- HD
    end

    subgraph Proof for B
        P1[1. HA - sibling]
        P2[2. H23 - sibling]
        P3[positions: Left, Right]
    end

    subgraph Verification Steps
        V1[Hash B to get HB]
        V2[H of HA+HB gives H01]
        V3[H of H01+H23 gives Root]
        V4[Compare with known Root]

        V1 --> V2
        V2 --> V3
        V3 --> V4
    end
```

### Efficiency Comparison

```mermaid
flowchart TD
    subgraph Without Merkle Proofs
        A1[1 Million Transactions]
        A1 --> A2[Must download ALL\n~250 MB]
        A2 --> A3[Verify ONE transaction]
        A3 --> A4[O n data transfer]
    end

    subgraph With Merkle Proofs
        B1[1 Million Transactions]
        B1 --> B2[Download proof only\n~640 bytes]
        B2 --> B3[Verify ONE transaction]
        B3 --> B4[O log n data transfer]
    end

    subgraph Efficiency Gain
        C1[250 MB vs 640 bytes]
        C2[400,000x smaller]
        C1 --> C2
    end
```

### Real-World Example: Bitcoin SPV

```mermaid
flowchart TD
    subgraph Bitcoin Full Node
        FN1[Stores full blockchain 500 GB]
        FN2[Has all transactions]
        FN3[Builds Merkle trees]
    end

    subgraph Block Header - 80 bytes
        BH1[Previous Block Hash]
        BH2[Merkle Root]
        BH3[Timestamp + Difficulty + Nonce]
    end

    subgraph SPV Wallet - Phone
        SW1[Stores headers only 60 MB]
        SW2[Knows Merkle roots]
        SW3[Cannot verify TXs alone]
    end

    FN3 --> BH2
    BH2 --> SW2

    subgraph Verification Flow
        V1[User asks: Is my TX confirmed?]
        V2[Wallet requests proof]
        V3[Receives ~20 hashes]
        V4[Verifies against root]
        V5[Trustless verification]

        V1 --> V2 --> V3 --> V4 --> V5
    end

    SW3 --> V1
```

## Architecture

```text
src/
├── hasher/              # Pluggable hash algorithms
│   ├── mod.rs           # Hasher trait definition
│   ├── sha256.rs        # Production SHA-256 hasher
│   └── simple.rs        # Test hasher (for debugging)
├── merkle/              # Tree structure
│   ├── mod.rs           # Public API and MerkleTree trait
│   ├── hash.rs          # Hash trait (for types that have a hash)
│   ├── node.rs          # Node enum (Leaf or Internal)
│   ├── leaf_node.rs     # Leaf node (contains raw data)
│   ├── internal_node.rs # Internal node (has two children)
│   └── simple_tree.rs   # SimpleMerkleTree implementation
└── lib.rs               # Public API exports
```

### Key Design Decisions

- **Strategy pattern** for hashing allows swapping algorithms without changing
  tree logic
- **`Arc<Node>`** enables cheap cloning during tree reconstruction
- **Raw byte arrays** (`[u8; 32]`) instead of hex strings for memory efficiency
- **`&[u8]` returns** from hash methods eliminate unnecessary allocations

## Development

### Prerequisites

For faster linking times, install mold:

```bash
sudo apt-get install clang mold
```

### Build and Test

```bash
cargo build              # Build the project
cargo test               # Run all tests
cargo test test_name     # Run a specific test
```

### Watch Mode

```bash
cargo install cargo-watch
cargo watch -x check -x test
```

### Code Coverage

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
cargo llvm-cov           # Generate coverage report
```

## Contributing

This project uses [OpenSpec](https://github.com/deruelle/openspec) for
spec-driven development of new features.

### When to Create a Proposal

Create an OpenSpec proposal for:

- New features or capabilities
- Breaking changes to the API
- Architecture changes
- Performance optimizations that change behavior

Skip proposals for:

- Bug fixes
- Documentation updates
- Dependency updates (non-breaking)

### Workflow

1. Review existing specs: `openspec list --specs`
2. Check active changes: `openspec list`
3. Create a proposal in `openspec/changes/<change-id>/`
4. Get approval before implementing
5. Archive after deployment

See `openspec/AGENTS.md` for detailed instructions.

## License

MIT

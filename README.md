# Merkle Trees

## Status

[![Rust](https://github.com/deruelle/merkle-trees/actions/workflows/rust.yml/badge.svg)](https://github.com/deruelle/merkle-trees/actions/workflows/rust.yml)
[![codecov](https://codecov.io/github/deruelle/merkle-trees/graph/badge.svg?token=MR8IGAENDM)](https://codecov.io/github/deruelle/merkle-trees)

## Overview

Learning Rust through Implementation of Merkle Trees.
Merkle trees are widely used in blockchains, including Bitcoin and Ethereum.

## Representation

![merkle](https://upload.wikimedia.org/wikipedia/commons/9/95/Hash_Tree.svg)

Merkle trees are a hash-based tree data structure in which every leaf node
is labelled with a data block and every non-leaf node is labelled with
the cryptographic hash of the labels of its child nodes.

A Merkle tree of n leaves has a height of log₂(n)

This design makes them extremely efficient for data verification.

### Invariants

* A leaf Node is raw data that gets hashed inside the Merkle tree.
* Domain separation:
  * Leaves: H(0x00 || leaf_bytes)
  * Internal nodes: H(0x01 || left_hash || right_hash)
* Dealing with Odd Numbers of Nodes:
  * Duplicate the last hash
* Empty Input:
  * Return an Error

### Basics

* Level 0 (leaves, hashed): h0, h1, h2
* Level 1: H(h0, h1), H(h2, h2)
* Level 2 (Merkle root): H( H(h0,h1), H(h2,h2) )

A hash is 32 bytes and a level is a vector of hashes

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
        D --> E{Odd number\nof nodes?}
        E -->|Yes| F[Duplicate last node]
        E -->|No| G[Pair nodes]
        F --> G
        G --> H[Hash pairs with 0x01 prefix]
        H --> I[Create InternalNodes]
        I --> J{Only one\nnode left?}
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
        C --> D{Wants to verify:\nIs data X in the tree?}
    end

    D -->|Option 1: Inefficient| E[Download Entire Tree]
    D -->|Option 2: Efficient| F[Request Merkle Proof]

    E --> G[Wastes bandwidth\nSlow, Storage heavy]

    F --> H[Receive Small Proof\n~640 bytes for 1M items]
    H --> I[Verify Locally]
    I --> J{Computed root\nmatches known root?}
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
        Root[Root\nH of H01+H23]
        H01[H01\nH of HA+HB]
        H23[H23\nH of HC+HD]
        HA[HA\nH of A]
        HB[HB\nH of B]
        HC[HC\nH of C]
        HD[HD\nH of D]

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
        FN1[Stores full blockchain\n~500 GB]
        FN2[Has all transactions]
        FN3[Builds Merkle trees]
    end

    subgraph Block Header - 80 bytes
        BH1[Previous Block Hash]
        BH2[Merkle Root]
        BH3[Timestamp + Difficulty + Nonce]
    end

    subgraph SPV Wallet - Phone
        SW1[Stores headers only\n~60 MB]
        SW2[Knows Merkle roots]
        SW3[Cannot verify TXs alone]
    end

    FN3 --> BH2
    BH2 --> SW2

    subgraph Verification Flow
        V1[User asks:\nIs my TX confirmed?]
        V2[Wallet requests proof]
        V3[Receives ~20 hashes]
        V4[Verifies against root]
        V5[Trustless verification]

        V1 --> V2 --> V3 --> V4 --> V5
    end

    SW3 --> V1
```

## Configuration

### Linking

The project is configured to use mold linker for faster linking times via
`.cargo/config.toml`. The configuration uses `clang` with `-fuse-ld=mold` flag,
which allows mold to be used as the linker.

Install `mold` via:

```bash
sudo apt-get install clang mold
```

After installation, simply build your project normally:

```bash
cargo build
```

The mold linker will be used automatically for faster linking.

## Faster Inner Dev Loop

Install `cargo watch` via:

```bash
cargo install cargo-watch
```

Run locally with

```bash
cargo watch -x check -x test
```

### Code Coverage

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
```

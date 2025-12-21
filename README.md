[![Rust](https://github.com/deruelle/merkle-trees/actions/workflows/rust.yml/badge.svg)](https://github.com/deruelle/merkle-trees/actions/workflows/rust.yml)

# merkle-trees
Learning Rust through Implementation of Merkle Trees

# Notes
This project uses mold linker for faster linking times.

## Installation

Install `mold` via:
```bash
sudo apt-get install clang mold
```

## Configuration

### Linking

The project is configured to use mold linker via `.cargo/config.toml`. The configuration uses `clang` with `-fuse-ld=mold` flag, which allows mold to be used as the linker.

After installation, simply build your project normally:
```bash
cargo build
```

The mold linker will be used automatically for faster linking.

### Faster Inner Dev Loop

Install `cargo watch` via:
```bash
cargo install cargo-watch
```

Run with 
```bash
cargo watch -x check -x test
```

### Code Coverage

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
```
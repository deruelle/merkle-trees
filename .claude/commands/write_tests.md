# Write Tests

Write comprehensive tests for: $ARGUMENTS

## Arguments

- Module name (e.g., `merkle::simple_tree`)
- Function name (e.g., `add_leaf`)
- Feature description (e.g., "Merkle proof generation")

## Coverage Requirements

- Test happy paths (normal operation)
- Test edge cases (empty input, single element, boundary conditions)
- Test error states (invalid input, expected failures)
- Focus on testing behavior and public APIs rather than implementation details

## Project Testing Patterns

Follow the existing test patterns in this codebase:

### Test Organization

- Tests are co-located in modules using `#[cfg(test)]` blocks
- Test functions follow `test_<description>` naming convention
- Use both `SimpleHasher` (for fast, predictable tests) and `Sha256Hasher`
  (for production-like tests)

### Common Test Categories

Reference existing tests in `src/lib.rs` and module files:

1. **Creation/initialization tests**: `test_empty_tree`, `test_leaf_creation`
2. **Single item tests**: `test_single_leaf`
3. **Multiple item tests**: `test_multiple_leaves`
4. **Error handling tests**: `test_empty_data_rejected`
5. **Determinism tests**: `test_deterministic_root`, `test_same_data_same_hash`
6. **Security tests**: `test_domain_separation_leaf_vs_internal`
7. **Different hasher tests**: `test_different_hashers_produce_different_results`

### Test Structure Example

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{Sha256Hasher, SimpleHasher};

    #[test]
    fn test_feature_basic() {
        // Arrange
        let mut tree = SimpleMerkleTree::new(SimpleHasher::new());

        // Act
        tree.add_leaf(b"data").unwrap();

        // Assert
        assert_eq!(tree.get_size(), 1);
    }
}
```

## Future Considerations

Per CLAUDE.md, consider adding property-based tests using `proptest` or
`quickcheck` for testing invariants across random inputs.

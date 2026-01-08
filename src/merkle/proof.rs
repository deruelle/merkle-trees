use crate::hasher::Hasher;

/// Represents a sibling's position relative to the computed hash at each level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiblingPosition {
    /// Sibling is on the left; computed hash goes on the right
    Left,
    /// Sibling is on the right; computed hash goes on the left
    Right,
}

/// A single step in the proof path from leaf to root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStep {
    /// The sibling hash at this level
    pub sibling_hash: [u8; 32],
    /// Position of the sibling relative to the current computed hash
    pub position: SiblingPosition,
}

/// A Merkle inclusion proof.
///
/// Contains all information needed to verify that a leaf at a specific index
/// is part of a Merkle tree with a given root hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// Index of the leaf being proved (0-indexed)
    pub leaf_index: usize,
    /// Hash of the leaf (computed with 0x00 prefix)
    pub leaf_hash: [u8; 32],
    /// Sibling hashes from leaf level up to (but not including) the root
    pub steps: Vec<ProofStep>,
}

/// Errors that can occur when deserializing a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// Not enough bytes to parse the proof
    InsufficientData,
    /// Invalid position byte (not 0x00 or 0x01)
    InvalidPosition,
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofError::InsufficientData => write!(f, "insufficient data to parse proof"),
            ProofError::InvalidPosition => write!(f, "invalid position byte in proof"),
        }
    }
}

impl std::error::Error for ProofError {}

impl Proof {
    /// Serialize the proof to bytes.
    ///
    /// Format:
    /// - leaf_index: u64 (8 bytes, little-endian)
    /// - leaf_hash: [u8; 32] (32 bytes)
    /// - num_steps: u64 (8 bytes, little-endian)
    /// - For each step:
    ///   - sibling_hash: [u8; 32] (32 bytes)
    ///   - position: u8 (1 byte, 0x00 = Left, 0x01 = Right)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(48 + self.steps.len() * 33);
        bytes.extend_from_slice(&(self.leaf_index as u64).to_le_bytes());
        bytes.extend_from_slice(&self.leaf_hash);
        bytes.extend_from_slice(&(self.steps.len() as u64).to_le_bytes());
        for step in &self.steps {
            bytes.extend_from_slice(&step.sibling_hash);
            bytes.push(match step.position {
                SiblingPosition::Left => 0x00,
                SiblingPosition::Right => 0x01,
            });
        }
        bytes
    }

    /// Deserialize a proof from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        // Need at least 48 bytes for header (8 + 32 + 8)
        if bytes.len() < 48 {
            return Err(ProofError::InsufficientData);
        }

        let leaf_index = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
        let leaf_hash: [u8; 32] = bytes[8..40].try_into().unwrap();
        let num_steps = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;

        // Check we have enough bytes for all steps (33 bytes each)
        let expected_len = 48 + num_steps * 33;
        if bytes.len() < expected_len {
            return Err(ProofError::InsufficientData);
        }

        let mut steps = Vec::with_capacity(num_steps);
        let mut offset = 48;
        for _ in 0..num_steps {
            let sibling_hash: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
            let position = match bytes[offset + 32] {
                0x00 => SiblingPosition::Left,
                0x01 => SiblingPosition::Right,
                _ => return Err(ProofError::InvalidPosition),
            };
            steps.push(ProofStep {
                sibling_hash,
                position,
            });
            offset += 33;
        }

        Ok(Proof {
            leaf_index,
            leaf_hash,
            steps,
        })
    }
}

/// Verify a Merkle proof against an expected root hash.
///
/// This standalone function can verify a proof without access to the original tree.
/// The same hasher that was used to build the tree must be provided.
///
/// # Arguments
/// * `proof` - The proof to verify
/// * `expected_root` - The expected root hash (32 bytes)
/// * `hasher` - The hasher to use for computing internal node hashes
///
/// # Returns
/// `true` if the proof is valid (computed root matches expected root), `false` otherwise
pub fn verify_proof<H: Hasher>(proof: &Proof, expected_root: &[u8], hasher: &H) -> bool {
    // Root must be 32 bytes
    if expected_root.len() != 32 {
        return false;
    }

    let mut computed = proof.leaf_hash;

    for step in &proof.steps {
        // Internal node hash: H(0x01 || left || right)
        let mut to_hash = Vec::with_capacity(65);
        to_hash.push(0x01); // Internal node prefix

        match step.position {
            SiblingPosition::Left => {
                // Sibling is on left, computed goes on right
                to_hash.extend_from_slice(&step.sibling_hash);
                to_hash.extend_from_slice(&computed);
            }
            SiblingPosition::Right => {
                // Computed goes on left, sibling is on right
                to_hash.extend_from_slice(&computed);
                to_hash.extend_from_slice(&step.sibling_hash);
            }
        }

        computed = hasher.hash_bytes(&to_hash);
    }

    computed.as_slice() == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sibling_position_debug() {
        assert_eq!(format!("{:?}", SiblingPosition::Left), "Left");
        assert_eq!(format!("{:?}", SiblingPosition::Right), "Right");
    }

    #[test]
    fn test_proof_step_equality() {
        let step1 = ProofStep {
            sibling_hash: [1u8; 32],
            position: SiblingPosition::Left,
        };
        let step2 = ProofStep {
            sibling_hash: [1u8; 32],
            position: SiblingPosition::Left,
        };
        let step3 = ProofStep {
            sibling_hash: [2u8; 32],
            position: SiblingPosition::Left,
        };
        assert_eq!(step1, step2);
        assert_ne!(step1, step3);
    }

    #[test]
    fn test_proof_serialization_empty_steps() {
        let proof = Proof {
            leaf_index: 42,
            leaf_hash: [0xAB; 32],
            steps: vec![],
        };

        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 48); // 8 + 32 + 8

        let restored = Proof::from_bytes(&bytes).unwrap();
        assert_eq!(proof, restored);
    }

    #[test]
    fn test_proof_serialization_with_steps() {
        let proof = Proof {
            leaf_index: 5,
            leaf_hash: [0x11; 32],
            steps: vec![
                ProofStep {
                    sibling_hash: [0x22; 32],
                    position: SiblingPosition::Left,
                },
                ProofStep {
                    sibling_hash: [0x33; 32],
                    position: SiblingPosition::Right,
                },
            ],
        };

        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 48 + 2 * 33); // 48 + 66 = 114

        let restored = Proof::from_bytes(&bytes).unwrap();
        assert_eq!(proof, restored);
    }

    #[test]
    fn test_deserialize_insufficient_data() {
        let bytes = vec![0u8; 10]; // Too short
        assert_eq!(Proof::from_bytes(&bytes), Err(ProofError::InsufficientData));
    }

    #[test]
    fn test_deserialize_truncated_steps() {
        // Valid header claiming 2 steps, but only provide 1
        let mut bytes = vec![0u8; 48];
        bytes[40..48].copy_from_slice(&2u64.to_le_bytes()); // num_steps = 2
        bytes.extend_from_slice(&[0u8; 33]); // Only 1 step

        assert_eq!(Proof::from_bytes(&bytes), Err(ProofError::InsufficientData));
    }

    #[test]
    fn test_deserialize_invalid_position() {
        let proof = Proof {
            leaf_index: 0,
            leaf_hash: [0; 32],
            steps: vec![ProofStep {
                sibling_hash: [0; 32],
                position: SiblingPosition::Left,
            }],
        };
        let mut bytes = proof.to_bytes();
        // Corrupt the position byte (last byte)
        *bytes.last_mut().unwrap() = 0xFF;

        assert_eq!(Proof::from_bytes(&bytes), Err(ProofError::InvalidPosition));
    }

    #[test]
    fn test_proof_error_display() {
        assert_eq!(
            format!("{}", ProofError::InsufficientData),
            "insufficient data to parse proof"
        );
        assert_eq!(
            format!("{}", ProofError::InvalidPosition),
            "invalid position byte in proof"
        );
    }
}

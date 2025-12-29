mod sha256;
mod simple;

// Re-export implementations
pub use sha256::Sha256Hasher;
pub use simple::SimpleHasher;

/// A trait for hash algorithms (SHA256, Blake3, etc.).
///
/// This allows injecting different hashing implementations at runtime.
/// The hasher instance is passed to nodes so they can compute hashes.
pub trait Hasher {
    /// Hash raw bytes and return the result as a hex string.
    fn hash_bytes(&self, data: &[u8]) -> String;
}

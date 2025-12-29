mod sha256;
mod simple;

// Re-export implementations
pub use sha256::Sha256Hasher;
pub use simple::SimpleHasher;

/// A trait for hash algorithms (SHA256, Blake3, etc.).
///
/// This allows injecting different hashing implementations at compile time.
/// The trait uses associated functions (no `self`) because hashers are typically
/// stateless - they just transform bytes into a hash.
pub trait Hasher {
    /// Hash raw bytes and return the result as a hex string.
    fn hash_bytes(data: &[u8]) -> String;
}

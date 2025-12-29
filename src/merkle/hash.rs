/// A trait for types that have a hash value.
///
/// This is implemented by Node, LeafNode, and InternalNode
/// to retrieve their stored hash.
pub trait Hash {
    /// Return the hash of this item as a hex string.
    fn hash(&self) -> String;
}

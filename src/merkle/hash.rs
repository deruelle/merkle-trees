pub trait Hash {
    fn hash_leaf(&self) -> String;
    fn hash_node(&self) -> String;
}
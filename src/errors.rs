use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum MerkleError {
    // Returned when trying to insert a leaf in a full Merkle tree
    MerkleTreeFull(),
    // Insufficient height when building tree, with length of leaves as argument
    InsufficientHeight(usize),
    // Index out of bounds
    IndexOutOfBounds(usize),
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MerkleError::MerkleTreeFull() => write!(f, "Merkle tree is full"),
            MerkleError::InsufficientHeight(height) => write!(
                f,
                "Insufficient height for building tree with {} leaves",
                height
            ),
            MerkleError::IndexOutOfBounds(index) => {
                write!(f, "Querying out of bounds leaf at index {}", index)
            }
        }
    }
}

impl Error for MerkleError {}

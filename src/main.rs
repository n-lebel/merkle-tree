mod errors;
mod proof;
mod tree;

use crate::errors::MerkleError;
use sha2::Sha256;
use tree::*;

fn main() -> Result<(), MerkleError> {
    let tree = MerkleTree::<Sha256, 0>::from_data(vec![b"0".to_vec()])?;

    println!("{:x?}", tree);

    Ok(())
}

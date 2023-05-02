use sha2::Digest;
use std::marker::PhantomData;

use crate::errors::MerkleError;
use crate::proof::Proof;

#[derive(Clone, Debug)]
pub struct MerkleTree<H: Digest, const HEIGHT: u32> {
    leaves: Vec<Vec<u8>>,
    tree: Vec<Vec<u8>>,
    hasher: PhantomData<H>,
}

impl<H: Digest, const HEIGHT: u32> MerkleTree<H, HEIGHT> {
    pub fn from_data(leaves: Vec<Vec<u8>>) -> Result<Self, MerkleError> {
        // Check leaves don't exceed capacity
        if leaves.len() > 2_usize.pow(HEIGHT) {
            return Err(MerkleError::InsufficientHeight(leaves.len()));
        }

        Ok(Self {
            leaves: leaves.clone(),
            tree: Self::build_tree(leaves),
            hasher: PhantomData,
        })
    }

    pub fn insert(&mut self, value: &[u8]) -> Result<(), MerkleError> {
        // Check whether tree is full
        if self.leaves.len() == 2_usize.pow(HEIGHT) {
            return Err(MerkleError::MerkleTreeFull());
        }

        // insert the value in the leaves vec
        self.leaves.push(value.to_vec());

        // insert the value hash in the first level of the tree
        let mut index = self.leaves.len() - 1;
        self.tree[index] = Self::hash(value);

        let mut offset = 0;

        // change only the appropriate node hashes within the tree
        for i in 0..HEIGHT {
            let current_hash = if index % 2 == 0 {
                Self::hash_pair(&self.tree[offset + index], &self.tree[offset + index + 1])
            } else {
                Self::hash_pair(&self.tree[offset + index - 1], &self.tree[offset + index])
            };

            index = index / 2;
            offset = offset + 2_usize.pow(HEIGHT - i);
            self.tree[offset + index] = current_hash;
        }

        Ok(())
    }

    pub fn get_proof(&self, mut index: usize) -> Result<Proof<H>, MerkleError> {
        if index >= self.leaves.len() {
            return Err(MerkleError::IndexOutOfBounds(index));
        }

        let mut lemma = Vec::with_capacity(HEIGHT as usize);
        let mut path = Vec::with_capacity(HEIGHT as usize);
        let mut offset = 0;

        for i in 0..HEIGHT {
            // Sibling node and position: right --> true, left --> false
            let (sibling_hash, pos) = if index % 2 == 0 {
                (self.tree[offset + index + 1].clone(), true)
            } else {
                (self.tree[offset + index - 1].clone(), false)
            };

            lemma.push(sibling_hash);
            path.push(pos);

            index = index / 2;
            offset = offset + 2_usize.pow(HEIGHT - i);
        }

        Ok(Proof::<H>::new(lemma, path))
    }

    pub fn root(&self) -> Option<&[u8]> {
        self.tree.last().map(AsRef::as_ref)
    }

    pub fn get_value(&self, index: usize) -> Option<&[u8]> {
        self.leaves.get(index).map(AsRef::as_ref)
    }

    fn hash(data: &[u8]) -> Vec<u8> {
        H::digest(data).to_vec()
    }

    fn hash_pair(left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut hasher = H::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().to_vec()
    }

    fn build_tree(leaves: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut tree = Vec::with_capacity(2_usize.pow(HEIGHT + 1));

        // Compute leaf hashes
        let mut hashes = leaves
            .iter()
            .map(|d| Self::hash(d))
            .collect::<Vec<Vec<u8>>>();
        println!("{:x?}", hashes);
        // Pad the hashed leaves with zero hashes
        hashes.extend(vec![
            H::digest(b"0").to_vec();
            2_usize.pow(HEIGHT) - leaves.len()
        ]);
        println!("{:x?}", hashes);

        tree.extend(hashes.clone());

        for h in 0..HEIGHT {
            let mut next_layer = Vec::with_capacity(2_usize.pow(HEIGHT - h - 1));

            for i in (0..hashes.len()).step_by(2) {
                let hash_pair_result = Self::hash_pair(&hashes[i], &hashes[i + 1]);
                next_layer.push(hash_pair_result);
            }

            tree.extend(next_layer.clone());
            hashes = next_layer;
        }

        tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    const TEST_TREE_HEIGHT: u32 = 2;

    fn sample_leaves() -> Vec<Vec<u8>> {
        vec![b"apple".to_vec(), b"banana".to_vec(), b"cherry".to_vec()]
    }

    #[test]
    fn test_from_data() {
        let leaves = sample_leaves();
        let tree = MerkleTree::<Sha256, TEST_TREE_HEIGHT>::from_data(leaves.clone()).unwrap();
        assert_eq!(tree.leaves, leaves);
    }

    #[test]
    fn test_from_data_insufficient_height() {
        let mut leaves = sample_leaves();
        leaves.extend(vec![b"extra".to_vec(), b"extra".to_vec()]);
        let result = MerkleTree::<Sha256, TEST_TREE_HEIGHT>::from_data(leaves);
        assert!(matches!(result, Err(MerkleError::InsufficientHeight(_))));
    }

    #[test]
    fn test_insert() {
        let leaves = sample_leaves();
        let mut tree = MerkleTree::<Sha256, TEST_TREE_HEIGHT>::from_data(leaves.clone()).unwrap();
        assert!(tree.insert(b"extra").is_ok());
        assert_eq!(tree.leaves.len(), 4);
    }

    #[test]
    fn test_insert_tree_full() {
        let leaves = vec![vec![0u8; 32]; 2_usize.pow(TEST_TREE_HEIGHT)];
        let mut tree = MerkleTree::<Sha256, TEST_TREE_HEIGHT>::from_data(leaves).unwrap();
        assert!(matches!(
            tree.insert(b"extra"),
            Err(MerkleError::MerkleTreeFull())
        ));
    }

    #[test]
    fn test_get_root() {
        let leaves = sample_leaves();
        let tree = MerkleTree::<Sha256, TEST_TREE_HEIGHT>::from_data(leaves).unwrap();
        assert!(tree.root().is_some());
    }

    #[test]
    fn test_get_value() {
        let leaves = sample_leaves();
        let tree = MerkleTree::<Sha256, TEST_TREE_HEIGHT>::from_data(leaves.clone()).unwrap();
        assert_eq!(tree.get_value(0), Some(leaves[0].as_ref()));
        assert_eq!(tree.get_value(1), Some(leaves[1].as_ref()));
        assert_eq!(tree.get_value(2), Some(leaves[2].as_ref()));
        assert_eq!(tree.get_value(3), None);
    }
}

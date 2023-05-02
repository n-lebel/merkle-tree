use sha2::Digest;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct Proof<H: Digest> {
    pub lemma: Vec<Vec<u8>>,
    pub path: Vec<bool>,
    hasher: PhantomData<H>,
}

impl<H: Digest> Proof<H> {
    pub fn new(lemma: Vec<Vec<u8>>, path: Vec<bool>) -> Self {
        Self {
            lemma,
            path,
            hasher: PhantomData,
        }
    }

    pub fn verify(&self, root: &[u8], key: &[u8]) -> bool {
        if self.lemma.len() == 0 {
            return false;
        }

        let mut current_hash = H::digest(key).to_vec();
        for (proof_hash, position) in self.lemma.iter().zip(self.path.iter()) {
            current_hash = if *position {
                Self::hash_pair(&current_hash, &proof_hash)
            } else {
                Self::hash_pair(&proof_hash, &current_hash)
            };
        }

        if current_hash.iter().eq(root.iter()) {
            return true;
        }

        false
    }

    fn hash_pair(left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut hasher = H::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    fn generate_correct_proof() -> (Proof<Sha256>, Vec<u8>, Vec<u8>) {
        let proof = Proof::<Sha256>::new(
            vec![
                vec![
                    75, 245, 18, 47, 52, 69, 84, 197, 59, 222, 46, 187, 140, 210, 183, 227, 209,
                    96, 10, 214, 49, 195, 133, 165, 215, 204, 226, 60, 119, 133, 69, 154,
                ],
                vec![
                    209, 115, 79, 241, 216, 102, 116, 137, 81, 135, 62, 94, 133, 51, 44, 182, 227,
                    254, 141, 152, 99, 1, 125, 142, 255, 243, 180, 154, 65, 164, 208, 251,
                ],
            ],
            vec![false, true],
        );

        let key = vec![2];
        let root = vec![
            26, 92, 39, 190, 48, 181, 74, 43, 196, 41, 15, 137, 20, 110, 178, 79, 251, 236, 25,
            136, 120, 180, 15, 87, 149, 137, 238, 153, 90, 190, 171, 201,
        ];

        (proof, key, root)
    }

    fn generate_incorrect_proof() -> (Proof<Sha256>, Vec<u8>, Vec<u8>) {
        let proof = Proof::<Sha256>::new(
            vec![
                vec![
                    95, 236, 235, 102, 255, 200, 111, 56, 217, 82, 120, 108, 109, 105, 108, 121,
                    194, 219, 194, 57, 221, 78, 145, 180, 103, 41, 215, 58, 39, 251, 87, 233,
                ],
                vec![
                    66, 219, 238, 180, 235, 93, 65, 187, 220, 147, 115, 44, 106, 135, 171, 50, 65,
                    238, 3, 244, 74, 7, 128, 165, 45, 223, 131, 31, 95, 216, 139, 83,
                ],
            ],
            vec![false, true],
        );

        let key = vec![2];
        let root = vec![
            26, 92, 39, 190, 48, 181, 74, 43, 196, 41, 15, 137, 20, 110, 178, 79, 251, 236, 25,
            136, 120, 180, 15, 87, 149, 137, 238, 153, 90, 190, 171, 201,
        ];

        (proof, key, root)
    }

    #[test]
    fn test_correct_proof() {
        let (proof, key, root) = generate_correct_proof();
        
        assert!(proof.verify(&root, &key));
    }

    #[test]
    fn test_incorrect_proof() {
        let (proof, key, root) = generate_incorrect_proof();
        
        assert!(!proof.verify(&root, &key));
    }

    #[test]
    fn test_malformed_proof() {
        let (_, key, root) = generate_incorrect_proof();
        let proof = Proof::<Sha256>::new(vec![vec![]], vec![]);

        assert!(!proof.verify(&key, &root));
    }
}

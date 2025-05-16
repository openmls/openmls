use std::collections::HashMap;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, CryptoError},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::ciphersuite::Secret;

#[derive(Debug, Error)]
pub enum PprfError {
    #[error("Index out of bounds")]
    IndexOutOfBounds,
    #[error("Evaluating on punctured input")]
    PuncturedInput,
    #[error("Error deriving child node: {0}")]
    ChildDerivationError(#[from] CryptoError),
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
struct PprfNode(Secret);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Prefix {
    bits: Vec<u8>, // bit-packed
    len: usize,
}

impl Prefix {
    fn new() -> Self {
        Prefix {
            bits: vec![],
            len: 0,
        }
    }

    fn push_bit(&mut self, bit: bool) {
        if self.len % 8 == 0 {
            self.bits.push(0);
        }
        if bit {
            let byte_index = self.len / 8;
            let bit_index = 7 - (self.len % 8);
            self.bits[byte_index] |= 1 << bit_index;
        }
        self.len += 1;
    }
}

impl PprfNode {
    fn derive_child(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        context: &[u8],
    ) -> Result<Self, CryptoError> {
        let secret = self.0.kdf_expand_label(
            crypto,
            ciphersuite,
            "tree",
            context,
            ciphersuite.hash_length(),
        )?;
        Ok(Self(secret))
    }

    fn derive_children(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<(Self, Self), CryptoError> {
        let left_child = self.derive_child(crypto, ciphersuite, b"left")?;
        let right_child = self.derive_child(crypto, ciphersuite, b"right")?;
        Ok((left_child, right_child))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
pub(super) struct Pprf {
    #[serde(
        serialize_with = "serialize_hashmap",
        deserialize_with = "deserialize_hashmap"
    )]
    nodes: HashMap<(Prefix, usize), PprfNode>, // Mapping of prefix and depth to node
    /// The number of bytes in the secret.
    width: usize,
}

fn get_bit(index: &[u8], bit_index: usize) -> bool {
    let byte = index[bit_index / 8];
    let bit = 7 - (bit_index % 8); // big-endian
    (byte >> bit) & 1 == 1
}

impl Pprf {
    pub fn new(secret: Secret) -> Self {
        let width = secret.as_slice().len();
        Pprf {
            // The width of the tree in bytes.
            width,
            nodes: [((Prefix::new(), 0), PprfNode(secret))].into(),
        }
    }

    fn max_depth(&self) -> usize {
        self.width * 8
    }

    pub fn evaluate(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        input: &[u8],
    ) -> Result<Secret, PprfError> {
        if input.len() > self.width {
            return Err(PprfError::IndexOutOfBounds);
        }

        // We interpret the input as a bit string indexing the leaf in our tree.
        let leaf_index = input;

        let mut prefix = Prefix::new();
        let mut current_node;
        let mut depth = 0;

        // Step 1: Find the deepest existing node in the cache
        loop {
            let key = (prefix.clone(), depth);

            if let Some(node) = self.nodes.remove(&key) {
                if depth == self.max_depth() {
                    return Ok(node.0);
                } // already at leaf
                current_node = node;
                break;
            }

            // If we reach the max depth and we didn't find a node, then
            // the PPRF was already punctured at this index.
            if depth == self.max_depth() {
                return Err(PprfError::PuncturedInput);
            }

            let bit = get_bit(&leaf_index, depth);
            prefix.push_bit(bit);
            depth += 1;
        }

        // Step 2: Derive and walk the rest of the path
        for d in depth..self.max_depth() {
            let (left, right) = current_node.derive_children(crypto, ciphersuite).unwrap();
            let bit = get_bit(&leaf_index, d);

            let (next_node, copath_node) = if bit { (right, left) } else { (left, right) };

            let mut copath_prefix = prefix.clone();
            copath_prefix.push_bit(!bit);
            self.nodes
                .insert((copath_prefix.clone(), d + 1), copath_node);

            current_node = next_node;
            prefix.push_bit(bit);
        }

        Ok(current_node.0)
    }
}

fn serialize_hashmap<'a, T, U, V, S>(v: &'a V, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    U: Serialize,
    &'a V: IntoIterator<Item = (T, U)> + 'a,
    S: Serializer,
{
    let vec = v.into_iter().collect::<Vec<_>>();
    vec.serialize(serializer)
}

fn deserialize_hashmap<'de, T, U, D>(deserializer: D) -> Result<HashMap<T, U>, D::Error>
where
    T: Eq + std::hash::Hash + Deserialize<'de>,
    U: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Ok(Vec::<(T, U)>::deserialize(deserializer)?
        .into_iter()
        .collect::<HashMap<T, U>>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_test::openmls_test;
    use rand::{
        rngs::{OsRng, StdRng},
        Rng, SeedableRng,
    };

    fn random_vec(rng: &mut impl Rng, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    fn dummy_secret(rng: &mut impl Rng, ciphersuite: Ciphersuite) -> Secret {
        Secret::from_slice(&random_vec(rng, ciphersuite.hash_length()))
    }

    fn dummy_index(rng: &mut impl Rng, ciphersuite: Ciphersuite) -> Vec<u8> {
        random_vec(rng, ciphersuite.hash_length())
    }

    #[openmls_test]
    fn evaluates_single_path() {
        let seed: [u8; 32] = OsRng.gen();
        println!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let root_secret = dummy_secret(&mut rng, ciphersuite);
        let mut pprf = Pprf::new(root_secret);
        let index = dummy_index(&mut rng, ciphersuite);
        let crypto = provider.crypto();

        let result = pprf.evaluate(crypto, ciphersuite, &index);
        assert!(result.is_ok());
        assert_eq!(result.as_ref().unwrap().as_slice().len(), 32);
        assert_eq!(pprf.nodes.len(), 256);
    }

    #[openmls_test]
    fn re_evaluation_of_same_index_returns_error() {
        let seed: [u8; 32] = OsRng.gen();
        println!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let root_secret = dummy_secret(&mut rng, ciphersuite);
        let mut pprf = Pprf::new(root_secret);
        let index = dummy_index(&mut rng, ciphersuite);
        let crypto = provider.crypto();

        let _first = pprf.evaluate(crypto, ciphersuite, &index).unwrap();
        let second = pprf
            .evaluate(crypto, ciphersuite, &index)
            .expect_err("Evaluation on same input should fail");

        assert!(matches!(second, PprfError::PuncturedInput));
    }

    #[openmls_test]
    fn different_indices_produce_different_results() {
        let seed: [u8; 32] = OsRng.gen();
        println!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let root_secret = dummy_secret(&mut rng, ciphersuite);
        let mut pprf = Pprf::new(root_secret);
        let index1 = dummy_index(&mut rng, ciphersuite);
        let index2 = dummy_index(&mut rng, ciphersuite);
        let crypto = provider.crypto();

        let leaf1 = pprf.evaluate(crypto, ciphersuite, &index1).unwrap();
        let leaf2 = pprf.evaluate(crypto, ciphersuite, &index2).unwrap();

        assert_ne!(leaf1.as_slice(), leaf2.as_slice());
    }

    #[openmls_test]
    fn rejects_out_of_bounds_index() {
        let seed: [u8; 32] = OsRng.gen();
        println!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let root_secret = dummy_secret(&mut rng, ciphersuite);
        let mut pprf = Pprf::new(root_secret);
        let mut index = dummy_index(&mut rng, ciphersuite);
        let crypto = provider.crypto();
        index.push(0);

        let result = pprf.evaluate(crypto, ciphersuite, &index);
        assert!(matches!(result, Err(PprfError::IndexOutOfBounds)));
    }
}

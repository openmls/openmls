use std::collections::HashMap;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, CryptoError},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

use crate::{binary_tree::array_representation::TreeSize, ciphersuite::Secret};

use input::AsIndexBytes;
use prefix::Prefix;

pub use prefix::Prefix16;

mod input;
mod prefix;

#[derive(Debug, Clone, Error, PartialEq)]
pub enum PprfError {
    #[error("Index out of bounds")]
    IndexOutOfBounds,
    #[error("Evaluating on punctured input")]
    PuncturedInput,
    #[error("Error deriving child node: {0}")]
    ChildDerivationError(#[from] CryptoError),
}

#[derive(Debug, Serialize, Deserialize, Clone, ZeroizeOnDrop)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq))]
#[serde(transparent)]
struct PprfNode(#[serde(with = "serde_bytes")] Vec<u8>);

impl From<Secret> for PprfNode {
    fn from(secret: Secret) -> Self {
        Self(secret.as_slice().to_vec())
    }
}

impl From<PprfNode> for Secret {
    fn from(node: PprfNode) -> Self {
        Secret::from_slice(&node.0)
    }
}

impl PprfNode {
    fn derive_child(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        context: &[u8],
    ) -> Result<Self, CryptoError> {
        let secret = Secret::from_slice(&self.0);
        let secret = secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "tree",
            context,
            ciphersuite.hash_length(),
        )?;
        Ok(secret.into())
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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq))]
pub(crate) struct Pprf<P: Prefix> {
    #[serde(
        serialize_with = "serialize_hashmap",
        deserialize_with = "deserialize_hashmap"
    )]
    nodes: HashMap<P, PprfNode>, // Mapping of prefix and depth to node
    width: usize,
}

fn get_bit(index: &[u8], bit_index: usize) -> bool {
    let byte = index[bit_index / 8];
    let bit = 7 - (bit_index % 8); // big-endian
    (byte >> bit) & 1 == 1
}

impl<P: Prefix> Pprf<P> {
    pub(super) fn new_with_size(secret: Secret, size: TreeSize) -> Self {
        let width = size.leaf_count() as usize;
        Pprf {
            // The width of the tree in bytes.
            width,
            nodes: [(P::new(), PprfNode(secret.as_slice().to_vec()))].into(),
        }
    }

    #[cfg(test)]
    pub(super) fn new_for_test(secret: Secret) -> Self {
        let width = secret.as_slice().len();
        Pprf {
            // The width of the tree in bytes.
            width,
            nodes: [(P::new(), secret.into())].into(),
        }
    }

    pub(super) fn evaluate<Input: AsIndexBytes>(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        input: &Input,
    ) -> Result<Secret, PprfError> {
        let input = input.as_index_bytes();
        if input.len() > P::MAX_INPUT_LEN {
            return Err(PprfError::IndexOutOfBounds);
        }

        // We interpret the input as a bit string indexing the leaf in our tree.
        let leaf_index = input;

        let mut prefix = P::new();
        let mut current_node;
        let mut depth = 0;

        // Step 1: Find the deepest existing node in the cache
        loop {
            let key = prefix.clone();

            if let Some(node) = self.nodes.remove(&key) {
                if depth == P::MAX_DEPTH {
                    return Ok(node.into());
                } // already at leaf
                current_node = node;
                break;
            }

            // If we reach the max depth and we didn't find a node, then
            // the PPRF was already punctured at this index.
            if depth == P::MAX_DEPTH {
                return Err(PprfError::PuncturedInput);
            }

            let bit = get_bit(&leaf_index, depth);
            prefix.push_bit(bit);
            depth += 1;
        }

        // Step 2: Derive and walk the rest of the path
        for d in depth..P::MAX_DEPTH {
            let (left, right) = current_node.derive_children(crypto, ciphersuite).unwrap();
            let bit = get_bit(&leaf_index, d);

            let (next_node, copath_node) = if bit { (right, left) } else { (left, right) };

            let mut copath_prefix = prefix.clone();
            copath_prefix.push_bit(!bit);
            self.nodes.insert(copath_prefix.clone(), copath_node);

            current_node = next_node;
            prefix.push_bit(bit);
        }

        Ok(current_node.into())
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
    use openmls_traits::OpenMlsProvider;
    use prefix::{Prefix32, PrefixVec};
    use rand::{
        random,
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

    fn dummy_index<P: Prefix>(rng: &mut impl Rng) -> Vec<u8> {
        random_vec(rng, P::MAX_INPUT_LEN)
    }

    #[openmls_test]
    fn evaluates_single_path() {
        fn evaluate_single_path<P: Prefix>(
            ciphersuite: Ciphersuite,
            provider: &impl OpenMlsProvider,
        ) {
            let seed: [u8; 32] = OsRng.gen();
            println!("Seed: {:?}", seed);
            let mut rng = StdRng::from_seed(seed);
            let root_secret = dummy_secret(&mut rng, ciphersuite);
            let mut pprf = Pprf::<P>::new_for_test(root_secret);
            let index = dummy_index::<P>(&mut rng);
            let crypto = provider.crypto();

            let result = pprf.evaluate(crypto, ciphersuite, &index);
            assert!(result.is_ok());
            assert_eq!(result.as_ref().unwrap().as_slice().len(), 32);
        }

        evaluate_single_path::<PrefixVec>(ciphersuite, provider);
        evaluate_single_path::<Prefix32>(ciphersuite, provider);
    }

    #[openmls_test]
    fn re_evaluation_of_same_index_returns_error() {
        fn re_evaluation_of_same_index_returns_error<P: Prefix>(
            ciphersuite: Ciphersuite,
            provider: &impl OpenMlsProvider,
        ) {
            let seed: [u8; 32] = OsRng.gen();
            println!("Seed: {:?}", seed);
            let mut rng = StdRng::from_seed(seed);
            let root_secret = dummy_secret(&mut rng, ciphersuite);
            let mut pprf = Pprf::<P>::new_for_test(root_secret);
            let index = dummy_index::<P>(&mut rng);
            let crypto = provider.crypto();

            let first = pprf.evaluate(crypto, ciphersuite, &index).unwrap();
            let second = pprf
                .evaluate(crypto, ciphersuite, &index)
                .expect_err("Evaluation on same input should fail");

            assert!(matches!(second, PprfError::PuncturedInput));
        }
        re_evaluation_of_same_index_returns_error::<PrefixVec>(ciphersuite, provider);
        re_evaluation_of_same_index_returns_error::<Prefix32>(ciphersuite, provider);
    }

    #[openmls_test]
    fn different_indices_produce_different_results() {
        fn different_indices_produce_different_results<P: Prefix>(
            ciphersuite: Ciphersuite,
            provider: &impl OpenMlsProvider,
        ) {
            let seed: [u8; 32] = OsRng.gen();
            println!("Seed: {:?}", seed);
            let mut rng = StdRng::from_seed(seed);
            let root_secret = dummy_secret(&mut rng, ciphersuite);
            let mut pprf = Pprf::<P>::new_for_test(root_secret);
            let index1 = dummy_index::<P>(&mut rng);
            let index2 = dummy_index::<P>(&mut rng);
            let crypto = provider.crypto();

            let leaf1 = pprf.evaluate(crypto, ciphersuite, &index1).unwrap();
            let leaf2 = pprf.evaluate(crypto, ciphersuite, &index2).unwrap();

            assert_ne!(leaf1.as_slice(), leaf2.as_slice());
        }

        different_indices_produce_different_results::<PrefixVec>(ciphersuite, provider);
        different_indices_produce_different_results::<Prefix32>(ciphersuite, provider);
    }

    #[openmls_test]
    fn rejects_out_of_bounds_index() {
        fn rejects_out_of_bounds_index<P: Prefix>(
            ciphersuite: Ciphersuite,
            provider: &impl OpenMlsProvider,
        ) {
            let seed: [u8; 32] = OsRng.gen();
            println!("Seed: {:?}", seed);
            let mut rng = StdRng::from_seed(seed);
            let root_secret = dummy_secret(&mut rng, ciphersuite);
            let mut pprf = Pprf::<P>::new_for_test(root_secret);
            let index = random_vec(&mut rng, P::MAX_INPUT_LEN + 1); // Out of bounds

            let crypto = provider.crypto();

            let result = pprf.evaluate(crypto, ciphersuite, &index);
            assert!(matches!(result, Err(PprfError::IndexOutOfBounds)));
        }

        rejects_out_of_bounds_index::<PrefixVec>(ciphersuite, provider);
        rejects_out_of_bounds_index::<Prefix32>(ciphersuite, provider);
    }
}

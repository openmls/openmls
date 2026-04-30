//! # Puncturable Pseudorandom Function (PPRF) Implementation
//!
//! This module implements a PPRF using the same binary tree structure as the
//! secret tree. In contrast to the secret tree, this implementation is generic
//! over the size of the tree. Additionally, it is designed to be efficient even
//! for larger sizes.

use std::{borrow::Cow, collections::HashMap, fmt, marker::PhantomData};

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, CryptoError},
};
use serde::{
    de::{self, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    binary_tree::array_representation::TreeSize, ciphersuite::Secret,
    tree::secret_tree::derive_child_secrets,
};

use input::AsIndexBytes;
use prefix::Prefix;

pub use prefix::Prefix16;

mod input;
mod prefix;

/// Error evaluating the PPRF at the given input.
#[derive(Debug, Clone, Error, PartialEq)]
pub enum PprfError {
    /// Index out of bounds.
    #[error("Index out of bounds")]
    IndexOutOfBounds,
    /// Evaluating on punctured input.
    #[error("Evaluating on punctured input")]
    PuncturedInput,
    /// Error deriving child node.
    #[error("Error deriving child node: {0}")]
    ChildDerivationError(#[from] CryptoError),
}

/// A Node in the PPRF tree that contains the node's secret.
///
/// Implements transparent and custom serde for efficiently storing and reading secret bytes.
#[derive(Debug, Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq))]
struct PprfNode(Secret);

impl Serialize for PprfNode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(self.0.as_slice()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PprfNode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Some serialization formats do not support 0-copy deserialization of bytes, so we need to
        // support owned bytes as well.
        let bytes: Cow<[u8]> = serde_bytes::Deserialize::deserialize(deserializer)?;
        let secret = Secret::from_slice(bytes.as_ref());
        if let Cow::Owned(mut bytes) = bytes {
            bytes.zeroize() // Zeroize owned bytes to prevent leaking secrets.
        }
        Ok(Self(secret))
    }
}

impl PprfNode {
    /// Derives the left and right child nodes from the current node.
    fn derive_children(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<(Self, Self), CryptoError> {
        let own_secret = &self.0;
        let (left_secret, right_secret) = derive_child_secrets(own_secret, crypto, ciphersuite)?;
        Ok((Self(left_secret), Self(right_secret)))
    }
}

/// The PPRF containing the tree of nodes, where each node contains a secret. It
/// can be evaluated at a given input only once. The struct will grow in size
/// with each evaluation.
///
/// The struct is generic over the prefix, which determines how individual nodes
/// are indexed. As prefixes are stored alongside each node, small prefixes help
/// keep the overall tree small.
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

/// Get the bit in the given byte slice at the given index.
fn get_bit(index: &[u8], bit_index: usize) -> bool {
    let byte = index[bit_index / 8];
    let bit = 7 - (bit_index % 8); // big-endian
    (byte >> bit) & 1 == 1
}

impl<P: Prefix> Pprf<P> {
    /// Create a new PPRF with the given secret and size.
    pub(super) fn new_with_size(secret: Secret, size: TreeSize) -> Self {
        let width = size.leaf_count() as usize;
        Pprf {
            // The width of the tree in bytes.
            width,
            nodes: [(P::new(), PprfNode(secret))].into(),
        }
    }

    #[cfg(test)]
    pub(super) fn new_for_test(secret: Secret) -> Self {
        let width = secret.as_slice().len();
        Pprf {
            // The width of the tree in bytes.
            width,
            nodes: [(P::new(), PprfNode(secret))].into(),
        }
    }

    /// Evaluates the PPRF at the given input.
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
            if let Some(node) = self.nodes.remove(&prefix) {
                if depth == P::MAX_DEPTH {
                    return Ok(node.0);
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
            let node_at_copath_prefix = self.nodes.insert(copath_prefix.clone(), copath_node);
            debug_assert!(node_at_copath_prefix.is_none());

            current_node = next_node;
            prefix.push_bit(bit);
        }

        Ok(current_node.0)
    }
}

fn serialize_hashmap<T, U, S>(map: &HashMap<T, U>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    U: Serialize,
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(map.len()))?;
    for (k, v) in map {
        seq.serialize_element(&(k, v))?;
    }
    seq.end()
}

fn deserialize_hashmap<'de, T, U, D>(deserializer: D) -> Result<HashMap<T, U>, D::Error>
where
    T: Eq + std::hash::Hash + Deserialize<'de>,
    U: Deserialize<'de>,
    D: Deserializer<'de>,
{
    struct TupleSeqVisitor<T, U> {
        marker: PhantomData<(T, U)>,
    }

    impl<'de, T, U> Visitor<'de> for TupleSeqVisitor<T, U>
    where
        T: Eq + std::hash::Hash + Deserialize<'de>,
        U: Deserialize<'de>,
    {
        type Value = HashMap<T, U>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a sequence of tuples")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut map = HashMap::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some((k, v)) = seq.next_element::<(T, U)>()? {
                map.insert(k, v);
            }
            Ok(map)
        }
    }

    deserializer.deserialize_seq(TupleSeqVisitor {
        marker: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_test::openmls_test;
    use rand::{
        rngs::{OsRng, StdRng},
        Rng, SeedableRng, TryRngCore,
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
        let provider = &Provider::default();
        let seed: [u8; 32] = OsRng.unwrap_mut().random();
        println!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let root_secret = dummy_secret(&mut rng, ciphersuite);
        let mut pprf = Pprf::<Prefix16>::new_for_test(root_secret);
        let index = dummy_index::<Prefix16>(&mut rng);
        let crypto = provider.crypto();

        let result = pprf.evaluate(crypto, ciphersuite, &index);
        assert!(result.is_ok());
        assert_eq!(result.as_ref().unwrap().as_slice().len(), 32);
    }

    #[openmls_test]
    fn re_evaluation_of_same_index_returns_error() {
        let provider = &Provider::default();
        let seed: [u8; 32] = OsRng.unwrap_mut().random();
        println!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let root_secret = dummy_secret(&mut rng, ciphersuite);
        let mut pprf = Pprf::<Prefix16>::new_for_test(root_secret);
        let index = dummy_index::<Prefix16>(&mut rng);
        let crypto = provider.crypto();

        let _first = pprf.evaluate(crypto, ciphersuite, &index).unwrap();
        let second = pprf
            .evaluate(crypto, ciphersuite, &index)
            .expect_err("Evaluation on same input should fail");

        assert!(matches!(second, PprfError::PuncturedInput));
    }

    #[openmls_test]
    fn different_indices_produce_different_results() {
        let provider = &Provider::default();
        let seed: [u8; 32] = OsRng.unwrap_mut().random();
        println!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let root_secret = dummy_secret(&mut rng, ciphersuite);
        let mut pprf = Pprf::<Prefix16>::new_for_test(root_secret);
        let index1 = dummy_index::<Prefix16>(&mut rng);
        let index2 = dummy_index::<Prefix16>(&mut rng);
        let crypto = provider.crypto();

        let leaf1 = pprf.evaluate(crypto, ciphersuite, &index1).unwrap();
        let leaf2 = pprf.evaluate(crypto, ciphersuite, &index2).unwrap();

        assert_ne!(leaf1.as_slice(), leaf2.as_slice());
    }

    #[openmls_test]
    fn rejects_out_of_bounds_index() {
        let provider = &Provider::default();
        let seed: [u8; 32] = OsRng.unwrap_mut().random();
        println!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let root_secret = dummy_secret(&mut rng, ciphersuite);
        let mut pprf = Pprf::<Prefix16>::new_for_test(root_secret);
        let index = random_vec(&mut rng, Prefix16::MAX_INPUT_LEN + 1); // Out of bounds

        let crypto = provider.crypto();

        let result = pprf.evaluate(crypto, ciphersuite, &index);
        assert!(matches!(result, Err(PprfError::IndexOutOfBounds)));
    }

    #[openmls_test]
    fn pprf_serialization() {
        let provider = &Provider::default();
        let seed: [u8; 32] = OsRng.unwrap_mut().random();
        println!("Seed: {:?}", seed);
        let mut rng = StdRng::from_seed(seed);
        let root_secret = dummy_secret(&mut rng, ciphersuite);
        let mut pprf = Pprf::<Prefix16>::new_for_test(root_secret);
        let index = random_vec(&mut rng, Prefix16::MAX_INPUT_LEN);

        let crypto = provider.crypto();

        let result = pprf.evaluate(crypto, ciphersuite, &index);
        assert!(result.is_ok());

        let serialized = serde_json::to_string(&pprf).unwrap();
        println!("Serialized: {}", serialized);
        let deserialized: Pprf<Prefix16> = serde_json::from_str(&serialized).unwrap();

        assert_eq!(pprf, deserialized);
    }
}

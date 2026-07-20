//! # Puncturable Pseudorandom Function (PPRF) Implementation
//!
//! This module implements a PPRF using the same binary tree structure as the
//! secret tree. In contrast to the secret tree, this implementation is generic
//! over the size of the tree. Additionally, it is designed to be efficient even
//! for larger sizes.

use std::collections::HashMap;

use openmls_traits::types::CryptoError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

use prefix::Prefix;

pub use prefix::Prefix16;

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

/// A Node in the PPRF tree that contains the node's secret.
#[derive(Debug, Serialize, Deserialize, Clone, ZeroizeOnDrop)]
#[serde(transparent)]
struct PprfNode(#[serde(with = "serde_bytes")] Vec<u8>);

/// The PPRF containing the tree of nodes, where each node contains a secret. It
/// can be evaluated at a given input only once. The struct will grow in size
/// with each evaluation.
///
/// The struct is generic over the prefix, which determines how individual nodes
/// are indexed. As prefixes are stored alongside each node, small prefixes help
/// keep the overall tree small.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Pprf<P: Prefix> {
    #[serde(
        serialize_with = "serialize_hashmap",
        deserialize_with = "deserialize_hashmap"
    )]
    nodes: HashMap<P, PprfNode>, // Mapping of prefix and depth to node
    width: usize,
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

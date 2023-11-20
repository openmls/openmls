use tls_codec::{Deserialize, DeserializeBytes, Size, TlsDeserialize, TlsSerialize, TlsSize};

use super::{
    leaf_node::LeafNodePayload,
    parent_node::{UnmergedLeaves, UnmergedLeavesError},
};

/// Node type. Can be either `Leaf` or `Parent`.
#[derive(PartialEq, Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
enum MlsNodeType {
    Leaf = 1,
    Parent = 2,
}

// Implementations for `ParentNode`

impl tls_codec::Deserialize for UnmergedLeaves {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let list = Vec::tls_deserialize(bytes)?;
        Self::try_from(list).map_err(|e| match e {
            UnmergedLeavesError::NotSorted => {
                tls_codec::Error::DecodingError("Unmerged leaves not sorted".into())
            }
        })
    }
}

impl DeserializeBytes for LeafNodePayload {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error>
    where
        Self: Sized,
    {
        let mut bytes_reader = bytes;
        let result = LeafNodePayload::tls_deserialize(&mut bytes_reader)?;
        let remainder = bytes.get(result.tls_serialized_len()..).ok_or_else(|| {
            tls_codec::Error::DecodingError(
                "Not enough bytes to deserialize LeafNodePayload".into(),
            )
        })?;
        Ok((result, remainder))
    }
}

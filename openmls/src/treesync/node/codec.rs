use tls_codec::{
    Deserialize, DeserializeBytes, Error, Size, TlsDeserialize, TlsDeserializeBytes, TlsSerialize,
    TlsSize,
};

use super::parent_node::{UnmergedLeaves, UnmergedLeavesError};

/// Node type. Can be either `Leaf` or `Parent`.
#[derive(
    PartialEq, Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
#[repr(u8)]
enum MlsNodeType {
    Leaf = 1,
    Parent = 2,
}

// Implementations for `ParentNode`

impl Deserialize for UnmergedLeaves {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let list = Vec::tls_deserialize(bytes)?;
        Self::try_from(list).map_err(|e| match e {
            UnmergedLeavesError::NotSorted => {
                Error::DecodingError("Unmerged leaves not sorted".into())
            }
        })
    }
}

impl DeserializeBytes for UnmergedLeaves {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let unmerged_leaves = UnmergedLeaves::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[unmerged_leaves.tls_serialized_len()..];
        Ok((unmerged_leaves, remainder))
    }
}

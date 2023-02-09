use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use super::parent_node::{UnmergedLeaves, UnmergedLeavesError};

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

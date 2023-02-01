use std::io::{Read, Write};

use tls_codec::{Deserialize, Serialize, Size};

use super::{LeafNodePayload, LeafNodeSource, LeafNodeTbs, TreeInfoTbs, TreePosition};

impl Serialize for LeafNodeTbs {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = self.payload.tls_serialize(writer)?;
        match &self.tree_info {
            TreeInfoTbs::KeyPackage => Ok(written),
            TreeInfoTbs::Update(p) | TreeInfoTbs::Commit(p) => {
                p.tls_serialize(writer).map(|b| written + b)
            }
        }
    }
}

impl Size for LeafNodeTbs {
    fn tls_serialized_len(&self) -> usize {
        let len = self.payload.tls_serialized_len();
        match &self.tree_info {
            TreeInfoTbs::KeyPackage => len,
            TreeInfoTbs::Update(p) | TreeInfoTbs::Commit(p) => p.tls_serialized_len() + len,
        }
    }
}

impl Deserialize for LeafNodeTbs {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let payload = LeafNodePayload::tls_deserialize(bytes)?;
        let tree_info = match payload.leaf_node_source {
            LeafNodeSource::KeyPackage(_) => TreeInfoTbs::KeyPackage,
            LeafNodeSource::Update => TreeInfoTbs::Update(TreePosition::tls_deserialize(bytes)?),
            LeafNodeSource::Commit(_) => TreeInfoTbs::Commit(TreePosition::tls_deserialize(bytes)?),
        };

        Ok(Self { payload, tree_info })
    }
}

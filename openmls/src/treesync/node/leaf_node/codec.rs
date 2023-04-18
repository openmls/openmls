use std::io::Write;

use tls_codec::{Serialize, Size};

use super::TreeInfoTbs;

impl Serialize for TreeInfoTbs {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match self {
            TreeInfoTbs::KeyPackage => Ok(0),
            TreeInfoTbs::Update(p) => p.tls_serialize(writer),
            TreeInfoTbs::Commit(p) => p.tls_serialize(writer),
        }
    }
}

impl Size for TreeInfoTbs {
    fn tls_serialized_len(&self) -> usize {
        match self {
            TreeInfoTbs::KeyPackage => 0,
            TreeInfoTbs::Update(p) => p.tls_serialized_len(),
            TreeInfoTbs::Commit(p) => p.tls_serialized_len(),
        }
    }
}

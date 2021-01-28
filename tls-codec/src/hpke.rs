//! TLS Codec for HPKE primitives

use super::*;
use hpke_rs::HPKEPublicKey;

impl Serialize for HPKEPublicKey {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        let value = TlsVecU16::from(self.as_slice());
        value.tls_serialize(buffer)
    }
}

impl Deserialize for HPKEPublicKey {
    fn tls_deserialize(cursor: &Cursor) -> Result<Self, Error> {
        let value = TlsVecU16::<u8>::tls_deserialize(&cursor)?;
        Ok(Self::new(value.as_slice().to_vec()))
    }
}

//! TLS Codec for HPKE primitives

use super::*;
use hpke_rs::HpkePublicKey;

impl Serialize for HpkePublicKey {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        let value = TlsVecU16::from(self.as_slice());
        value.tls_serialize(buffer)
    }
}

impl Deserialize for HpkePublicKey {
    fn tls_deserialize(cursor: &Cursor) -> Result<Self, Error> {
        let value = TlsVecU16::<u8>::tls_deserialize(&cursor)?;
        Ok(Self::new(value.as_slice().to_vec()))
    }
}

impl TlsSize for HpkePublicKey {
    #[inline]
    fn serialized_len(&self) -> usize {
        TlsVecU16::<u8>::len_len() + self.as_slice().len()
    }
}

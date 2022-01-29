//! TLS codec implementation for preshared keys.

use tls_codec::TlsByteVecU8;

use super::*;

use std::io::{Read, Write};

impl tls_codec::Size for &PreSharedKeyId {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        (*self).tls_serialized_len()
    }
}

impl tls_codec::Size for PreSharedKeyId {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.psk_type.tls_serialized_len()
            + match &self.psk {
                Psk::External(external_psk) => external_psk.tls_serialized_len(),
                Psk::Reinit(reinit_psk) => reinit_psk.tls_serialized_len(),
                Psk::Branch(branch_psk) => branch_psk.tls_serialized_len(),
            }
            + self.psk_nonce.tls_serialized_len()
    }
}

impl tls_codec::Serialize for PreSharedKeyId {
    #[inline]
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, ::tls_codec::Error> {
        let mut written = self.psk_type.tls_serialize(writer)?;
        written += match &self.psk {
            Psk::External(external_psk) => external_psk.tls_serialize(writer)?,
            Psk::Reinit(reinit_psk) => reinit_psk.tls_serialize(writer)?,
            Psk::Branch(branch_psk) => branch_psk.tls_serialize(writer)?,
        };
        self.psk_nonce.tls_serialize(writer).map(|l| l + written)
    }
}

impl tls_codec::Serialize for &PreSharedKeyId {
    #[inline]
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, ::tls_codec::Error> {
        (*self).tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for PreSharedKeyId {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, ::tls_codec::Error> {
        let psktype = PskType::tls_deserialize(bytes)?;
        let psk = match psktype {
            PskType::External => Psk::External(ExternalPsk::tls_deserialize(bytes)?),
            PskType::Reinit => Psk::Reinit(ReinitPsk::tls_deserialize(bytes)?),
            PskType::Branch => Psk::Branch(BranchPsk::tls_deserialize(bytes)?),
        };
        let psk_nonce = TlsByteVecU8::tls_deserialize(bytes)?;
        Ok(Self {
            psk_type: psktype,
            psk,
            psk_nonce,
        })
    }
}

use std::io::Read;

use openmls_traits::types::Ciphersuite;

use crate::key_packages::*;
use crate::versions::ProtocolVersion;

impl tls_codec::Size for KeyPackage {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.payload.tls_serialized_len() + self.signature.tls_serialized_len()
    }
}

impl tls_codec::Size for &KeyPackage {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        (*self).tls_serialized_len()
    }
}

impl tls_codec::Serialize for &KeyPackage {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        (*self).tls_serialize(writer)
    }
}

impl tls_codec::Serialize for KeyPackage {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let encoded = self.unsigned_payload()?;
        let written = writer.write(&encoded)?;
        debug_assert_eq!(written, encoded.len());
        self.signature.tls_serialize(writer).map(|l| l + written)
    }
}

impl tls_codec::Deserialize for KeyPackage {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let protocol_version = ProtocolVersion::tls_deserialize(bytes)?;
        let ciphersuite = Ciphersuite::tls_deserialize(bytes)?;
        let hpke_init_key = HpkePublicKey::tls_deserialize(bytes)?;
        let credential = Credential::tls_deserialize(bytes)?;
        let extensions = TlsVecU32::tls_deserialize(bytes)?;
        let signature = Signature::tls_deserialize(bytes)?;
        let payload = KeyPackagePayload {
            protocol_version,
            ciphersuite,
            hpke_init_key,
            credential,
            extensions,
        };
        let kp = KeyPackage { payload, signature };

        // FIXME: Was this necessary? If so, add verification of key packages again after deserializing.
        // if kp.verify_no_out(kp.credential()).is_err() {
        //     let msg = format!("Error verifying a key package after decoding\n{:?}", kp);
        //     log::error!("{}", msg);
        //     return Err(tls_codec::Error::DecodingError(msg));
        // }
        Ok(kp)
    }
}

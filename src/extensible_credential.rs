use crate::ciphersuite::Ciphersuite;
use crate::ciphersuite::Signature;
use crate::ciphersuite::SignaturePublicKey;
use crate::codec::encode_vec;
use crate::codec::Codec;
use crate::codec::CodecError;
use crate::codec::VecSize;
use crate::extensions::Extension;

/// A Basic Credential that allows for extensions. It also contains the
/// Ciphersuite corresponding to the public key it contains.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtensibleCredential {
    pub identity: Vec<u8>,
    pub ciphersuite: Ciphersuite,
    pub public_key: SignaturePublicKey,
    pub extensions: Vec<Extension>,
}

impl ExtensibleCredential {
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> bool {
        self.ciphersuite
            .verify(signature, &self.public_key, payload)
    }
}

impl Codec for ExtensibleCredential {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.identity)?;
        self.ciphersuite.encode(buffer)?;
        self.public_key.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.extensions)?;
        Ok(())
    }
}

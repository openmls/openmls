use crate::creds::*;
use crate::ciphersuite::*;

/// The `Signable` trait is implemented by all struct that are being signed.
/// The implementation has to provide the `unsigned_payload` function.
pub trait Signable: Sized {
    fn unsigned_payload(&self) -> Result<Vec<u8>, crate::codec::CodecError>;

    /// Sign the payload with the given `id`.
    /// 
    /// Returns a `Signature`.
    fn sign(&mut self, id: &Identity) -> Signature {
        let payload = self.unsigned_payload().unwrap();
        id.sign(&payload)
    }

    /// Verifies the payload against the given `id` and `signature`.
    /// 
    /// Returns a `true` if the signature is valid and `false` otherwise.
    fn verify(&self, id: &Identity, signature: &Signature) -> bool {
        let payload = self.unsigned_payload().unwrap();
        id.verify(&payload, signature)
    }
}

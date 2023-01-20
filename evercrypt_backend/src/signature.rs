use openmls_traits::signatures::{ByteSigner, ByteVerifier, Signer, Verifier};

pub struct EvercryptSigner {}
pub struct EvercryptVerifier {}

impl ByteSigner for EvercryptSigner {}

impl Signer<Vec<u8>> for EvercryptSigner {
    type Error = String;

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }
}

impl ByteVerifier for EvercryptVerifier {}
impl Verifier<[u8]> for EvercryptVerifier {
    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), openmls_traits::types::Error> {
        todo!()
    }
}

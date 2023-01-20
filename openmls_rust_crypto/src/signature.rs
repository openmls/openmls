use openmls_traits::signatures::{ByteSigner, ByteVerifier, Signer, Verifier};

pub struct RustCryptoSigner {}
pub struct RustCryptoVerifier {}

impl ByteSigner for RustCryptoSigner {}

impl Signer<Vec<u8>> for RustCryptoSigner {
    type Error = String;

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }
}

impl ByteVerifier for RustCryptoVerifier {}
impl Verifier<[u8]> for RustCryptoVerifier {
    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), openmls_traits::types::Error> {
        todo!()
    }
}

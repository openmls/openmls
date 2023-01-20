use openmls_memory_keystore::MemoryKeyStore;
use openmls_traits::OpenMlsCryptoProvider;

mod provider;
mod signature;
pub use provider::*;
pub use signature::*;

#[derive(Default, Debug)]
pub struct OpenMlsEvercrypt {
    crypto: EvercryptProvider,
    key_store: MemoryKeyStore,
}

impl OpenMlsCryptoProvider for OpenMlsEvercrypt {
    type CryptoProvider = EvercryptProvider;
    type RandProvider = EvercryptProvider;
    type KeyStoreProvider = MemoryKeyStore;
    type Signer = EvercryptSigner;
    type Verifier = EvercryptVerifier;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &self.key_store
    }

    fn signer(&self) -> &Self::Signer {
        todo!()
    }

    fn verifier(&self) -> &Self::Verifier {
        todo!()
    }
}

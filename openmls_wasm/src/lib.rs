use openmls::credentials::{Credential, CredentialType};
use openmls_traits::{random::OpenMlsRand, OpenMlsProvider};

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn test() {
    let cred = Credential::new(b"i am a test identity".to_vec(), CredentialType::Basic);
    alert(&format!("{cred:?}"))
}

#[wasm_bindgen]
pub fn rand() {
    let provider: openmls_rust_crypto::OpenMlsRustCrypto = Default::default();
    let rand = provider.rand();
    alert(&format!("{:x?}", rand.random_vec(16).unwrap()))
}

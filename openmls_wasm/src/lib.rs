use openmls::credentials::{Credential, CredentialType};
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

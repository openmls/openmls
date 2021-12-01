use openmls_traits::types::HpkeKeyPair;

use crate::{
    ciphersuite::{HpkePublicKey, Secret},
    prelude::ProtocolVersion,
};

#[test]
fn test_parent_node() {
    let backend = OpenMlsRustCrypto::default();
    // FIXME: use the macro here.
    for ciphersuite in Config::supported_ciphersuites() {
        let version = ProtocolVersion::default();
        let secret = Secret::random(ciphersuite, backend, version);
    }
}

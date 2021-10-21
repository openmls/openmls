//! Unit test for PrivateTree

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{random::OpenMlsRand, OpenMlsCryptoProvider};

use super::test_util::*;
use crate::{
    ciphersuite::*,
    credentials::*,
    key_packages::*,
    tree::{
        index::{LeafIndex, NodeIndex},
        private_tree::*,
    },
};

// Common setup for tests.
fn setup(ciphersuite: &Ciphersuite, len: usize) -> (KeyPackageBundle, LeafIndex, Vec<NodeIndex>) {
    let crypto = OpenMlsRustCrypto::default();
    let credential_bundle = CredentialBundle::new(
        "username".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        &crypto,
    )
    .unwrap();
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, &crypto, vec![]).unwrap();
    let own_index = LeafIndex::from(0u32);
    let direct_path = generate_path_u8(len);

    (key_package_bundle, own_index, direct_path)
}

// Common tests after setup.
fn test_private_tree(
    private_tree: &PrivateTree,
    direct_path: &[NodeIndex],
    public_keys: &[HpkePublicKey],
    ciphersuite: &Ciphersuite,
    crypto: &impl OpenMlsCryptoProvider,
) {
    // Check that we can encrypt to a public key.
    let path_index = 15;
    let index = direct_path[path_index];
    let public_key = &public_keys[path_index];
    let private_key = private_tree.path_keys().get(index).unwrap();
    let data = crypto.rand().random_vec(55).unwrap();
    let info = b"PrivateTree Test Info";
    let aad = b"PrivateTree Test AAD";

    let c = ciphersuite.hpke_seal(public_key, info, aad, &data);
    let m = ciphersuite
        .hpke_open(&c, private_key, info, aad)
        .expect("Error decrypting valid Secret in PrivateTree test.");
    assert_eq!(m, data);
}

#[test]
fn create_private_tree_from_secret() {
    use crate::config::*;
    const PATH_LENGTH: usize = 33;
    let crypto = OpenMlsRustCrypto::default();
    for ciphersuite in Config::supported_ciphersuites() {
        let (key_package_bundle, own_index, direct_path) = setup(ciphersuite, PATH_LENGTH);

        let mut private_tree =
            PrivateTree::from_leaf_secret(&crypto, own_index, key_package_bundle.leaf_secret());

        // Compute path secrets from the leaf and generate keypairs
        let public_keys = private_tree.generate_path_secrets(
            ciphersuite,
            &crypto,
            key_package_bundle.leaf_secret(),
            &direct_path,
        );

        assert_eq!(public_keys.len(), direct_path.len());

        test_private_tree(
            &private_tree,
            &direct_path,
            &public_keys,
            ciphersuite,
            &crypto,
        );
    }
}

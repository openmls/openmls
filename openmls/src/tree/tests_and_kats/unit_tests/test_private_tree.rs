//! Unit test for PrivateTree

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, OpenMlsCryptoProvider};

use super::test_util::*;
use crate::{
    ciphersuite::*,
    credentials::*,
    key_packages::*,
    test_utils::*,
    tree::{
        index::{LeafIndex, NodeIndex},
        private_tree::*,
    },
};

// Common setup for tests.
fn setup(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    len: usize,
) -> (KeyPackageBundle, LeafIndex, Vec<NodeIndex>) {
    let credential_bundle = CredentialBundle::new(
        "username".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &credential_bundle, backend, vec![])
            .expect("An unexpected error occurred.");
    let own_index = LeafIndex::from(0u32);
    let direct_path = generate_path_u8(len);

    (key_package_bundle, own_index, direct_path)
}

// Common tests after setup.
fn test_private_tree(
    private_tree: &PrivateTree,
    direct_path: &[NodeIndex],
    public_keys: &[HpkePublicKey],
    ciphersuite: Ciphersuite,
    crypto: &impl OpenMlsCryptoProvider,
) {
    // Check that we can encrypt to a public key.
    let path_index = 15;
    let index = direct_path[path_index];
    let public_key = &public_keys[path_index];
    let private_key = private_tree
        .path_keys()
        .get(index)
        .expect("An unexpected error occurred.");
    let data = crypto
        .rand()
        .random_vec(55)
        .expect("An unexpected error occurred.");
    let info = b"PrivateTree Test Info";
    let aad = b"PrivateTree Test AAD";

    let c = crypto.crypto().hpke_seal(
        ciphersuite.hpke_config(),
        public_key.as_slice(),
        info,
        aad,
        &data,
    );
    let m = crypto
        .crypto()
        .hpke_open(
            ciphersuite.hpke_config(),
            &c,
            private_key.as_slice(),
            info,
            aad,
        )
        .expect("Error decrypting valid Secret in PrivateTree test.");
    assert_eq!(m, data);
}

#[apply(ciphersuites_and_backends)]
fn create_private_tree_from_secret(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    const PATH_LENGTH: usize = 33;
    let (key_package_bundle, own_index, direct_path) = setup(ciphersuite, backend, PATH_LENGTH);

    let mut private_tree =
        PrivateTree::from_leaf_secret(backend, own_index, key_package_bundle.leaf_secret())
            .expect("Could not create PrivateTree.");

    // Compute path secrets from the leaf and generate keypairs
    let public_keys = private_tree
        .generate_path_secrets(
            ciphersuite,
            backend,
            key_package_bundle.leaf_secret(),
            &direct_path,
        )
        .expect("Could not generate path secrets.");

    assert_eq!(public_keys.len(), direct_path.len());

    test_private_tree(
        &private_tree,
        &direct_path,
        &public_keys,
        ciphersuite,
        backend,
    );
}

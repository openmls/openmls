//! Unit test for PrivateTree

#[cfg(test)]
use super::{index::NodeIndex, private_tree::*, test_util::*};
#[cfg(test)]
use crate::{ciphersuite::*, creds::*, key_packages::*, utils::*};

#[cfg(test)]
// Common setup for tests.
fn setup(
    ciphersuite_name: CiphersuiteName,
    len: usize,
) -> (Ciphersuite, KeyPackageBundle, NodeIndex, Vec<NodeIndex>) {
    let ciphersuite = Ciphersuite::new(ciphersuite_name);
    let credential_bundle =
        CredentialBundle::new("username".into(), CredentialType::Basic, ciphersuite_name).unwrap();
    let key_package_bundle = KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, vec![]);
    let own_index = NodeIndex::from(0u32);
    let direct_path = generate_path_u8(len);

    (ciphersuite, key_package_bundle, own_index, direct_path)
}

#[cfg(test)]
// Common tests after setup.
fn test_private_tree(
    private_tree: &PrivateTree,
    direct_path: &[NodeIndex],
    public_keys: &[HPKEPublicKey],
    ciphersuite: &Ciphersuite,
) {
    // Check that we can encrypt to a public key.
    let path_index = 15;
    let index = direct_path[path_index];
    let public_key = &public_keys[path_index];
    let private_key = private_tree.get_path_keys().get(index).unwrap();
    let data = randombytes(55);
    let info = b"PrivateTree Test Info";
    let aad = b"PrivateTree Test AAD";

    let c = ciphersuite.hpke_seal(public_key, info, aad, &data);
    let m = ciphersuite.hpke_open(&c, &private_key, info, aad);
    assert_eq!(m, data);
}

#[test]
fn create_private_tree_from_secret() {
    use crate::config::*;
    const PATH_LENGTH: usize = 33;
    for &ciphersuite_name in Config::supported_ciphersuites() {
        let (ciphersuite, key_package_bundle, own_index, direct_path) =
            setup(ciphersuite_name, PATH_LENGTH);

        let mut private_tree = PrivateTree::from_key_package_bundle(own_index, &key_package_bundle);

        // Compute path secrets from the leaf and generate keypairs
        let public_keys = private_tree.generate_path_secrets(
            &ciphersuite,
            key_package_bundle.leaf_secret(),
            &direct_path,
        );

        assert_eq!(public_keys.len(), direct_path.len());

        test_private_tree(&private_tree, &direct_path, &public_keys, &ciphersuite);
    }
}

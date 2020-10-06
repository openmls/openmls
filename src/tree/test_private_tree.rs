//! Unit test for PrivateTree

#[cfg(test)]
use super::{index::NodeIndex, private_tree::*, test_util::*};
#[cfg(test)]
use crate::{ciphersuite::*, utils::*};

#[cfg(test)]
// Common setup for tests.
fn setup(len: usize) -> (Ciphersuite, HPKEPrivateKey, NodeIndex, Vec<NodeIndex>) {
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let hpke_private_key = HPKEPrivateKey::from_slice(&randombytes(32));
    let own_index = NodeIndex::from(0u32);
    let direct_path = generate_path_u8(len);

    (ciphersuite, hpke_private_key, own_index, direct_path)
}

#[cfg(test)]
// Common tests after setup.
fn test_private_tree(
    private_tree: &OwnLeaf,
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
    let info = b"OwnLeaf Test Info";
    let aad = b"OwnLeaf Test AAD";

    let c = ciphersuite.hpke_seal(public_key, info, aad, &data);
    let m = ciphersuite.hpke_open(&c, &private_key, info, aad);
    assert_eq!(m, data);
}

#[test]
fn create_private_tree_from_secret() {
    const PATH_LENGTH: usize = 33;
    let (ciphersuite, hpke_private_key, own_index, direct_path) = setup(PATH_LENGTH);

    let mut private_tree = OwnLeaf::from_private_key(own_index, hpke_private_key);

    // Compute path secrets form the leaf.
    private_tree.generate_path_secrets(&ciphersuite, None, direct_path.len());

    // Compute commit secret.
    private_tree.generate_commit_secret(&ciphersuite).unwrap();

    // Generate key pairs and return.
    let public_keys = private_tree
        .generate_path_keypairs(&ciphersuite, &direct_path)
        .unwrap();

    assert_eq!(public_keys.len(), direct_path.len());

    test_private_tree(&private_tree, &direct_path, &public_keys, &ciphersuite);
}

#[test]
fn create_private_tree_from_raw() {
    const PATH_LENGTH: usize = 33;
    let (ciphersuite, hpke_private_key, own_index, direct_path) = setup(PATH_LENGTH);

    let (private_tree, public_keys) =
        OwnLeaf::new_raw(&ciphersuite, own_index, hpke_private_key, &direct_path).unwrap();

    test_private_tree(&private_tree, &direct_path, &public_keys, &ciphersuite);
}
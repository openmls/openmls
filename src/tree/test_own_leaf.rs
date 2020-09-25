//! Unit test for OwnLeaf

#[cfg(test)]
use super::{index::NodeIndex, own_leaf::*, test_util::*};
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
fn test_own_leaf(
    own_leaf: &OwnLeaf,
    direct_path: &[NodeIndex],
    public_keys: &[HPKEPublicKey],
    ciphersuite: &Ciphersuite,
) {
    // Check that we can encrypt to a public key.
    let path_index = 15;
    let index = direct_path[path_index];
    let public_key = &public_keys[path_index];
    let private_key = own_leaf.get_path_keys().get(index).unwrap();
    let data = randombytes(55);
    let info = b"OwnLeaf Test Info";
    let aad = b"OwnLeaf Test AAD";

    let c = ciphersuite.hpke_seal(public_key, info, aad, &data);
    let m = ciphersuite.hpke_open(&c, &private_key, info, aad);
    assert_eq!(m, data);
}

#[test]
fn create_own_leaf_from_secret() {
    const PATH_LENGTH: usize = 33;
    let (ciphersuite, hpke_private_key, own_index, direct_path) = setup(PATH_LENGTH);

    let mut own_leaf = OwnLeaf::from_private_key(own_index, hpke_private_key);

    // Compute path secrets form the leaf.
    own_leaf.generate_path_secrets(&ciphersuite, None, direct_path.len());

    // Compute commit secret.
    own_leaf.generate_commit_secret(&ciphersuite).unwrap();

    // Generate key pairs and return.
    let public_keys = own_leaf
        .generate_path_keypairs(&ciphersuite, &direct_path)
        .unwrap();

    assert_eq!(public_keys.len(), direct_path.len());

    test_own_leaf(&own_leaf, &direct_path, &public_keys, &ciphersuite);
}

#[test]
fn create_own_leaf_from_raw() {
    const PATH_LENGTH: usize = 33;
    let (ciphersuite, hpke_private_key, own_index, direct_path) = setup(PATH_LENGTH);

    let (own_leaf, public_keys) =
        OwnLeaf::new_raw(&ciphersuite, own_index, hpke_private_key, &direct_path).unwrap();

    test_own_leaf(&own_leaf, &direct_path, &public_keys, &ciphersuite);
}

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::HpkeKeyPair;
use openmls_traits::OpenMlsCryptoProvider;

use crate::ciphersuite::Ciphersuite;
use crate::credentials::{CredentialBundle, CredentialType::Basic};
use crate::messages::PathSecret;
use crate::prelude::KeyPackageBundle;
use crate::{
    ciphersuite::{HpkePublicKey, Secret},
    prelude::ProtocolVersion,
};

use super::leaf_node::LeafNode;
use super::parent_node::ParentNode;

#[test]
fn test_leaf_node() {
    // Neither ciphersuite nor crypto backend are particularly important here.
    let ciphersuite = Ciphersuite::default();
    let backend = OpenMlsRustCrypto::default();
    // Creation
    let cb = CredentialBundle::new(
        "test".into(),
        Basic,
        ciphersuite.signature_scheme(),
        &backend,
    )
    .expect("error creating CB");
    let kpb = KeyPackageBundle::new(&[ciphersuite.name()], &cb, &backend, vec![])
        .expect("error creating KPB");
    let (kp, _leaf_secret, private_key) = kpb.into_parts();
    let private_key_bytes = private_key.as_slice().to_vec();

    let mut leaf_node: LeafNode = kp.clone().into();

    assert_eq!(leaf_node.public_key(), kp.hpke_init_key());

    assert_eq!(leaf_node.key_package(), &kp);

    assert!(leaf_node.private_key().is_none());

    leaf_node.set_private_key(private_key);

    assert_eq!(
        leaf_node
            .private_key()
            .as_ref()
            .expect("error retrieving leaf private key")
            .as_slice(),
        private_key_bytes
    );
}

#[test]
fn test_parent_node() {
    // Fastest way to get hold of a keypair

    // Neither ciphersuite nor crypto backend are particularly important here.
    let ciphersuite = Ciphersuite::default();
    let backend = OpenMlsRustCrypto::default();
    // Creation
    let cb = CredentialBundle::new(
        "test".into(),
        Basic,
        ciphersuite.signature_scheme(),
        &backend,
    )
    .expect("error creating CB");
    let kpb = KeyPackageBundle::new(&[ciphersuite.name()], &cb, &backend, vec![])
        .expect("error creating KPB");
    let (kp, _leaf_secret, private_key) = kpb.into_parts();

    let mut parent_node: ParentNode = kp.hpke_init_key().clone().into();

    // The public key should match and everything else should be empty.
    assert_eq!(parent_node.public_key(), kp.hpke_init_key());
    assert_eq!(parent_node.unmerged_leaves(), &[0u32; 0]);
    assert_eq!(parent_node.parent_hash(), &[0u8; 0]);
    assert!(parent_node.private_key().is_none());

    // Adding unmerged leaves
    parent_node.add_unmerged_leaf(0);

    assert_eq!(parent_node.unmerged_leaves(), &[0]);

    // Setting parent hash
    parent_node.set_parent_hash(vec![0]);
    assert_eq!(parent_node.parent_hash(), &[0]);

    // Creation from a keypair
    let private_key_bytes = private_key.as_slice().to_vec();
    let mut parent_node: ParentNode = (kp.hpke_init_key().clone(), private_key).into();

    // Private and public key should match and everything else should be empty.
    assert_eq!(parent_node.public_key(), kp.hpke_init_key());
    assert_eq!(parent_node.unmerged_leaves(), &[0u32; 0]);
    assert_eq!(parent_node.parent_hash(), &[0u8; 0]);
    assert_eq!(
        parent_node
            .private_key()
            .as_ref()
            .expect("no private key despite generating node from keypair")
            .as_slice(),
        private_key_bytes.as_slice()
    );

    // Not much we can do here to test parent hashes. This is done properly in
    // the test vectors.
    let parent_hash = parent_node
        .compute_parent_hash(&backend, ciphersuite, &[], &[])
        .expect("error computing parent hash");
    assert!(!parent_hash.is_empty())
}

#[test]
fn test_node() {
    todo!()
}

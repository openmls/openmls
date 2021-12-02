use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::HpkeKeyPair;
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Deserialize, Serialize};

use crate::ciphersuite::Ciphersuite;
use crate::credentials::{CredentialBundle, CredentialType::Basic};
use crate::messages::PathSecret;
use crate::prelude::ExtensionType::ParentHash;
use crate::prelude::KeyPackageBundle;
use crate::{
    ciphersuite::{HpkePublicKey, Secret},
    prelude::ProtocolVersion,
};

use super::leaf_node::LeafNode;
use super::parent_node::ParentNode;
use super::{Node, NodeError};

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

    // `Node` enum
    let mut node = Node::LeafNode(leaf_node.clone());

    assert_eq!(node.public_key(), kp.hpke_init_key());
    assert_eq!(
        node.private_key()
            .as_ref()
            .expect("error retrieving leaf private key")
            .as_slice(),
        private_key_bytes
    );
    assert_eq!(
        node.as_leaf_node()
            .expect("error casting node in to leaf node"),
        &leaf_node
    );

    assert_eq!(
        node.as_parent_node()
            .expect_err("no error casting node to wrong type"),
        NodeError::AsParentError
    );

    assert_eq!(
        node.as_parent_node_mut()
            .expect_err("no error casting node to wrong type"),
        NodeError::AsParentError
    );

    // Codec
    // Verify that we still have a private key
    assert!(leaf_node.private_key().is_some());
    let serialized_leaf = (&leaf_node)
        .tls_serialize_detached()
        .expect("error serializing leaf node");
    let deserialized_node = LeafNode::tls_deserialize(&mut serialized_leaf.as_slice())
        .expect("error deserializing leaf node");
    // This should now be the same node as before, but without a private key.
    let leaf_without_sk: LeafNode = kp.into();
    assert_eq!(leaf_without_sk, deserialized_node);

    // Node codec
    let serialized_node = node
        .tls_serialize_detached()
        .expect("error serializing node");
    let deserialized_node =
        Node::tls_deserialize(&mut serialized_node.as_slice()).expect("error deserializing node");
    // This should now be the same node as before, but without a private key.
    assert_eq!(deserialized_node, Node::LeafNode(leaf_without_sk));
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
    assert!(!parent_hash.is_empty());

    // `Node` enum
    let mut node = Node::ParentNode(parent_node.clone());

    assert_eq!(node.public_key(), kp.hpke_init_key());
    assert_eq!(
        node.private_key()
            .as_ref()
            .expect("error retrieving leaf private key")
            .as_slice(),
        private_key_bytes
    );
    assert_eq!(
        node.parent_hash()
            .expect("error getting parent hash from parent node"),
        parent_node.parent_hash()
    );

    assert_eq!(
        node.as_parent_node()
            .expect("error casting node in to parent node"),
        &parent_node
    );

    assert_eq!(
        node.as_parent_node_mut()
            .expect("error casting node in to parent node"),
        &parent_node
    );

    assert_eq!(
        node.as_leaf_node()
            .expect_err("no error casting node to wrong type"),
        NodeError::AsLeafError
    );

    // Codec

    // Verify that we still have a private key
    assert!(parent_node.private_key().is_some());
    let serialized_parent = (&parent_node)
        .tls_serialize_detached()
        .expect("error serializing parent node");
    let deserialized_node = ParentNode::tls_deserialize(&mut serialized_parent.as_slice())
        .expect("error deserializing parent node");
    // This should now be the same node as before, but without a private key.
    let parent_without_sk: ParentNode = kp.hpke_init_key().clone().into();
    assert_eq!(parent_without_sk, deserialized_node);

    // Node codec
    let serialized_node = node
        .tls_serialize_detached()
        .expect("error serializing node");
    let deserialized_node =
        Node::tls_deserialize(&mut serialized_node.as_slice()).expect("error deserializing node");
    // This should now be the same node as before, but without a private key.
    assert_eq!(deserialized_node, Node::ParentNode(parent_without_sk));
}

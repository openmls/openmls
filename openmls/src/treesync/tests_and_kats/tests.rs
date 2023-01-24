use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
    credentials::CredentialType,
    group::{MlsGroup, MlsGroupConfig},
    key_packages::KeyPackage,
    prelude::*,
};

mod test_diff;
mod test_unmerged_leaves;

/// Pathological example taken from ...
///   https://github.com/mlswg/mls-protocol/issues/690#issue-1244086547.
#[allow(non_snake_case)]
#[test]
fn that_commit_secret_is_derived_from_end_of_update_path_not_root() {
    let mls_group_config = MlsGroupConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    struct Member {
        backend: OpenMlsRustCrypto,
        credential_bundle: CredentialBundle,
        key_package: KeyPackage,
    }

    fn create_member(name: &[u8]) -> Member {
        let backend = OpenMlsRustCrypto::default();
        let credential_bundle = generate_credential_bundle(&backend, name);
        let key_package = generate_key_package(&backend, credential_bundle.credential());

        Member {
            backend,
            credential_bundle,
            key_package,
        }
    }

    let A = create_member(b"A");
    let B = create_member(b"B");
    let C = create_member(b"C");
    let D = create_member(b"D");

    // `A` creates a group with `B`, `C`, and `D` ...
    let mut A_group = MlsGroup::new(
        &A.backend,
        &mls_group_config,
        A.credential_bundle.credential().signature_key(),
    )
    .unwrap();
    A_group.print_tree("A (after new)");

    let (_, welcome, _group_info) = A_group
        .add_members(&A.backend, &[B.key_package, C.key_package, D.key_package])
        .expect("Adding members failed.");

    A_group.merge_pending_commit(&A.backend).unwrap();
    A_group.print_tree("A (after add_members)");

    // ---------------------------------------------------------------------------------------------

    // ... and then `C` removes `A` and `B`.
    let mut C_group = {
        MlsGroup::new_from_welcome(
            &C.backend,
            &mls_group_config,
            welcome.into_welcome().unwrap(),
            None,
        )
        .expect("Joining the group failed.")
    };
    C_group.print_tree("C (after new)");

    let A: LeafNodeIndex = LeafNodeIndex::new(0);
    let B: LeafNodeIndex = LeafNodeIndex::new(1);
    C_group
        .remove_members(&C.backend, &[A, B])
        .expect("Removal of members failed.");

    C_group.merge_pending_commit(&C.backend).unwrap();
    C_group.print_tree("C (after remove)");

    // This leaves C and D as the only leaves in the tree.
    //
    // ```text
    //       _ = Y
    //     __|__
    //    /     \
    //   _       _ = Z
    //  / \     / \
    // _   _   C   D
    // ```

    // C's direct path is [Z, Y], but its filtered direct path is just [Z] because the copath subtree of Y is all blank.
    // So C will not generate a path_secret for Y, which means that the commit secret is not really defined.

    C_group
        .create_message(&C.backend, b"Hello, World!".as_slice())
        .unwrap();
}

// FIXME: Move this to utils:: and remove everywhere.
fn generate_credential_bundle(
    backend: &impl OpenMlsCryptoProvider,
    name: &[u8],
) -> CredentialBundle {
    let credential_bundle = CredentialBundle::new(
        name.to_vec(),
        CredentialType::Basic,
        SignatureScheme::ED25519,
        backend,
    )
    .unwrap();

    let index = credential_bundle
        .credential()
        .signature_key()
        .tls_serialize_detached()
        .unwrap();

    backend
        .key_store()
        .store(&index, &credential_bundle)
        .expect("Storage of signature public key failed.");

    credential_bundle
}

// FIXME: Move this to utils:: and remove everywhere.
fn generate_key_package(
    backend: &impl OpenMlsCryptoProvider,
    credential: &Credential,
) -> KeyPackage {
    let credential_bundle = backend
        .key_store()
        .read(&credential.signature_key().tls_serialize_detached().unwrap())
        .unwrap();

    KeyPackage::builder()
        .build(
            CryptoConfig {
                ciphersuite: Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                version: ProtocolVersion::default(),
            },
            backend,
            &credential_bundle,
        )
        .unwrap()
}

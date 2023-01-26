use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
    credentials::CredentialType,
    group::{MlsGroup, MlsGroupConfig},
    key_packages::KeyPackage,
    prelude::*,
    test_utils::*,
};

mod test_diff;
mod test_unmerged_leaves;

/// Pathological example taken from ...
///   https://github.com/mlswg/mls-protocol/issues/690#issue-1244086547.
#[apply(ciphersuites_and_backends)]
fn that_commit_secret_is_derived_from_end_of_update_path_not_root(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let _ = backend; // get rid of warning
    let crypto_config = CryptoConfig::with_default_version(ciphersuite);
    let mls_group_config = MlsGroupConfig::builder()
        .crypto_config(crypto_config)
        .use_ratchet_tree_extension(true)
        .build();

    struct Member {
        id: Vec<u8>,
        credential_bundle: CredentialBundle,
        key_package: KeyPackage,
        // FIXME: the own_leaf_index from the group is beeing computed incorrectly, so we can't use
        // the backend from the function parameter. #1221
        backend: OpenMlsRustCrypto,
    }

    fn create_member(ciphersuite: Ciphersuite, backend: OpenMlsRustCrypto, name: &[u8]) -> Member {
        let credential_bundle = generate_credential_bundle(ciphersuite, &backend, name);
        let key_package = KeyPackage::builder()
            .build(
                CryptoConfig::with_default_version(ciphersuite),
                &backend,
                &credential_bundle,
            )
            .unwrap();

        Member {
            id: name.to_vec(),
            credential_bundle,
            key_package,
            backend,
        }
    }

    fn get_member_leaf_index(group: &MlsGroup, target_id: &[u8]) -> LeafNodeIndex {
        group.members().for_each(|member| {
            println!(
                "member: {}, index: {:?}, target: {}, own_leaf_index: {:?}",
                String::from_utf8_lossy(&member.identity),
                member.index,
                String::from_utf8_lossy(target_id),
                group.own_leaf_index()
            );
        });
        group
            .members()
            .find_map(|member| {
                if member.identity == target_id {
                    Some(member.index)
                } else {
                    None
                }
            })
            .unwrap()
    }

    let alice = create_member(ciphersuite, OpenMlsRustCrypto::default(), b"alice");
    let bob = create_member(ciphersuite, OpenMlsRustCrypto::default(), b"bob");
    let charlie = create_member(ciphersuite, OpenMlsRustCrypto::default(), b"charlie");
    let dave = create_member(ciphersuite, OpenMlsRustCrypto::default(), b"dave");

    // `A` creates a group with `B`, `C`, and `D` ...
    let mut alice_group = MlsGroup::new(
        &alice.backend,
        &mls_group_config,
        alice.credential_bundle.credential().signature_key(),
    )
    .unwrap();
    alice_group.print_tree("Alice (after new)");

    let (_, welcome, _group_info) = alice_group
        .add_members(
            &alice.backend,
            &[bob.key_package, charlie.key_package, dave.key_package],
        )
        .expect("Adding members failed.");

    alice_group.merge_pending_commit(&alice.backend).unwrap();
    alice_group.print_tree("Alice (after add_members)");

    // ---------------------------------------------------------------------------------------------

    // ... and then `C` removes `A` and `B`.
    let mut charlie_group = {
        MlsGroup::new_from_welcome(
            &charlie.backend,
            &mls_group_config,
            welcome.into_welcome().unwrap(),
            None,
        )
        .expect("Joining the group failed.")
    };
    charlie_group.print_tree("Charlie (after new)");

    let alice = get_member_leaf_index(&charlie_group, &alice.id);
    let bob = get_member_leaf_index(&charlie_group, &bob.id);
    charlie_group
        .remove_members(&charlie.backend, &[alice, bob])
        .expect("Removal of members failed.");

    charlie_group
        .merge_pending_commit(&charlie.backend)
        .unwrap();
    charlie_group.print_tree("Charlie (after remove)");

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

    // C(harlie)'s direct path is [Z, Y], but its filtered direct path is just [Z] because the copath subtree of Y is all blank.
    // So C(harlie) will not generate a path_secret for Y, which means that the commit secret is not really defined.

    charlie_group
        .create_message(&charlie.backend, b"Hello, World!".as_slice())
        .unwrap();
}

// FIXME: Move this to utils:: and remove everywhere.
fn generate_credential_bundle(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    name: &[u8],
) -> CredentialBundle {
    let credential_bundle = CredentialBundle::new(
        name.to_vec(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
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

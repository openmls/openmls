use crate::{
    group::{
        tests_and_kats::utils::{generate_credential_with_key, CredentialWithKeyAndSigner},
        MlsGroup, MlsGroupCreateConfig,
    },
    key_packages::KeyPackage,
    prelude::*,
    storage::OpenMlsProvider,
};

mod test_diff;
mod test_unmerged_leaves;

/// Pathological example taken from ...
///   https://github.com/mlswg/mls-protocol/issues/690#issue-1244086547.
#[openmls_test::openmls_test]
fn that_commit_secret_is_derived_from_end_of_update_path_not_root() {
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();

    struct Member<Provider: OpenMlsProvider> {
        id: Vec<u8>,
        credential_with_key_and_signer: CredentialWithKeyAndSigner,
        key_package: KeyPackage,
        // FIXME: the own_leaf_index from the group is being computed incorrectly, so we can't use
        // the provider from the function parameter. #1221
        provider: Provider,
    }

    fn create_member<Provider: OpenMlsProvider>(
        ciphersuite: Ciphersuite,
        provider: Provider,
        name: Vec<u8>,
    ) -> Member<Provider> {
        let credential_with_key_and_signer = generate_credential_with_key(
            name.clone(),
            ciphersuite.signature_algorithm(),
            &provider,
        );
        let key_package = KeyPackage::builder()
            .build(
                ciphersuite,
                &provider,
                &credential_with_key_and_signer.signer,
                credential_with_key_and_signer.credential_with_key.clone(),
            )
            .unwrap();

        Member {
            id: name,
            credential_with_key_and_signer,
            key_package: key_package.key_package().clone(),
            provider,
        }
    }

    fn get_member_leaf_index(group: &MlsGroup, target_id: &[u8]) -> LeafNodeIndex {
        group
            .members()
            .find_map(|member| {
                if member.credential.serialized_content() == target_id {
                    Some(member.index)
                } else {
                    None
                }
            })
            .unwrap()
    }

    let alice = create_member(ciphersuite, Provider::default(), "alice".into());
    let bob = create_member(ciphersuite, Provider::default(), "bob".into());
    let charlie = create_member(ciphersuite, Provider::default(), "charlie".into());
    let dave = create_member(ciphersuite, Provider::default(), "dave".into());

    // `A` creates a group with `B`, `C`, and `D` ...
    let mut alice_group = MlsGroup::new(
        &alice.provider,
        &alice.credential_with_key_and_signer.signer,
        &mls_group_create_config,
        alice
            .credential_with_key_and_signer
            .credential_with_key
            .clone(),
    )
    .unwrap();
    alice_group.print_ratchet_tree("Alice (after new)");

    let (_, welcome, _group_info) = alice_group
        .add_members(
            &alice.provider,
            &alice.credential_with_key_and_signer.signer,
            &[bob.key_package, charlie.key_package, dave.key_package],
        )
        .expect("Adding members failed.");
    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected message to be a welcome");

    alice_group.merge_pending_commit(&alice.provider).unwrap();
    alice_group.print_ratchet_tree("Alice (after add_members)");

    // ---------------------------------------------------------------------------------------------

    // ... and then `C` removes `A` and `B`.
    let mut charlie_group = {
        StagedWelcome::new_from_welcome(
            &charlie.provider,
            mls_group_create_config.join_config(),
            welcome,
            None,
        )
        .expect("Staging the join failed.")
        .into_group(&charlie.provider)
        .expect("Joining the group failed.")
    };
    charlie_group.print_ratchet_tree("Charlie (after new)");

    let alice = get_member_leaf_index(&charlie_group, &alice.id);
    let bob = get_member_leaf_index(&charlie_group, &bob.id);
    charlie_group
        .remove_members(
            &charlie.provider,
            &charlie.credential_with_key_and_signer.signer,
            &[alice, bob],
        )
        .expect("Removal of members failed.");

    charlie_group
        .merge_pending_commit(&charlie.provider)
        .unwrap();
    charlie_group.print_ratchet_tree("Charlie (after remove)");

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
        .create_message(
            &charlie.provider,
            &charlie.credential_with_key_and_signer.signer,
            b"Hello, World!".as_slice(),
        )
        .unwrap();
}

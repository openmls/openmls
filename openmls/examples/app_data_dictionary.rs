use openmls::prelude::*;

type Provider = openmls_libcrux_crypto::Provider;

// AppDataDictionaryExtension example
fn app_data_dictionary_extension_in_group_context() {
    use openmls::test_utils::single_group_test_framework::*;

    let provider = openmls_libcrux_crypto::Provider::default();
    let ciphersuite = provider.crypto().supported_ciphersuites()[0];

    // set up a large app data dictionary

    let data_gb = vec![0; 1_000_000_000];

    let dictionary = AppDataDictionary::builder()
        .with_entry(5, &[])
        .with_entry(0, &data_gb)
        .build();

    let extension = Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));

    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .with_group_context_extensions(Extensions::single(extension))
        .unwrap()
        .build();

    let group_id = GroupId::from_slice(b"Test Group");

    let mut group_state = GroupState::new_from_party(
        group_id,
        alice_party.generate_pre_group(ciphersuite),
        create_config.clone(),
    )
    .unwrap();

    let [alice] = group_state.members_mut(&["alice"]);
    // build the commit
    let _message_bundle = alice
        .group
        .commit_builder()
        .propose_adds(Some(
            bob_party
                .generate_pre_group(ciphersuite)
                .key_package_bundle
                .key_package()
                .clone(),
        ))
        .load_psks(alice_party.provider.storage())
        .unwrap()
        .build(
            alice_party.provider.rand(),
            alice_party.provider.crypto(),
            &alice.party.signer,
            |_proposal| true,
        )
        .unwrap()
        .stage_commit(&alice_party.provider)
        .unwrap();
}

fn main() {
    app_data_dictionary_extension_in_group_context();
}

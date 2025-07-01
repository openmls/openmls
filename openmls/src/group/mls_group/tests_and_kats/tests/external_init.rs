use crate::group::{
    errors::ExternalCommitError,
    mls_group::tests_and_kats::utils::{setup_alice_bob_group, setup_client},
    public_group::errors::CreationFromExternalError,
    MlsGroup, MlsGroupJoinConfig,
};

#[openmls_test::openmls_test]
fn test_external_init_broken_signature() {
    let (group_alice, alice_signer, _group_bob, _bob_signer, _alice_credetial_with_key, _bob_credential_with_key) =
        // TODO: don't let alice and bob share the provider
        setup_alice_bob_group(ciphersuite, provider, provider);

    // Now set up charly and try to init externally.
    let (charlie_credential, _charlie_kpb, charlie_signer, _charlie_pk) =
        setup_client("Charlie", ciphersuite, provider);

    let verifiable_group_info = {
        let mut verifiable_group_info = group_alice
            .export_group_info(provider.crypto(), &alice_signer, true)
            .unwrap()
            .into_verifiable_group_info()
            .unwrap();
        verifiable_group_info.break_signature();
        verifiable_group_info
    };

    let result = MlsGroup::join_by_external_commit(
        provider,
        &charlie_signer,
        None,
        verifiable_group_info,
        &MlsGroupJoinConfig::default(),
        None,
        None,
        &[],
        charlie_credential,
    )
    .expect_err("Signature was corrupted. This should have failed.");
    assert!(matches!(
        result,
        ExternalCommitError::PublicGroupError(CreationFromExternalError::InvalidGroupInfoSignature)
    ));
}

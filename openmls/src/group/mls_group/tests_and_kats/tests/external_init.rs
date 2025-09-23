use crate::group::{
    mls_group::tests_and_kats::utils::{setup_alice_bob_group, setup_client},
    public_group::errors::CreationFromExternalError,
    ExternalCommitBuilderError, MlsGroup,
};

#[openmls_test::openmls_test]
fn test_external_init_broken_signature() {
    let alice_provider = Provider::default();
    let bob_provider = Provider::default();
    let charlie_provider = Provider::default();

    let (
        alice_group,
        alice_signer,
        _bob_group,
        _bob_signer,
        _alice_credetial_with_key,
        _bob_credential_with_key,
    ) = setup_alice_bob_group(ciphersuite, &alice_provider, &bob_provider);

    // Now set up charly and try to init externally.
    let (charlie_credential, _charlie_kpb, _charlie_signer, _charlie_pk) =
        setup_client("Charlie", ciphersuite, &charlie_provider);

    let verifiable_group_info = {
        let mut verifiable_group_info = alice_group
            .export_group_info(alice_provider.crypto(), &alice_signer, true)
            .unwrap()
            .into_verifiable_group_info()
            .unwrap();
        verifiable_group_info.break_signature();
        verifiable_group_info
    };

    let result = MlsGroup::external_commit_builder()
        .build_group(
            &charlie_provider,
            verifiable_group_info,
            charlie_credential.clone(),
        )
        .expect_err("Signature was corrupted. This should have failed.");
    assert!(matches!(
        result,
        ExternalCommitBuilderError::PublicGroupError(
            CreationFromExternalError::InvalidGroupInfoSignature
        )
    ));
}

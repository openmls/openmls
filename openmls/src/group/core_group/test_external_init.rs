use crate::{
    framing::test_framing::setup_alice_bob_group,
    group::{
        errors::ExternalCommitError, public_group::errors::CreationFromExternalError,
        test_core_group::setup_client, CreateCommitParams,
    },
    storage::OpenMlsProvider,
};
use openmls_traits::prelude::*;

use super::CoreGroup;

#[openmls_test::openmls_test]
fn test_external_init_broken_signature() {
    let (
        framing_parameters,
        group_alice,
        alice_signer,
        _group_bob,
        _bob_signer,
        _bob_credential_with_key,
    ) = setup_alice_bob_group(ciphersuite, provider);

    // Now set up charly and try to init externally.
    let (_charlie_credential, _charlie_kpb, charlie_signer, _charlie_pk) =
        setup_client("Charlie", ciphersuite, provider);

    let verifiable_group_info = {
        let mut verifiable_group_info = group_alice
            .export_group_info(provider.crypto(), &alice_signer, true)
            .unwrap()
            .into_verifiable_group_info();
        verifiable_group_info.break_signature();
        verifiable_group_info
    };

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .build();

    let result = CoreGroup::join_by_external_commit(
        provider,
        &charlie_signer,
        params,
        None,
        verifiable_group_info,
    )
    .expect_err("Signature was corrupted. This should have failed.");
    assert!(matches!(
        result,
        ExternalCommitError::<<Provider as OpenMlsProvider>::StorageError>::PublicGroupError(
            CreationFromExternalError::InvalidGroupInfoSignature
        )
    ));
}

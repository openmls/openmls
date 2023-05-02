use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};

use crate::{
    extensions::{
        ApplicationIdExtension, Extension, ExtensionType, Extensions, RequiredCapabilitiesExtension,
    },
    framing::{validation::ProcessedMessageContent, MlsMessageIn},
    group::errors::UpdateExtensionsError,
    test_utils::*,
    treesync::errors::{LeafNodeValidationError, MemberExtensionValidationError},
};

use super::test_gce_proposals::{group_setup, ALL_CREDENTIAL_TYPES, DEFAULT_PROPOSAL_TYPES};

#[apply(ciphersuites_and_backends)]
fn gce_fails_when_it_contains_unsupported_extensions(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let required_capabilities =
        RequiredCapabilitiesExtension::new(&[], &DEFAULT_PROPOSAL_TYPES, &ALL_CREDENTIAL_TYPES);
    // Bob has been created from a welcome message
    let (mut alice_group, mut bob_group, alice_signer, bob_signer) = group_setup(
        ciphersuite,
        required_capabilities,
        None,
        Extensions::empty(),
        backend,
    );
    // Alice tries to add a required capability she doesn't support herself.
    let required_key_id = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
        &[ExtensionType::ExternalSenders],
        &[],
        &[],
    ));
    let e = alice_group.update_extensions(backend, &alice_signer, Extensions::single(required_key_id.clone()))
        .expect_err("Alice was able to create a gce proposal with a required extensions she doesn't support.");
    assert_eq!(
        e,
        UpdateExtensionsError::MemberExtensionValidationError(
            MemberExtensionValidationError::LeafNodeValidationError(
                LeafNodeValidationError::UnsupportedExtensions
            )
        )
    );
    // Now Bob wants the ExternalSenders extension to be required.
    // This should fail because Alice doesn't support it.
    let e = bob_group
        .update_extensions(backend, &bob_signer, Extensions::single(required_key_id))
        .expect_err("Bob was able to create a gce proposal for an extension not supported by all other parties.");
    assert_eq!(
        e,
        UpdateExtensionsError::MemberExtensionValidationError(
            MemberExtensionValidationError::LeafNodeValidationError(
                LeafNodeValidationError::UnsupportedExtensions
            )
        )
    );
}

#[apply(ciphersuites_and_backends)]
fn gce_commit_can_roundtrip(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let required_capabilities =
        RequiredCapabilitiesExtension::new(&[], &DEFAULT_PROPOSAL_TYPES, &ALL_CREDENTIAL_TYPES);
    let (mut alice_group, mut bob_group, alice_signer, _) = group_setup(
        ciphersuite,
        required_capabilities,
        None,
        Extensions::empty(),
        backend,
    );

    // Alice adds an extension
    let new_extensions = Extensions::single(Extension::ApplicationId(ApplicationIdExtension::new(
        b"test_mls",
    )));
    let (gce_commit, _) = alice_group
        .update_extensions(backend, &alice_signer, new_extensions.clone())
        .unwrap();
    alice_group.merge_pending_commit(backend).unwrap();
    assert_eq!(*alice_group.group_context_extensions(), new_extensions);

    // bob should be able to process the commit
    let processed_message = bob_group
        .process_message(backend, MlsMessageIn::from(gce_commit))
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(gce_commit) = processed_message.into_content() else { panic!("Not a remove proposal");};
    bob_group.merge_staged_commit(backend, *gce_commit).unwrap();
    assert_eq!(*bob_group.group_context_extensions(), new_extensions);
}

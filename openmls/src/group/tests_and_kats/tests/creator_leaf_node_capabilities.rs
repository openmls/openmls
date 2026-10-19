//! Exercises whether a group creator's own leaf node capabilities stay in
//! sync with what the creator's group actually needs.
//!
//! Every leaf the library builds goes through
//! `LeafNodePayload::enforce_capabilities`, which checks the leaf's
//! capabilities against its own ciphersuite, credential type and extensions,
//! and against the group's `RequiredCapabilitiesExtension`.
//!
//! Which policy applies depends on whether the caller set capabilities at all:
//! capabilities set explicitly are held to exactly what was listed
//! (`CapabilitiesPolicy::Reject`), while unset capabilities are derived from
//! the leaf (`CapabilitiesPolicy::Widen`). Widening only ever adds facts about
//! the leaf in hand; the group's required capabilities always have to be
//! declared by the caller.

use tls_codec::{Deserialize, Serialize};

use crate::{
    credentials::{Credential, CredentialType},
    extensions::{
        Extension, ExtensionType, Extensions, RequiredCapabilitiesExtension, UnknownExtension,
    },
    framing::MlsMessageIn,
    group::{
        errors::NewGroupError, tests_and_kats::utils::generate_credential_with_key, MlsGroup,
        MlsGroupCreateConfig,
    },
    key_packages::KeyPackage,
    messages::proposals::ProposalType,
    treesync::{
        errors::LeafNodeValidationError,
        node::leaf_node::{
            Capabilities, CapabilitiesPolicy, LeafNodeBuildError, LeafNodeParameters,
        },
    },
    versions::ProtocolVersion,
};

/// The creator's own leaf node must end up advertising the group's ciphersuite
/// — but which way that is enforced depends on the policy.
///
/// Under the default `CapabilitiesPolicy::Reject`, capabilities that don't
/// cover the group's ciphersuite fail group creation outright. Under
/// `CapabilitiesPolicy::Widen`, the missing ciphersuite is added instead and
/// creation succeeds.
///
/// The capabilities here deliberately carry an *empty* ciphersuite list, so the
/// mismatch holds for every ciphersuite the test matrix runs, not just the ones
/// outside `Capabilities::default()`'s hardcoded list.
#[openmls_test::openmls_test]
fn creator_leaf_node_advertises_group_ciphersuite() {
    let provider = Provider::default();
    let capabilities_without_ciphersuite = Capabilities::builder()
        .credentials(vec![CredentialType::Basic])
        .build();

    // Reject (the default): creation fails rather than silently advertising
    // capabilities that don't match the group.
    let alice_credential =
        generate_credential_with_key("Alice".into(), ciphersuite.signature_algorithm(), &provider);
    let err = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_capabilities(capabilities_without_ciphersuite.clone())
        .build(
            &provider,
            &alice_credential.signer,
            alice_credential.credential_with_key,
        )
        .expect_err("group creation should be rejected: the creator's own leaf doesn't advertise the group's ciphersuite");

    assert!(matches!(
        err,
        NewGroupError::LeafNodeBuild(LeafNodeBuildError::Validation(
            LeafNodeValidationError::CiphersuiteNotInCapabilities
        ))
    ));

    // Widen: the same capabilities are extended to cover the group ciphersuite.
    let bob_credential =
        generate_credential_with_key("Bob".into(), ciphersuite.signature_algorithm(), &provider);
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .capabilities(capabilities_without_ciphersuite)
        .capabilities_policy(CapabilitiesPolicy::Widen)
        .build();
    let bob_group = MlsGroup::new(
        &provider,
        &bob_credential.signer,
        &config,
        bob_credential.credential_with_key,
    )
    .expect("group creation should succeed under the widening policy");

    assert!(
        bob_group
            .own_leaf_node()
            .expect("creator must have an own leaf node")
            .capabilities()
            .ciphersuites()
            .contains(&ciphersuite.into()),
        "widening should have added the group's ciphersuite to the creator's leaf node"
    );
}

/// Regression test: the creator's own leaf node must advertise its own
/// credential type when capabilities are set explicitly.
///
/// Capabilities listing only `Basic` say nothing about the credential actually
/// passed to `MlsGroup::builder()`, so the mismatch is caught at construction
/// time and rejected rather than producing a leaf every peer would refuse.
#[openmls_test::openmls_test]
fn creator_leaf_node_rejects_missing_credential_type() {
    let mut alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        &Provider::default(),
    );
    let provider = Provider::default();

    // Give Alice a non-Basic credential without customizing capabilities to
    // match.
    let custom_credential_type = CredentialType::Other(3);
    alice_credential.credential_with_key.credential =
        Credential::new(custom_credential_type, b"alice".to_vec());

    // Satisfy every dimension except the credential type under test, so the
    // rejection can only come from the credential check.
    let err = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_capabilities(
            Capabilities::builder()
                .ciphersuites(vec![ciphersuite])
                .credentials(vec![CredentialType::Basic])
                .build(),
        )
        .build(
            &provider,
            &alice_credential.signer,
            alice_credential.credential_with_key,
        )
        .expect_err(
            "group creation should be rejected: the creator's own leaf doesn't \
             advertise its own credential type",
        );

    assert!(matches!(
        err,
        NewGroupError::LeafNodeBuild(LeafNodeBuildError::Validation(
            LeafNodeValidationError::CredentialNotInCapabilities
        ))
    ));
}

/// Regression test: the creator's own leaf node must satisfy the
/// `RequiredCapabilitiesExtension` set on the creator's own group.
///
/// The group's `RequiredCapabilitiesExtension` is threaded down to the
/// creator's own leaf construction, so a mismatch is rejected there rather
/// than slipping through uncaught.
#[openmls_test::openmls_test]
fn creator_leaf_node_rejects_unmet_required_capabilities() {
    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        &Provider::default(),
    );
    let provider = Provider::default();

    let required_extension = ExtensionType::Unknown(0xf001);
    let gc_extensions = Extensions::single(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&[required_extension], &[], &[]),
    ))
    .expect("required capabilities extension should be valid in group context");

    // Satisfy every dimension except the required extension under test, so the
    // rejection can only come from the required-capabilities check.
    let err = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_capabilities(
            Capabilities::builder()
                .ciphersuites(vec![ciphersuite])
                .credentials(vec![CredentialType::Basic])
                .build(),
        )
        .with_group_context_extensions(gc_extensions)
        .build(
            &provider,
            &alice_credential.signer,
            alice_credential.credential_with_key,
        )
        .expect_err(
            "group creation should be rejected: the creator's own leaf doesn't \
             satisfy its own required capabilities",
        );

    assert!(matches!(
        err,
        NewGroupError::LeafNodeBuild(LeafNodeBuildError::Validation(
            LeafNodeValidationError::UnsupportedExtensions
        ))
    ));
}

/// The creator's own leaf node must advertise the extensions carried in its
/// own leaf, not just the ones the group requires.
///
/// This is the leaf-extensions check, distinct from the
/// `RequiredCapabilitiesExtension` one below it: here the extension is one the
/// creator put in its *own* leaf.
#[openmls_test::openmls_test]
fn creator_leaf_node_rejects_leaf_extensions_not_in_capabilities() {
    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        &Provider::default(),
    );
    let provider = Provider::default();

    // Satisfy every dimension except the leaf's own extension, so the
    // rejection can only come from the leaf-extension check.
    let err = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_capabilities(
            Capabilities::builder()
                .ciphersuites(vec![ciphersuite])
                .credentials(vec![CredentialType::Basic])
                .build(),
        )
        .with_leaf_node_extensions(
            Extensions::single(Extension::Unknown(
                0xff00,
                UnknownExtension(b"leaf data".to_vec()),
            ))
            .expect("failed to create single-element extensions list"),
        )
        .expect("configuring leaf extensions should not fail eagerly")
        .build(
            &provider,
            &alice_credential.signer,
            alice_credential.credential_with_key,
        )
        .expect_err(
            "group creation should be rejected: the creator's own leaf doesn't \
             advertise its own extension",
        );

    assert!(matches!(
        err,
        NewGroupError::LeafNodeBuild(LeafNodeBuildError::Validation(
            LeafNodeValidationError::ExtensionsNotInCapabilities
        ))
    ));
}

/// The creator's own leaf node must advertise the proposal types its own group
/// requires.
#[openmls_test::openmls_test]
fn creator_leaf_node_rejects_unmet_required_proposals() {
    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        &Provider::default(),
    );
    let provider = Provider::default();

    // Only non-default proposal types are checked, so a custom one is needed
    // to exercise this at all.
    let required_proposal = ProposalType::Custom(0xf00d);
    let gc_extensions = Extensions::single(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&[], &[required_proposal], &[]),
    ))
    .expect("required capabilities extension should be valid in group context");

    // Satisfy every dimension except the required proposal under test.
    let err = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_capabilities(
            Capabilities::builder()
                .ciphersuites(vec![ciphersuite])
                .credentials(vec![CredentialType::Basic])
                .build(),
        )
        .with_group_context_extensions(gc_extensions)
        .build(
            &provider,
            &alice_credential.signer,
            alice_credential.credential_with_key,
        )
        .expect_err(
            "group creation should be rejected: the creator's own leaf doesn't \
             advertise its group's required proposal type",
        );

    assert!(matches!(
        err,
        NewGroupError::LeafNodeBuild(LeafNodeBuildError::Validation(
            LeafNodeValidationError::UnsupportedProposals
        ))
    ));
}

/// The creator's own leaf node must advertise the credential types its own
/// group requires, which is a separate check from advertising the credential
/// the creator itself uses.
#[openmls_test::openmls_test]
fn creator_leaf_node_rejects_unmet_required_credentials() {
    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        &Provider::default(),
    );
    let provider = Provider::default();

    let required_credential = CredentialType::X509;
    let gc_extensions = Extensions::single(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(&[], &[], &[required_credential]),
    ))
    .expect("required capabilities extension should be valid in group context");

    // Alice's own credential is `Basic` and is advertised, so the credential
    // check passes; only the required-credentials check can reject here.
    let err = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_capabilities(
            Capabilities::builder()
                .ciphersuites(vec![ciphersuite])
                .credentials(vec![CredentialType::Basic])
                .build(),
        )
        .with_group_context_extensions(gc_extensions)
        .build(
            &provider,
            &alice_credential.signer,
            alice_credential.credential_with_key,
        )
        .expect_err(
            "group creation should be rejected: the creator's own leaf doesn't \
             advertise its group's required credential type",
        );

    assert!(matches!(
        err,
        NewGroupError::LeafNodeBuild(LeafNodeBuildError::Validation(
            LeafNodeValidationError::UnsupportedCredentials
        ))
    ));
}

/// `CapabilitiesPolicy::Widen` covers every dimension the library can derive
/// from the leaf itself — and stops there.
///
/// Widening adds facts about the leaf in hand: its ciphersuite, its credential
/// type and its own extension types. It deliberately does *not* add the
/// group's `RequiredCapabilitiesExtension` entries, because those are claims
/// about what the application implements and the library cannot make them on
/// its behalf. So a creator that requires something it hasn't declared is
/// rejected even under `Widen`.
#[openmls_test::openmls_test]
fn widening_covers_self_derived_dimensions_only() {
    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        &Provider::default(),
    );
    let provider = Provider::default();

    let leaf_extension_type = ExtensionType::Unknown(0xff01);
    let required_extension = ExtensionType::Unknown(0xf003);
    let required_proposal = ProposalType::Custom(0xf00e);
    let required_credential = CredentialType::X509;

    let gc_extensions = Extensions::single(Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(
            &[required_extension],
            &[required_proposal],
            &[required_credential],
        ),
    ))
    .expect("required capabilities extension should be valid in group context");

    let leaf_extensions = Extensions::single(Extension::Unknown(
        0xff01,
        UnknownExtension(b"leaf data".to_vec()),
    ))
    .expect("failed to create single-element extensions list");

    // Widening alone is not enough: the group's required capabilities are the
    // application's to declare, so creation is rejected rather than having the
    // library assert support on its behalf.
    let err = MlsGroup::new(
        &provider,
        &alice_credential.signer,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            // Empty: no ciphersuite, no credential, no extensions, no proposals.
            .capabilities(Capabilities::builder().build())
            .capabilities_policy(CapabilitiesPolicy::Widen)
            .with_group_context_extensions(gc_extensions.clone())
            .with_leaf_node_extensions(leaf_extensions.clone())
            .expect("configuring leaf extensions should not fail eagerly")
            .build(),
        alice_credential.credential_with_key.clone(),
    )
    .expect_err("widening must not claim support for the group's required capabilities");
    assert!(matches!(
        err,
        NewGroupError::LeafNodeBuild(LeafNodeBuildError::Validation(
            LeafNodeValidationError::UnsupportedExtensions
        ))
    ));

    // Declaring the required capabilities explicitly is enough. The leaf's own
    // ciphersuite, credential type and extension type are still derived.
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .capabilities(
            Capabilities::builder()
                .extensions(vec![required_extension])
                .proposals(vec![required_proposal])
                .credentials(vec![required_credential])
                .build(),
        )
        .capabilities_policy(CapabilitiesPolicy::Widen)
        .with_group_context_extensions(gc_extensions)
        .with_leaf_node_extensions(leaf_extensions)
        .expect("configuring leaf extensions should not fail eagerly")
        .build();

    let alice_group = MlsGroup::new(
        &provider,
        &alice_credential.signer,
        &config,
        alice_credential.credential_with_key,
    )
    .expect("group creation should succeed under the widening policy");

    let capabilities = alice_group
        .own_leaf_node()
        .expect("creator must have an own leaf node")
        .capabilities();

    assert!(
        capabilities.ciphersuites().contains(&ciphersuite.into()),
        "widening did not add the group's ciphersuite"
    );
    assert!(
        capabilities.credentials().contains(&CredentialType::Basic),
        "widening did not add the creator's own credential type"
    );
    assert!(
        capabilities.extensions().contains(&leaf_extension_type),
        "widening did not add the leaf's own extension type"
    );
    // Declared by the caller, not invented by widening.
    assert!(capabilities.extensions().contains(&required_extension));
    assert!(capabilities.proposals().contains(&required_proposal));
    assert!(capabilities.credentials().contains(&required_credential));
}

/// The protocol version is the one dimension that is completed even under
/// `CapabilitiesPolicy::Reject`.
///
/// This is a deliberate asymmetry with every other dimension above, so it is
/// pinned down here: a leaf advertising no version at all is completed rather
/// than rejected.
#[openmls_test::openmls_test]
fn creator_leaf_node_always_advertises_protocol_version() {
    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        &Provider::default(),
    );
    let provider = Provider::default();

    let alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_capabilities(Capabilities::new(
            Some(&[]), // no versions advertised at all
            Some(&[ciphersuite]),
            None,
            None,
            Some(&[CredentialType::Basic]),
        ))
        .build(
            &provider,
            &alice_credential.signer,
            alice_credential.credential_with_key,
        )
        .expect("group creation should succeed: the version is added, not rejected");

    assert!(
        alice_group
            .own_leaf_node()
            .expect("creator must have an own leaf node")
            .capabilities()
            .versions()
            .contains(&ProtocolVersion::Mls10),
        "the leaf's own protocol version should have been added to its capabilities"
    );
}

/// Regression test for the analogous bug in `KeyPackageBuilder`: a new
/// member's own `KeyPackage` leaf must advertise the ciphersuite it was built
/// for, even when capabilities are left at their default.
#[openmls_test::openmls_test]
fn key_package_advertises_its_own_ciphersuite() {
    let bob_credential = generate_credential_with_key(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        &Provider::default(),
    );
    let provider = Provider::default();

    let bob_key_package_bundle = KeyPackage::builder()
        .build(
            ciphersuite,
            &provider,
            &bob_credential.signer,
            bob_credential.credential_with_key,
        )
        .expect("key package creation should succeed");

    let capabilities = bob_key_package_bundle
        .key_package()
        .leaf_node()
        .capabilities();

    assert!(
        capabilities.ciphersuites().contains(&ciphersuite.into()),
        "key package's own leaf node does not advertise its own ciphersuite"
    );
}

/// Regression test for the member-commit path: a self-update whose caller
/// supplies explicit capabilities that omit the group's ciphersuite must
/// still produce a leaf advertising that ciphersuite.
///
/// `compute_path`'s `CommitType::Member` arm takes caller-supplied
/// capabilities verbatim when `LeafNodeParameters::capabilities()` is `Some`,
/// so the ciphersuite is only inherited from the previous leaf when the caller
/// passes nothing. Enforcing the invariant in `LeafNodeTbs::new` covers this
/// case too.
#[openmls_test::openmls_test]
fn self_update_leaf_advertises_group_ciphersuite() {
    let provider = &Provider::default();
    let alice_credential =
        generate_credential_with_key("Alice".into(), ciphersuite.signature_algorithm(), provider);

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(
            provider,
            &alice_credential.signer,
            alice_credential.credential_with_key,
        )
        .expect("group creation should succeed");

    // Capabilities that deliberately advertise only a ciphersuite the group
    // does not use.
    let decoy = if ciphersuite == Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 {
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    } else {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    };
    let leaf_node_parameters = LeafNodeParameters::builder()
        .with_capabilities(Capabilities::new(None, Some(&[decoy]), None, None, None))
        .with_capabilities_policy(CapabilitiesPolicy::Widen)
        .build();

    alice_group
        .self_update(provider, &alice_credential.signer, leaf_node_parameters)
        .expect("self update should succeed");
    alice_group
        .merge_pending_commit(provider)
        .expect("merging the self update should succeed");

    let capabilities = alice_group
        .own_leaf_node()
        .expect("alice must have an own leaf node")
        .capabilities();

    assert!(
        capabilities.ciphersuites().contains(&ciphersuite.into()),
        "self-updated leaf node does not advertise the group's own ciphersuite"
    );
}

/// Covers `PublicGroupDiff::compute_path`'s `CommitType::External` arm: an
/// external committer's new leaf must advertise the group's ciphersuite.
///
/// As with the creator, the policy decides how that is enforced. Leaving the
/// external commit's leaf node parameters at their default is rejected (the
/// default capabilities don't cover an arbitrary ciphersuite); asking for
/// `CapabilitiesPolicy::Widen` adds the group's ciphersuite instead.
#[openmls_test::openmls_test]
fn external_committer_leaf_advertises_group_ciphersuite() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let bob_credential = generate_credential_with_key(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(
            alice_provider,
            &alice_credential.signer,
            alice_credential.credential_with_key,
        )
        .expect("group creation should succeed");

    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_credential.signer, false)
        .expect("exporting group info should succeed")
        .into_verifiable_group_info()
        .expect("group info should be verifiable");
    let ratchet_tree = alice_group.export_ratchet_tree();

    let (bob_group, public_message_commit) = MlsGroup::external_commit_builder()
        .with_config(alice_group.configuration().clone())
        .with_ratchet_tree(ratchet_tree.into())
        .build_group(
            bob_provider,
            verifiable_group_info,
            bob_credential.credential_with_key,
        )
        .expect("external commit builder setup should succeed")
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities_policy(CapabilitiesPolicy::Widen)
                .build(),
        )
        .load_psks(bob_provider.storage())
        .expect("loading psks should succeed")
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_credential.signer,
            |_| true,
        )
        .expect("building the external commit should succeed")
        .finalize(bob_provider)
        .expect("finalizing the external commit should succeed");

    let capabilities = bob_group
        .own_leaf_node()
        .expect("external committer must have an own leaf node")
        .capabilities();

    assert!(
        capabilities.ciphersuites().contains(&ciphersuite.into()),
        "external committer's own leaf node does not advertise the group's own ciphersuite"
    );

    // Sanity-check that Alice can still process Bob's commit.
    let public_message_commit = {
        let serialized_message = public_message_commit
            .into_commit()
            .tls_serialize_detached()
            .expect("serializing the commit should succeed");

        MlsMessageIn::tls_deserialize(&mut serialized_message.as_slice())
            .expect("deserializing the commit should succeed")
            .into_plaintext()
            .expect("the commit should be a plaintext message")
    };
    alice_group
        .process_message(alice_provider, public_message_commit)
        .expect("alice should be able to process bob's external commit");
}

/// Regression test for the third variant of the same bug: the
/// virtual-clients batch KeyPackage builder
/// (`VcKeyPackageBatchBuilder::build_vc_key_package_for_index`, reached via
/// `KeyPackageBuilder::build_vc_batch`, see `openmls/src/key_packages/vc.rs`)
/// also defaulted to `Capabilities::default()` instead of the ciphersuite the
/// batch is built for.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn vc_key_package_batch_advertises_its_own_ciphersuite() {
    use crate::{
        components::vc_derivation_info::VC_COMPONENT_ID,
        extensions::{AppDataDictionary, AppDataDictionaryExtension},
        group::{MlsGroupCreateConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY},
        treesync::node::leaf_node::{Capabilities, CapabilitiesPolicy},
    };
    use tls_codec::Serialize as _;

    let provider = Provider::default();

    // VC-capable leaf config: declares AppDataDictionary support and lists
    // VC_COMPONENT_ID in its AppComponents entry, as `build_vc_batch`
    // requires. Deliberately doesn't set ciphersuites, relying on
    // `CapabilitiesPolicy::Widen` to add the leaf's own ciphersuite instead
    // of the (now rejecting-by-default) construction failing outright.
    let vc_capabilities = Capabilities::builder()
        .extensions(vec![ExtensionType::AppDataDictionary])
        .build();
    let vc_leaf_extensions = {
        let supported_components: Vec<u16> = vec![VC_COMPONENT_ID];
        let app_components_body = supported_components
            .tls_serialize_detached()
            .expect("serialize AppComponents body");
        let mut dictionary = AppDataDictionary::new();
        dictionary.insert(1, app_components_body);
        let ext = Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
        Extensions::from_vec(vec![ext]).expect("build leaf-node Extensions")
    };

    // Emulator group: `build_vc_batch` derives from its newest derivation
    // epoch.
    let emulator_credential = generate_credential_with_key(
        "Emulator".into(),
        ciphersuite.signature_algorithm(),
        &provider,
    );
    let emulator_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities.clone())
        .capabilities_policy(CapabilitiesPolicy::Widen)
        .with_leaf_node_extensions(vc_leaf_extensions.clone())
        .expect("attach emulator leaf-node extensions")
        .emulation_group(true)
        .build();
    let emulator = MlsGroup::new(
        &provider,
        &emulator_credential.signer,
        &emulator_config,
        emulator_credential.credential_with_key,
    )
    .expect("create emulator group");

    let vc_credential = generate_credential_with_key(
        "VirtualClient".into(),
        ciphersuite.signature_algorithm(),
        &provider,
    );

    let mut batch = KeyPackage::builder()
        .leaf_node_capabilities(vc_capabilities)
        .leaf_node_extensions(vc_leaf_extensions)
        .capabilities_policy(CapabilitiesPolicy::Widen)
        .build_vc_batch(
            ciphersuite,
            &provider,
            &vc_credential.signer,
            vc_credential.credential_with_key,
            emulator.group_id(),
            1,
        )
        .expect("build_vc_batch should succeed");

    let (bundle, _) = batch.key_packages.remove(0);
    let capabilities = bundle.key_package().leaf_node().capabilities();

    assert!(
        capabilities.ciphersuites().contains(&ciphersuite.into()),
        "virtual-client key package's own leaf node does not advertise its own ciphersuite"
    );
}

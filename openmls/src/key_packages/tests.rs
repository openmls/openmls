use crate::{
    prelude::ExtensionTypeNotValidInLeafNodeError, test_utils::*,
    treesync::node::leaf_node::Capabilities,
};
use openmls_basic_credential::SignatureKeyPair;

use tls_codec::Deserialize;

use crate::{extensions::errors::*, extensions::*, key_packages::*, storage::OpenMlsProvider};

/// Helper function to generate key packages
pub(crate) fn key_package(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) -> (KeyPackageBundle, Credential, SignatureKeyPair) {
    let credential = BasicCredential::new(b"Sasha".to_vec());
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    // Generate a valid KeyPackage.
    let key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            provider,
            &signer,
            CredentialWithKey {
                credential: credential.clone().into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .expect("An unexpected error occurred.");

    (key_package, credential.into(), signer)
}

/// Ensure that invalid leaf node extensions cannot be added to the KeyPackage
#[test]
fn key_package_builder_leaf_node_extensions_validation() {
    // create an extension that is invalid in the leaf node
    let extension = Extension::ExternalSenders(ExternalSendersExtension::new());
    assert!(!extension.extension_type().is_valid_in_leaf_node());

    let extensions_result: Result<Extensions<LeafNode>, _> = Extensions::single(extension);
    let err = extensions_result
        .expect_err("expected validation to fail because this type is not valid in leaf nodes");

    assert_eq!(
        err,
        InvalidExtensionError::ExtensionTypeNotValidInLeafNode(
            ExtensionTypeNotValidInLeafNodeError(ExtensionType::ExternalSenders)
        ),
    );
}

#[test]
fn key_package_rejects_unsupported_ciphersuite() {
    use crate::test_utils::restricted_provider::RestrictedProvider;

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    // The provider supports some ciphersuite, but not `ciphersuite`.
    let provider =
        RestrictedProvider::new(vec![Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256]);

    // The signer matches the ciphersuite's signature scheme, so the
    // ciphersuite/signature-scheme mismatch check passes and the provider
    // support check is what fails.
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential = BasicCredential::new(b"Sasha".to_vec());

    let err = KeyPackage::builder()
        .build(
            ciphersuite,
            &provider,
            &signer,
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .expect_err("key package creation should fail for an unsupported ciphersuite");

    assert!(matches!(
        err,
        KeyPackageNewError::UnsupportedCiphersuite(cs) if cs == ciphersuite
    ));
}

#[openmls_test::openmls_test]
fn generate_key_package() {
    let provider = &Provider::default();
    let (key_package, _credential, _signature_keys) = key_package(ciphersuite, provider);

    let kpi = KeyPackageIn::from(key_package.key_package().clone());
    assert!(kpi
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .is_ok());
}

#[openmls_test::openmls_test]
fn serialization() {
    let provider = &Provider::default();
    let (key_package, _, _) = key_package(ciphersuite, provider);

    let encoded = key_package
        .key_package()
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    let decoded_key_package = KeyPackage::from(
        KeyPackageIn::tls_deserialize(&mut encoded.as_slice())
            .expect("An unexpected error occurred."),
    );
    assert_eq!(key_package.key_package(), &decoded_key_package);
}

#[openmls_test::openmls_test]
fn application_id_extension() {
    let provider = &Provider::default();
    let credential = BasicCredential::new(b"Sasha".to_vec());
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    // Generate a valid KeyPackage.
    let id = b"application id" as &[u8];
    let key_package = KeyPackage::builder()
        .leaf_node_extensions(
            Extensions::single(Extension::ApplicationId(ApplicationIdExtension::new(id)))
                .expect("failed to create single-element extensions list"),
        )
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential: credential.into(),
            },
        )
        .expect("An unexpected error occurred.");

    let kpi = KeyPackageIn::from(key_package.key_package().clone());
    assert!(kpi
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .is_ok());

    // Check ID
    assert_eq!(
        Some(id),
        key_package
            .key_package()
            .leaf_node()
            .extensions()
            .application_id()
            .map(|e| e.as_slice())
    );
}

/// Test that the key package is correctly validated:
/// - The protocol version is correct
/// - The init key is not equal to the encryption key
#[openmls_test::openmls_test]
fn key_package_validation() {
    let provider = &Provider::default();
    let (key_package_orig, _, _) = key_package(ciphersuite, provider);

    // === Protocol version ===

    let mut franken_key_package =
        frankenstein::FrankenKeyPackage::from(key_package_orig.key_package().clone());
    // Set an invalid protocol version
    franken_key_package.protocol_version = 999;

    let key_package_in = KeyPackageIn::from(franken_key_package);

    let err = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap_err();

    // Expect an invalid protocol version error
    assert_eq!(err, KeyPackageVerifyError::InvalidProtocolVersion);

    // === Init/encryption key ===

    let mut franken_key_package =
        frankenstein::FrankenKeyPackage::from(key_package_orig.key_package().clone());
    // Set an invalid init key
    franken_key_package.init_key = franken_key_package.leaf_node.encryption_key.clone();

    let key_package_in = KeyPackageIn::from(franken_key_package);

    let err = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap_err();

    // Expect an invalid init/encryption key error
    assert_eq!(err, KeyPackageVerifyError::InitKeyEqualsEncryptionKey);
}

#[cfg(feature = "extensions-draft")]
fn last_resort_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![ExtensionType::AppDataDictionary])
        .build()
}

#[cfg(not(feature = "extensions-draft"))]
fn last_resort_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![ExtensionType::LastResort])
        .build()
}

#[cfg(feature = "extensions-draft")]
fn assert_last_resort_encoding(key_package: &KeyPackage) {
    assert!(key_package.last_resort());
    assert!(!key_package.extensions().contains(ExtensionType::LastResort));

    let dictionary = key_package
        .extensions()
        .app_data_dictionary()
        .expect("last-resort KeyPackage should contain app_data_dictionary")
        .dictionary();
    assert_eq!(dictionary.get(&last_resort_component_id()), Some(&[][..]));
}

#[cfg(not(feature = "extensions-draft"))]
fn assert_last_resort_encoding(key_package: &KeyPackage) {
    assert!(key_package.last_resort());
    assert!(key_package.extensions().contains(ExtensionType::LastResort));
}

/// Building a last-resort KeyPackage fails before producing an invalid
/// KeyPackage when the marker's extension is absent from the LeafNode
/// capabilities.
#[openmls_test::openmls_test]
fn last_resort_key_package_requires_capability() {
    let provider = &Provider::default();
    let credential = Credential::from(BasicCredential::new(b"Sasha".to_vec()));
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let required_extension = last_resort_capabilities().extensions()[0];
    let builder = KeyPackage::builder().mark_as_last_resort();

    // Exercise the draft migration failure mode specifically: advertising the
    // legacy extension no longer covers the AppDataDictionary marker.
    #[cfg(feature = "extensions-draft")]
    let builder = builder.leaf_node_capabilities(
        Capabilities::builder()
            .extensions(vec![ExtensionType::LastResort])
            .build(),
    );

    let error = builder
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential,
            },
        )
        .expect_err("missing last-resort capability must fail during KeyPackage creation");

    assert_eq!(
        error,
        KeyPackageNewError::MissingLastResortCapability(required_extension)
    );
}

/// Test that a KeyPackage is correctly built with a last-resort marker when
/// the last-resort flag is set during the build process.
#[openmls_test::openmls_test]
fn last_resort_key_package() {
    let provider = &Provider::default();
    let credential = Credential::from(BasicCredential::new(b"Sasha".to_vec()));
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    // build without any other extensions
    let key_package = KeyPackage::builder()
        .leaf_node_capabilities(last_resort_capabilities())
        .mark_as_last_resort()
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential: credential.clone(),
            },
        )
        .expect("An unexpected error occurred.");
    assert_last_resort_encoding(key_package.key_package());

    let encoded = key_package
        .key_package()
        .tls_serialize_detached()
        .expect("failed to serialize last-resort KeyPackage");
    let decoded = KeyPackageIn::tls_deserialize(&mut encoded.as_slice())
        .expect("failed to deserialize last-resort KeyPackage")
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .expect("failed to validate last-resort KeyPackage");
    assert_last_resort_encoding(&decoded);

    // build with empty extensions
    let key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(last_resort_capabilities())
        .mark_as_last_resort()
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential: credential.clone(),
            },
        )
        .expect("An unexpected error occurred.");
    assert_last_resort_encoding(key_package.key_package());

    // build with extension
    let key_package = KeyPackage::builder()
        .key_package_extensions(
            Extensions::single(Extension::Unknown(0xFF00, UnknownExtension(vec![0x00])))
                .expect("failed to create single-element extensions list"),
        )
        .leaf_node_capabilities(last_resort_capabilities())
        .mark_as_last_resort()
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential: credential.clone(),
            },
        )
        .expect("An unexpected error occurred.");
    assert_last_resort_encoding(key_package.key_package());

    #[cfg(feature = "extensions-draft")]
    {
        let private_component_id = 0x8001;
        let private_component_data = vec![1, 2, 3];
        let mut dictionary = AppDataDictionary::new();
        dictionary.insert(private_component_id, private_component_data.clone());
        dictionary.insert(last_resort_component_id(), vec![0xff]);
        let extensions = Extensions::from_vec(vec![
            Extension::LastResort(LastResortExtension::new()),
            Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary)),
        ])
        .expect("failed to create KeyPackage extensions");

        let key_package = KeyPackage::builder()
            .key_package_extensions(extensions)
            .leaf_node_capabilities(last_resort_capabilities())
            .mark_as_last_resort()
            .build(
                ciphersuite,
                provider,
                &signature_keys,
                CredentialWithKey {
                    signature_key: signature_keys.to_public_vec().into(),
                    credential: credential.clone(),
                },
            )
            .expect("failed to build last-resort KeyPackage");

        assert_last_resort_encoding(key_package.key_package());
        assert_eq!(
            key_package
                .key_package()
                .extensions()
                .app_data_dictionary()
                .expect("missing app_data_dictionary")
                .dictionary()
                .get(&private_component_id),
            Some(private_component_data.as_slice())
        );
    }
}

#[cfg(feature = "extensions-draft")]
#[openmls_test::openmls_test]
fn malformed_last_resort_component_is_rejected() {
    let provider = &Provider::default();
    let credential = Credential::from(BasicCredential::new(b"Sasha".to_vec()));
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(last_resort_component_id(), vec![1]);

    let key_package = KeyPackage::builder()
        .key_package_extensions(
            Extensions::single(Extension::AppDataDictionary(
                AppDataDictionaryExtension::new(dictionary),
            ))
            .expect("failed to create app_data_dictionary extension"),
        )
        .leaf_node_capabilities(last_resort_capabilities())
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential,
            },
        )
        .expect("failed to build malformed KeyPackage fixture");

    assert!(!key_package.key_package().last_resort());
    let error = KeyPackageIn::from(key_package.key_package().clone())
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .expect_err("non-empty last-resort component data must be rejected");
    assert_eq!(error, KeyPackageVerifyError::MalformedLastResortComponent);
}

#[cfg(feature = "extensions-draft")]
#[openmls_test::openmls_test]
fn legacy_last_resort_extension_is_still_recognized() {
    let provider = &Provider::default();
    let credential = Credential::from(BasicCredential::new(b"Sasha".to_vec()));
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let key_package = KeyPackage::builder()
        .key_package_extensions(
            Extensions::single(Extension::LastResort(LastResortExtension::new()))
                .expect("failed to create legacy last-resort extension"),
        )
        .leaf_node_capabilities(
            Capabilities::builder()
                .extensions(vec![ExtensionType::LastResort])
                .build(),
        )
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential,
            },
        )
        .expect("failed to build legacy last-resort KeyPackage");

    assert!(key_package.key_package().last_resort());
}

/// Build a batch of virtual-client KeyPackages and verify the first carries a
/// reproducible derivation info. Registers an emulation epoch on a VC-capable
/// emulator group, calls `build_vc_batch`, and checks that the batch reports
/// generation 0, that the first leaf carries a `VC_COMPONENT_ID` entry in its
/// `app_data_dictionary`, and that the embedded `DerivationInfo` decrypts
/// (with the epoch's encryption key) to a `DerivationInfoTbe` whose
/// `leaf_index`, `generation`, and `key_package_index` match the emulator
/// leaf, the consumed generation, and the batch index. Also checks that a
/// count of 0 is rejected with `EmptyBatch`.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn build_vc_key_package_carries_reproducible_derivation_info() {
    use crate::{
        components::vc_derivation_info::{
            DerivationInfo, DerivationInfoTbe, EmulationEpochState, VirtualClientOperationType,
            VC_COMPONENT_ID,
        },
        credentials::test_utils::new_credential,
        extensions::{AppDataDictionary, AppDataDictionaryExtension},
        group::{MlsGroup, MlsGroupCreateConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY},
        key_packages::errors::KeyPackageNewError,
        treesync::node::leaf_node::Capabilities,
    };
    use tls_codec::{DeserializeBytes as _, Serialize as _};

    let provider = Provider::default();

    // VC-capable leaf config: declares AppDataDictionary support and lists
    // VC_COMPONENT_ID in its AppComponents entry (component id 1).
    let capabilities = Capabilities::builder()
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

    // Emulator group: source of safe_export_secret(VC_COMPONENT_ID).
    let (emulator_credential, emulator_signer) =
        new_credential(&provider, b"Emulator", ciphersuite.signature_algorithm());
    let emulator_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities.clone())
        .with_leaf_node_extensions(vc_leaf_extensions.clone())
        .expect("attach emulator leaf-node extensions")
        .build();
    let mut emulator = MlsGroup::new(
        &provider,
        &emulator_signer,
        &emulator_config,
        emulator_credential,
    )
    .expect("create emulator group");
    let emulation_leaf_index = emulator.own_leaf_index();

    let epoch_id = emulator
        .register_vc_emulation_epoch(provider.crypto(), provider.storage())
        .expect("register vc emulation epoch");

    // The virtual client's own signing identity for the KeyPackage.
    let (vc_credential, vc_signer) = new_credential(
        &provider,
        b"VirtualClient",
        ciphersuite.signature_algorithm(),
    );

    // A count of 0 is rejected before any state is loaded or consumed.
    let empty = KeyPackage::builder().build_vc_batch(
        ciphersuite,
        &provider,
        &vc_signer,
        vc_credential.clone(),
        epoch_id.clone(),
        0,
    );
    assert_eq!(empty.unwrap_err(), KeyPackageNewError::EmptyBatch);

    let mut batch = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .leaf_node_extensions(vc_leaf_extensions)
        .build_vc_batch(
            ciphersuite,
            &provider,
            &vc_signer,
            vc_credential,
            epoch_id.clone(),
            1,
        )
        .expect("build_vc_batch must succeed");

    assert_eq!(
        batch.generation, 0,
        "the first key_package operation must consume generation 0"
    );
    assert_eq!(
        batch.key_packages.len(),
        1,
        "a count of 1 must produce one KeyPackage"
    );
    let (bundle, key_package_info) = batch.key_packages.remove(0);
    assert_eq!(
        key_package_info.key_package_index, 0,
        "the only KeyPackage in the batch has index 0"
    );

    // The leaf carries a VC_COMPONENT_ID entry in its app_data_dictionary.
    let leaf = bundle.key_package().leaf_node();
    let dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .expect("leaf must carry an AppDataDictionary extension")
        .dictionary();
    let derivation_info_bytes = dictionary
        .get(&VC_COMPONENT_ID)
        .expect("leaf must carry a VC_COMPONENT_ID entry");

    // The embedded DerivationInfo decrypts with the epoch's encryption key.
    let state: EmulationEpochState = provider
        .storage()
        .vc_emulation_epoch_state(&epoch_id)
        .expect("load emulation epoch state")
        .expect("emulation epoch state present");
    let (_leaf_index, epoch_encryption_key, emulation_ciphersuite) = state.into_parts();
    let derivation_info = DerivationInfo::tls_deserialize_exact_bytes(derivation_info_bytes)
        .expect("deserialize DerivationInfo");
    assert_eq!(derivation_info.epoch_id(), &epoch_id);
    let leaf_encryption_key = leaf
        .encryption_key()
        .tls_serialize_detached()
        .expect("serialize leaf encryption key");
    let tbe = derivation_info
        .decrypt(
            provider.crypto(),
            emulation_ciphersuite,
            &epoch_encryption_key,
            &leaf_encryption_key,
            VirtualClientOperationType::KeyPackage,
        )
        .expect("decrypt DerivationInfoTbe");
    let DerivationInfoTbe::KeyPackage {
        leaf_index,
        generation: tbe_generation,
        key_package_index,
    } = tbe
    else {
        panic!("a key-package leaf must decode to the KeyPackage variant");
    };
    assert_eq!(leaf_index, emulation_leaf_index);
    assert_eq!(tbe_generation, batch.generation);
    assert_eq!(key_package_index, key_package_info.key_package_index);
}

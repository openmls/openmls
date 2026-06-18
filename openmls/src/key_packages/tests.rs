use crate::{prelude::ExtensionTypeNotValidInLeafNodeError, test_utils::*};
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

/// Test that a key package is correctly built with a last resort extension when
/// the last resort flag is set during the build process.
#[openmls_test::openmls_test]
fn last_resort_key_package() {
    let provider = &Provider::default();
    let credential = Credential::from(BasicCredential::new(b"Sasha".to_vec()));
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    // build without any other extensions
    let key_package = KeyPackage::builder()
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
    assert!(key_package.key_package().last_resort());

    // build with empty extensions
    let key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
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
    assert!(key_package.key_package().last_resort());

    // build with extension
    let key_package = KeyPackage::builder()
        .key_package_extensions(
            Extensions::single(Extension::Unknown(0xFF00, UnknownExtension(vec![0x00])))
                .expect("failed to create single-element extensions list"),
        )
        .mark_as_last_resort()
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential,
            },
        )
        .expect("An unexpected error occurred.");
    assert!(key_package.key_package().last_resort());
}

/// Build a batch of virtual-client KeyPackages and verify the first carries a
/// reproducible derivation info. Registers an emulation epoch on a VC-capable
/// emulator group, calls `build_vc_batch`, and checks that the batch reports
/// generation 0, that the first leaf carries a `VC_COMPONENT_ID` entry in its
/// `app_data_dictionary`, and that the embedded `DerivationInfo` decrypts
/// (with the epoch's encryption key) to a `DerivationInfoTbe` whose
/// `leaf_index`, `generation`, and `key_package_index` match the emulator
/// leaf, the consumed generation, and the batch index.
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

    let (generation, mut batch) = KeyPackage::builder()
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
        generation, 0,
        "the first key_package operation must consume generation 0"
    );
    assert_eq!(batch.len(), 1, "a count of 1 must produce one KeyPackage");
    let (bundle, key_package_info) = batch.remove(0);
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
    assert_eq!(tbe_generation, generation);
    assert_eq!(key_package_index, key_package_info.key_package_index);
}

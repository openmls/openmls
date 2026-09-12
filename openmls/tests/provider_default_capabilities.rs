use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, CredentialWithKey, KeyPackage, MlsGroup,
    MlsGroupCreateConfig, OpenMlsProvider as _, VerifiableCiphersuite,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;

fn credential(signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(b"provider capability test".to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    }
}

fn non_grease_ciphersuites(capabilities: &Capabilities) -> Vec<VerifiableCiphersuite> {
    capabilities
        .ciphersuites()
        .iter()
        .filter(|suite| !suite.is_grease())
        .copied()
        .collect()
}

fn first_supported_ciphersuite(provider: &OpenMlsRustCrypto) -> Ciphersuite {
    provider
        .crypto()
        .supported_ciphersuites()
        .into_iter()
        .next()
        .expect("the test provider must support at least one ciphersuite")
}

#[test]
fn implicit_group_and_key_package_capabilities_follow_the_provider() {
    let provider = OpenMlsRustCrypto::default();
    let ciphersuite = first_supported_ciphersuite(&provider);
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .expect("the supported ciphersuite must have a signer");
    let expected = Capabilities::for_provider(provider.crypto());

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();
    let group = MlsGroup::new(&provider, &signer, &config, credential(&signer))
        .expect("group creation with a supported ciphersuite must succeed");
    assert_eq!(
        non_grease_ciphersuites(
            group
                .own_leaf_node()
                .expect("a newly created group must contain its own leaf")
                .capabilities(),
        ),
        expected.ciphersuites()
    );

    let group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(&provider, &signer, credential(&signer))
        .expect("builder-based group creation must succeed");
    assert_eq!(
        non_grease_ciphersuites(
            group
                .own_leaf_node()
                .expect("a newly created group must contain its own leaf")
                .capabilities(),
        ),
        expected.ciphersuites()
    );

    let key_package = KeyPackage::builder()
        .build(ciphersuite, &provider, &signer, credential(&signer))
        .expect("key package creation with a supported ciphersuite must succeed");
    assert_eq!(
        non_grease_ciphersuites(key_package.key_package().leaf_node().capabilities()),
        expected.ciphersuites()
    );
}

#[test]
fn explicit_group_and_key_package_capabilities_are_preserved() {
    let provider = OpenMlsRustCrypto::default();
    let ciphersuite = first_supported_ciphersuite(&provider);
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .expect("the supported ciphersuite must have a signer");

    for expected in [
        Capabilities::default(),
        Capabilities::new(None, Some(&[ciphersuite]), None, None, None),
        Capabilities::new(None, Some(&[]), None, None, None),
    ] {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .capabilities(expected.clone())
            .build();
        let group = MlsGroup::new(&provider, &signer, &config, credential(&signer))
            .expect("explicit capabilities must permit group creation");
        assert_eq!(
            non_grease_ciphersuites(
                group
                    .own_leaf_node()
                    .expect("a newly created group must contain its own leaf")
                    .capabilities(),
            ),
            expected.ciphersuites()
        );

        let group = MlsGroup::builder()
            .ciphersuite(ciphersuite)
            .with_capabilities(expected.clone())
            .build(&provider, &signer, credential(&signer))
            .expect("explicit builder capabilities must permit group creation");
        assert_eq!(
            non_grease_ciphersuites(
                group
                    .own_leaf_node()
                    .expect("a newly created group must contain its own leaf")
                    .capabilities(),
            ),
            expected.ciphersuites()
        );

        let key_package = KeyPackage::builder()
            .leaf_node_capabilities(expected.clone())
            .build(ciphersuite, &provider, &signer, credential(&signer))
            .expect("explicit capabilities must permit key package creation");
        assert_eq!(
            non_grease_ciphersuites(key_package.key_package().leaf_node().capabilities()),
            expected.ciphersuites()
        );
    }
}

#[test]
fn serialized_create_configs_preserve_the_existing_wire_shape() {
    let implicit = MlsGroupCreateConfig::builder().build();
    let explicit = MlsGroupCreateConfig::builder()
        .capabilities(Capabilities::default())
        .build();

    let implicit_value =
        serde_json::to_value(&implicit).expect("the implicit config must serialize");
    let explicit_value =
        serde_json::to_value(&explicit).expect("the explicit config must serialize");

    assert!(implicit_value.get("capabilities_source").is_none());
    assert_eq!(implicit_value, explicit_value);

    let decoded: MlsGroupCreateConfig =
        serde_json::from_value(implicit_value).expect("the existing config shape must decode");
    assert_eq!(implicit, decoded);
}

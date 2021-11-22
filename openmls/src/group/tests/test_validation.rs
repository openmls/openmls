//! This module contains all tests regarding the validation of incoming messages
//! as defined in https://github.com/openmls/openmls/wiki/Message-validation

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme, OpenMlsCryptoProvider};
use tls_codec::{Deserialize, Serialize};

use crate::{
    ciphersuite::{Ciphersuite, CiphersuiteName},
    credentials::{Credential, CredentialBundle, CredentialError, CredentialType},
    extensions::Extension,
    framing::{MlsCiphertext, MlsMessageIn, VerifiableMlsPlaintext},
    group::{
        FramingValidationError, GroupId, ManagedGroup, ManagedGroupConfig, ManagedGroupError,
        MlsGroupError, WireFormat,
    },
    key_packages::{KeyPackage, KeyPackageBundle, KeyPackageError},
};

fn generate_credential_bundle(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_scheme: SignatureScheme,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<Credential, CredentialError> {
    let cb = CredentialBundle::new(identity, credential_type, signature_scheme, backend)?;
    let credential = cb.credential().clone();
    backend
        .key_store()
        .store(credential.signature_key(), &cb)
        .unwrap();
    Ok(credential)
}

fn generate_key_package_bundle(
    ciphersuites: &[CiphersuiteName],
    credential: &Credential,
    extensions: Vec<Extension>,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<KeyPackage, KeyPackageError> {
    let credential_bundle = backend
        .key_store()
        .read(credential.signature_key())
        .unwrap();
    let kpb = KeyPackageBundle::new(ciphersuites, &credential_bundle, backend, extensions)?;
    let kp = kpb.key_package().clone();
    backend.key_store().store(&kp.hash(backend), &kpb).unwrap();
    Ok(kp)
}

#[cfg(test)]
struct ValidationTestSetup {
    backend: OpenMlsRustCrypto,
    alice_group: ManagedGroup,
    alice_credential: Credential,
    bob_credential: Credential,
    alice_key_package: KeyPackage,
    bob_key_package: KeyPackage,
}

#[cfg(test)]
fn validation_test_setup(wire_format: WireFormat) -> ValidationTestSetup {
    let backend = OpenMlsRustCrypto::default();

    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).unwrap();
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credential bundles
    let alice_credential = generate_credential_bundle(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        &backend,
    )
    .unwrap();

    let bob_credential = generate_credential_bundle(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        &backend,
    )
    .unwrap();

    // Generate KeyPackages
    let alice_key_package =
        generate_key_package_bundle(&[ciphersuite.name()], &alice_credential, vec![], &backend)
            .unwrap();

    let bob_key_package =
        generate_key_package_bundle(&[ciphersuite.name()], &bob_credential, vec![], &backend)
            .unwrap();

    // Define the managed group configuration

    let managed_group_config = ManagedGroupConfig::builder()
        .wire_format(wire_format)
        .build();

    // === Alice creates a group ===
    let alice_group = ManagedGroup::new(
        &backend,
        &managed_group_config,
        group_id,
        &alice_key_package.hash(&backend),
    )
    .unwrap();

    ValidationTestSetup {
        backend,
        alice_group,
        alice_credential,
        bob_credential,
        alice_key_package,
        bob_key_package,
    }
}

#[test]
fn test_valsem1() {
    // Test with MlsPlaintext
    let ValidationTestSetup {
        backend,
        mut alice_group,
        alice_credential: _,
        bob_credential: _,
        alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(WireFormat::MlsPlaintext);

    let (message, _welcome) = alice_group
        .add_members(&backend, &[bob_key_package])
        .expect("Could not add member.");

    let mut serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    serialized_message[0] = WireFormat::MlsCiphertext as u8;

    let err = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect_err("Could deserialize message despite wrong wire format.");

    assert_eq!(
        err,
        tls_codec::Error::DecodingError("Wrong wire format.".to_string())
    );

    // Test with MlsCiphertext
    let ValidationTestSetup {
        backend,
        mut alice_group,
        alice_credential: _,
        bob_credential: _,
        alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(WireFormat::MlsCiphertext);

    let (message, _welcome) = alice_group
        .add_members(&backend, &[bob_key_package])
        .expect("Could not add member.");

    let mut serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    serialized_message[0] = WireFormat::MlsPlaintext as u8;

    let err = MlsCiphertext::tls_deserialize(&mut serialized_message.as_slice())
        .expect_err("Could deserialize message despite wrong wire format.");

    assert_eq!(
        err,
        tls_codec::Error::DecodingError("Wrong wire format.".to_string())
    );
}

#[test]
fn test_valsem2() {
    let ValidationTestSetup {
        backend,
        mut alice_group,
        alice_credential: _,
        bob_credential: _,
        alice_key_package: _,
        bob_key_package,
    } = validation_test_setup(WireFormat::MlsPlaintext);

    let (message, _welcome) = alice_group
        .add_members(&backend, &[bob_key_package])
        .expect("Could not add member.");

    let serialized_message = message
        .tls_serialize_detached()
        .expect("Could not serialize message.");

    let mut plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut serialized_message.as_slice())
        .expect("Could not deserialize message.");

    plaintext.set_group_id(GroupId::from_slice(&[9, 9, 9]));

    let message_in = MlsMessageIn::from(plaintext);

    let err = alice_group
        .parse_message(message_in, &backend)
        .expect_err("Could parse message despite wrong group ID.");

    assert_eq!(
        err,
        ManagedGroupError::Group(MlsGroupError::FramingValidationError(
            FramingValidationError::WrongGroupId
        ))
    );
}

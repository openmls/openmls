use ds_lib::{self, *};
use openmls::prelude::{config::CryptoConfig, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize, Serialize};

#[test]
fn test_client_info() {
    let crypto = &OpenMlsRustCrypto::default();
    let client_name = "Client1";
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let credential =
        Credential::new(client_name.as_bytes().to_vec(), CredentialType::Basic).unwrap();
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential_with_key = CredentialWithKey {
        credential,
        signature_key: signature_keys.to_public_vec().into(),
    };
    signature_keys.store(crypto.key_store()).unwrap();

    let client_key_package = KeyPackage::builder()
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            crypto,
            &signature_keys,
            credential_with_key,
        )
        .unwrap();

    let client_key_package = vec![(
        client_key_package
            .hash_ref(crypto.crypto())
            .expect("Could not hash KeyPackage.")
            .as_slice()
            .to_vec(),
        KeyPackageIn::from(client_key_package),
    )];
    let client_data = ClientInfo::new(client_name.to_string(), client_key_package);

    let encoded_client_data = client_data.tls_serialize_detached().unwrap();
    let client_data2 = ClientInfo::tls_deserialize(&mut encoded_client_data.as_slice())
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    assert_eq!(client_data.tls_serialize_detached().unwrap(), client_data2);
}

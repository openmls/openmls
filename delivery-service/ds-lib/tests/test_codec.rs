use ds_lib::{self, *};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;
use tls_codec::{Deserialize, Serialize};

#[test]
fn test_client_info() {
    let crypto = &OpenMlsRustCrypto::default();
    let client_name = "Client1";
    let ciphersuite = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let credential_bundle = CredentialBundle::new(
        client_name.as_bytes().to_vec(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite),
        crypto,
    )
    .unwrap();
    let client_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &credential_bundle, crypto, vec![]).unwrap();
    let client_key_package = vec![(
        client_key_package_bundle
            .key_package()
            .hash(crypto)
            .expect("Could not hash KeyPackage."),
        client_key_package_bundle.key_package().clone(),
    )];
    let client_data = ClientInfo::new(client_name.to_string(), client_key_package);

    let encoded_client_data = client_data.tls_serialize_detached().unwrap();
    let client_data2 = ClientInfo::tls_deserialize(&mut encoded_client_data.as_slice())
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    assert_eq!(client_data.tls_serialize_detached().unwrap(), client_data2);
}

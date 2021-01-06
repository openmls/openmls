use ds_lib::*;
use openmls::prelude::*;

#[test]
fn test_client_info() {
    let client_name = "Client1";
    let ciphersuite = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let credential_bundle = CredentialBundle::new(
        client_name.as_bytes().to_vec(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite),
    )
    .unwrap();
    let client_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &credential_bundle, vec![]).unwrap();
    let client_key_package = vec![(
        client_key_package_bundle.key_package().hash(),
        client_key_package_bundle.key_package().clone(),
    )];
    let client_data = ClientInfo::new(client_name.to_string(), client_key_package);

    let encoded_client_data = client_data.encode_detached().unwrap();
    assert_eq!(
        client_data,
        ClientInfo::decode(&mut Cursor::new(&encoded_client_data)).unwrap()
    );
}

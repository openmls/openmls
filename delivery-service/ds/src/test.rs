use super::*;
use actix_web::{dev::Body, http::StatusCode, test, web, web::Bytes, App};
use openmls::prelude::config::CryptoConfig;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::key_store::OpenMlsKeyStore;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{TlsByteVecU8, TlsVecU16};

fn generate_credential(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_scheme: SignatureScheme,
    crypto_backend: &impl OpenMlsCryptoProvider,
) -> Result<Credential, CredentialError> {
    let cb = CredentialBundle::new(identity, credential_type, signature_scheme, crypto_backend)?;
    let credential = cb.credential().clone();
    crypto_backend
        .key_store()
        .store(
            &credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key"),
            &cb,
        )
        .expect("An unexpected error occurred.");
    Ok(credential)
}

fn generate_key_package(
    ciphersuites: &[Ciphersuite],
    credential: &Credential,
    extensions: Vec<Extension>,
    crypto_backend: &impl OpenMlsCryptoProvider,
) -> KeyPackage {
    let credential_bundle = crypto_backend
        .key_store()
        .read(
            &credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key"),
        )
        .expect("An unexpected error occurred.");

    KeyPackage::create(
        CryptoConfig {
            ciphersuite: ciphersuites[0],
            version: ProtocolVersion::default(),
        },
        crypto_backend,
        &credential_bundle,
        extensions,
        vec![],
    )
    .unwrap()
}

#[actix_rt::test]
async fn test_list_clients() {
    let data = web::Data::new(Mutex::new(DsData::default()));
    let mut app = test::init_service(
        App::new()
            .app_data(data.clone())
            .service(get_key_packages)
            .service(list_clients)
            .service(register_client),
    )
    .await;

    // There is no client. So the response body is empty.
    let req = test::TestRequest::with_uri("/clients/list").to_request();

    let mut response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let response_body = response.response_mut().take_body();
    let response_body = response_body.as_ref().unwrap();

    let expected = TlsVecU32::<ClientInfo>::new(vec![]);
    let response_body = match response_body {
        Body::Bytes(b) => {
            TlsVecU32::<ClientInfo>::tls_deserialize(&mut b.as_ref()).expect("Invalid client list")
        }
        _ => panic!("Unexpected server response."),
    };
    assert_eq!(
        response_body.tls_serialize_detached().unwrap(),
        expected.tls_serialize_detached().unwrap()
    );

    // Add a client.
    let client_name = "Client1";
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let crypto = &OpenMlsRustCrypto::default();
    let credential_bundle = generate_credential(
        client_name.into(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite),
        crypto,
    )
    .unwrap();
    let client_id = credential_bundle.identity().to_vec();
    let client_key_package =
        generate_key_package(&[ciphersuite], &credential_bundle, vec![], crypto);
    let client_key_package = vec![(
        client_key_package
            .hash_ref(crypto.crypto())
            .unwrap()
            .as_slice()
            .to_vec(),
        client_key_package.clone(),
    )];
    let client_data = ClientInfo::new(client_name.to_string(), client_key_package.clone());
    let req = test::TestRequest::post()
        .uri("/clients/register")
        .set_payload(Bytes::copy_from_slice(
            &client_data.tls_serialize_detached().unwrap(),
        ))
        .to_request();

    let response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    // There should be Client1 now.
    let req = test::TestRequest::with_uri("/clients/list").to_request();

    let mut response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let response_body = response.response_mut().take_body();
    let response_body = response_body.as_ref().unwrap();

    let expected = TlsVecU32::<ClientInfo>::new(vec![client_data]);
    let response_body = match response_body {
        Body::Bytes(b) => {
            TlsVecU32::<ClientInfo>::tls_deserialize(&mut b.as_ref()).expect("Invalid client list")
        }
        _ => panic!("Unexpected server response."),
    };
    assert_eq!(
        response_body.tls_serialize_detached().unwrap(),
        expected.tls_serialize_detached().unwrap()
    );

    // Get Client1 key packages.
    let path =
        "/clients/key_packages/".to_owned() + &base64::encode_config(client_id, base64::URL_SAFE);
    let req = test::TestRequest::with_uri(&path).to_request();

    let mut response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let response_body = response.response_mut().take_body();
    let response_body = response_body.as_ref().unwrap();
    let mut key_packages: Vec<(TlsByteVecU8, KeyPackage)> = match response_body {
        Body::Bytes(b) => {
            ClientKeyPackages::tls_deserialize(&mut b.as_ref())
                .expect("Invalid key package response")
                .0
        }
        _ => panic!("Unexpected server response."),
    }
    .into();
    let key_packages: Vec<(Vec<u8>, KeyPackage)> = key_packages
        .drain(..)
        .map(|(e1, e2)| (e1.into(), e2))
        .collect();

    assert_eq!(client_key_package, key_packages);
}

#[actix_rt::test]
async fn test_group() {
    let crypto = &OpenMlsRustCrypto::default();
    let mls_group_config = MlsGroupConfig::default();
    let data = web::Data::new(Mutex::new(DsData::default()));
    let mut app = test::init_service(
        App::new()
            .app_data(data.clone())
            .service(register_client)
            .service(list_clients)
            .service(get_key_packages)
            .service(send_welcome)
            .service(msg_recv)
            .service(msg_send),
    )
    .await;

    // Add two clients.
    let clients = ["Client1", "Client2"];
    let mut key_packages = Vec::new();
    let mut credentials = Vec::new();
    let mut client_ids = Vec::new();
    for client_name in clients.iter() {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let credential = generate_credential(
            client_name.as_bytes().to_vec(),
            CredentialType::Basic,
            SignatureScheme::from(ciphersuite),
            crypto,
        )
        .unwrap();
        let client_key_package = generate_key_package(&[ciphersuite], &credential, vec![], crypto);
        let client_data = ClientInfo::new(
            client_name.to_string(),
            vec![(
                client_key_package
                    .hash_ref(crypto.crypto())
                    .unwrap()
                    .as_slice()
                    .to_vec(),
                client_key_package.clone(),
            )],
        );
        key_packages.push(client_key_package);
        client_ids.push(credential.identity().to_vec());
        credentials.push(credential);
        let req = test::TestRequest::post()
            .uri("/clients/register")
            .set_payload(Bytes::copy_from_slice(
                &client_data.tls_serialize_detached().unwrap(),
            ))
            .to_request();
        let response = test::call_service(&mut app, req).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Client1 creates MyFirstGroup
    let group_id = GroupId::from_slice(b"MyFirstGroup");
    let group_ciphersuite = key_packages[0].ciphersuite();
    let mut group =
        MlsGroup::new_with_group_id(crypto, &mls_group_config, group_id, key_packages.remove(0))
            .expect("An unexpected error occurred.");

    // === Client1 invites Client2 ===
    // First we need to get the key package for Client2 from the DS.
    let path = "/clients/key_packages/".to_owned()
        + &base64::encode_config(&client_ids[1], base64::URL_SAFE);
    println!("path: {}", path);
    let req = test::TestRequest::with_uri(&path).to_request();

    let mut response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let response_body = response.response_mut().take_body();
    let response_body = response_body.as_ref().unwrap();
    let mut client2_key_packages = match response_body {
        Body::Bytes(b) => {
            ClientKeyPackages::tls_deserialize(&mut b.as_ref())
                .expect("Invalid key package response")
                .0
        }
        _ => panic!("Unexpected server response."),
    };
    let client2_key_package = client2_key_packages
        .iter()
        .position(|(_hash, kp)| kp.ciphersuite() == group_ciphersuite)
        .expect("No key package with the group ciphersuite available");
    let (_client2_key_package_hash, client2_key_package) =
        client2_key_packages.remove(client2_key_package);

    // With the key package we can invite Client2 (create proposal and merge it
    // locally.)
    let (_out_messages, welcome_msg) = group
        .add_members(crypto, &[client2_key_package])
        .expect("Could not add member to group.");
    group
        .merge_pending_commit()
        .expect("error merging pending commit");

    // Send welcome message for Client2
    let req = test::TestRequest::post()
        .uri("/send/welcome")
        .set_payload(Bytes::copy_from_slice(
            &welcome_msg.tls_serialize_detached().unwrap(),
        ))
        .to_request();
    let response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    // There should be a welcome message now for Client2.
    let path = "/recv/".to_owned() + &base64::encode_config(clients[1], base64::URL_SAFE);
    let req = test::TestRequest::with_uri(&path).to_request();
    let mut response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let response_body = response.response_mut().take_body();
    let response_body = response_body.as_ref().unwrap();
    let mut messages: Vec<Message> = match response_body {
        Body::Bytes(b) => TlsVecU16::<Message>::tls_deserialize(&mut b.as_ref())
            .expect("Invalid message list")
            .into(),
        _ => panic!("Unexpected server response."),
    };

    let welcome_message = messages
        .iter()
        .position(|m| matches!(m, Message::Welcome(_)))
        .expect("Didn't get a welcome message from the server.");
    let welcome_message = match messages.remove(welcome_message) {
        Message::Welcome(m) => m,
        _ => panic!("This is not a welcome message."),
    };
    assert_eq!(welcome_msg, welcome_message);
    assert!(messages.is_empty());

    let mut group_on_client2 = MlsGroup::new_from_welcome(
        crypto,
        &mls_group_config,
        welcome_msg,
        Some(group.export_ratchet_tree()), // delivered out of band
    )
    .expect("Error creating group from Welcome");

    assert_eq!(
        group.export_ratchet_tree(),
        group_on_client2.export_ratchet_tree(),
    );

    // === Client2 sends a message to the group ===
    let client2_message = b"Thanks for adding me Client1.";
    let out_messages = group_on_client2
        .create_message(crypto, client2_message)
        .unwrap();

    // Send private_message to the group
    let msg = GroupMessage::new(out_messages.into(), &client_ids);
    let req = test::TestRequest::post()
        .uri("/send/message")
        .set_payload(Bytes::copy_from_slice(
            &msg.tls_serialize_detached().unwrap(),
        ))
        .to_request();
    let response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Client1 retrieves messages from the DS
    let path = "/recv/".to_owned() + &base64::encode_config(clients[0], base64::URL_SAFE);
    let req = test::TestRequest::with_uri(&path).to_request();
    let mut response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let response_body = response.response_mut().take_body();
    let response_body = response_body.as_ref().unwrap();
    let mut messages: Vec<Message> = match response_body {
        Body::Bytes(b) => TlsVecU16::<Message>::tls_deserialize(&mut b.as_ref())
            .expect("Invalid message list")
            .into(),
        _ => panic!("Unexpected server response."),
    };

    let mls_message = messages
        .iter()
        .position(|m| matches!(m, Message::MlsMessage(_)))
        .expect("Didn't get an MLS application message from the server.");
    let mls_message = match messages.remove(mls_message) {
        Message::MlsMessage(m) => m,
        _ => panic!("This is not an MLS message."),
    };
    assert!(messages.is_empty());

    // Decrypt the message on Client1
    let processed_message = group
        .process_message(crypto, mls_message)
        .expect("Could not process unverified message.");
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_message.into_content()
    {
        assert_eq!(client2_message, &application_message.into_bytes()[..]);
    } else {
        panic!("Expected application message");
    }
}

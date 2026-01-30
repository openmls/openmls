use super::*;
use actix_web::{body::MessageBody, http::StatusCode, test, web, web::Bytes, App};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;
use tls_codec::{TlsByteVecU8, TlsVecU16};

fn generate_credential(
    identity: Vec<u8>,
    signature_scheme: SignatureScheme,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity);
    let signature_keys = SignatureKeyPair::new(signature_scheme).unwrap();
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.to_public_vec().into(),
    };

    (credential_with_key, signature_keys)
}

fn generate_key_package(
    ciphersuite: Ciphersuite,
    credential_with_key: CredentialWithKey,
    extensions: Extensions<KeyPackage>,
    crypto_provider: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
) -> KeyPackageBundle {
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(ciphersuite, crypto_provider, signer, credential_with_key)
        .unwrap()
}

#[actix_rt::test]
async fn test_list_clients() {
    let data = web::Data::new(DsData::default());
    let app = test::init_service(
        App::new()
            .app_data(data.clone())
            .service(get_key_packages)
            .service(consume_key_package)
            .service(publish_key_packages)
            .service(list_clients)
            .service(register_client),
    )
    .await;

    // There is no client. So the response body is empty.
    let req = test::TestRequest::with_uri("/clients/list").to_request();

    let response = test::call_service(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response.into_body().try_into_bytes().unwrap();
    let client_info =
        TlsVecU32::<ClientInfo>::tls_deserialize(&mut bytes.as_ref()).expect("Invalid client list");

    let expected = TlsVecU32::<ClientInfo>::new(vec![]);

    assert_eq!(
        client_info.tls_serialize_detached().unwrap(),
        expected.tls_serialize_detached().unwrap()
    );

    // Add a client.
    let client_name = "Client1";
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let crypto = &OpenMlsRustCrypto::default();
    let (credential_with_key, signer) =
        generate_credential(client_name.into(), SignatureScheme::from(ciphersuite));
    let identity = credential_with_key.credential.serialized_content();
    let client_id = identity.to_vec();
    let client_key_package = generate_key_package(
        ciphersuite,
        credential_with_key.clone(),
        Extensions::empty(),
        crypto,
        &signer,
    );
    let client_key_package = vec![(
        client_key_package
            .key_package()
            .hash_ref(crypto.crypto())
            .unwrap()
            .as_slice()
            .to_vec(),
        KeyPackageIn::from(client_key_package.clone()),
    )];
    let mut client_data = ClientInfo::new(client_key_package.clone());
    let body = RegisterClientRequest {
        key_packages: ClientKeyPackages(
            client_key_package
                .clone()
                .into_iter()
                .map(|(b, kp)| (b.into(), kp))
                .collect::<Vec<(TlsByteVecU8, KeyPackageIn)>>()
                .into(),
        ),
    };

    let req = test::TestRequest::post()
        .uri("/clients/register")
        .set_payload(Bytes::copy_from_slice(
            &body.tls_serialize_detached().unwrap(),
        ))
        .to_request();

    let response = test::call_service(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response_body = RegisterClientSuccessResponse::tls_deserialize_exact(
        response.into_body().try_into_bytes().unwrap(),
    )
    .unwrap();
    client_data.auth_token = response_body.auth_token;

    // There should be Client1 now.
    let req = test::TestRequest::with_uri("/clients/list").to_request();

    let response = test::call_service(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response.into_body().try_into_bytes().unwrap();
    let client_ids =
        TlsVecU32::<Vec<u8>>::tls_deserialize(&mut bytes.as_ref()).expect("Invalid client list");

    let expected = TlsVecU32::<Vec<u8>>::new(vec![client_data.id().to_vec()]);

    assert_eq!(
        client_ids.tls_serialize_detached().unwrap(),
        expected.tls_serialize_detached().unwrap()
    );

    // Get Client1 key packages.
    let path = "/clients/key_packages/".to_owned()
        + &base64::engine::general_purpose::URL_SAFE.encode(client_id);
    let req = test::TestRequest::with_uri(&path).to_request();

    let response = test::call_service(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response.into_body().try_into_bytes().unwrap();
    let mut key_packages =
        TlsVecU32::<(TlsByteVecU8, KeyPackageIn)>::tls_deserialize(&mut bytes.as_ref())
            .expect("Invalid key package response")
            .into_vec();

    let key_packages: Vec<(Vec<u8>, KeyPackageIn)> = key_packages
        .drain(..)
        .map(|(e1, e2)| (e1.into(), e2))
        .collect();

    assert_eq!(client_key_package, key_packages);
}

#[actix_rt::test]
async fn test_group() {
    let crypto = &OpenMlsRustCrypto::default();
    let mls_group_create_config = MlsGroupCreateConfig::default();
    let data = web::Data::new(DsData::default());
    let app = test::init_service(
        App::new()
            .app_data(data.clone())
            .service(register_client)
            .service(list_clients)
            .service(get_key_packages)
            .service(consume_key_package)
            .service(publish_key_packages)
            .service(send_welcome)
            .service(msg_recv)
            .service(msg_send),
    )
    .await;

    // Add two clients.
    let clients = ["Client1", "Client2"];
    let mut key_packages = Vec::new();
    let mut credentials_with_key = Vec::new();
    let mut signers = Vec::new();
    let mut client_ids = Vec::new();
    let mut client_data_vec = Vec::new();
    for client_name in clients.iter() {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let (credential_with_key, signer) = generate_credential(
            client_name.as_bytes().to_vec(),
            SignatureScheme::from(ciphersuite),
        );
        let client_key_package = generate_key_package(
            ciphersuite,
            credential_with_key.clone(),
            Extensions::empty(),
            crypto,
            &signer,
        );
        let client_key_packages = (
            client_key_package
                .key_package()
                .hash_ref(crypto.crypto())
                .unwrap()
                .as_slice()
                .to_vec(),
            client_key_package.clone().into(),
        );

        let mut client_data = ClientInfo::new(vec![(client_key_packages.clone())]);
        key_packages.push(client_key_package);

        let id = credential_with_key.credential.serialized_content();
        client_ids.push(id.to_vec());
        credentials_with_key.push(credential_with_key);
        signers.push(signer);

        let body = RegisterClientRequest {
            key_packages: ClientKeyPackages(
                vec![client_key_packages.clone()]
                    .into_iter()
                    .map(|(b, kp)| (b.into(), kp))
                    .collect::<Vec<(TlsByteVecU8, KeyPackageIn)>>()
                    .into(),
            ),
        };

        let req = test::TestRequest::post()
            .uri("/clients/register")
            .set_payload(Bytes::copy_from_slice(
                &body.tls_serialize_detached().unwrap(),
            ))
            .to_request();
        let response = test::call_service(&app, req).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = RegisterClientSuccessResponse::tls_deserialize_exact(
            response.into_body().try_into_bytes().unwrap(),
        )
        .unwrap();
        client_data.auth_token = response_body.auth_token;
        client_data_vec.push(client_data);
    }

    // Add an additional key package for Client2
    let group_ciphersuite = key_packages[0].key_package().ciphersuite();
    let key_package_2 = generate_key_package(
        group_ciphersuite,
        credentials_with_key.get(1).unwrap().clone(),
        Extensions::empty(),
        crypto,
        signers.get(1).unwrap(),
    );

    let key_package_2 = (
        key_package_2
            .key_package()
            .hash_ref(crypto.crypto())
            .unwrap()
            .as_slice()
            .to_vec(),
        key_package_2,
    );

    let ckp = ClientKeyPackages(
        vec![key_package_2]
            .into_iter()
            .map(|(b, kp)| (b.into(), KeyPackageIn::from(kp)))
            .collect::<Vec<(TlsByteVecU8, KeyPackageIn)>>()
            .into(),
    );

    // Publish key package to the DS for Client2
    let path = "/clients/key_packages/".to_string()
        + &base64::engine::general_purpose::URL_SAFE.encode(&client_ids[1]);
    let body = PublishKeyPackagesRequest {
        key_packages: ckp,
        auth_token: client_data_vec[1].auth_token.clone(),
    };
    let req = test::TestRequest::post()
        .uri(&path)
        .set_payload(Bytes::copy_from_slice(
            &body.tls_serialize_detached().unwrap(),
        ))
        .to_request();

    // The response should be empty.
    let response = test::call_service(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Client1 creates MyFirstGroup
    let group_id = GroupId::from_slice(b"MyFirstGroup");

    let credential_with_key_1 = credentials_with_key.remove(0);
    let signer_1 = signers.remove(0);
    let mut group = MlsGroup::new_with_group_id(
        crypto,
        &signer_1,
        &mls_group_create_config,
        group_id,
        credential_with_key_1,
    )
    .expect("An unexpected error occurred.");

    // === Client1 invites Client2 ===
    // First we need to reserve the key package for Client2 from the DS.
    let path = "/clients/key_package/".to_owned()
        + &base64::engine::general_purpose::URL_SAFE.encode(&client_ids[1]);

    let req = test::TestRequest::with_uri(&path).to_request();

    let response = test::call_service(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response.into_body().try_into_bytes().unwrap();
    let client2_key_package =
        KeyPackageIn::tls_deserialize(&mut bytes.as_ref()).expect("Invalid key package response");

    // With the key package we can invite Client2 (create proposal and merge it
    // locally.)
    let (_out_messages, welcome_msg, _group_info) = group
        .add_members(crypto, &signer_1, &[client2_key_package.into()])
        .expect("Could not add member to group.");
    group
        .merge_pending_commit(crypto)
        .expect("error merging pending commit");

    // Send welcome message for Client2
    let req = test::TestRequest::post()
        .uri("/send/welcome")
        .set_payload(Bytes::copy_from_slice(
            &welcome_msg.tls_serialize_detached().unwrap(),
        ))
        .to_request();
    let response = test::call_service(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    // There should be a welcome message now for Client2.
    let body = RecvMessageRequest {
        auth_token: client_data_vec[1].auth_token.clone(),
    };
    let path = "/recv/".to_owned() + &base64::engine::general_purpose::URL_SAFE.encode(clients[1]);
    let req = test::TestRequest::with_uri(&path)
        .set_payload(Bytes::copy_from_slice(
            &body.tls_serialize_detached().unwrap(),
        ))
        .to_request();
    let response = test::call_service(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response.into_body().try_into_bytes().unwrap();
    let mut messages = TlsVecU16::<MlsMessageIn>::tls_deserialize(&mut bytes.as_ref())
        .expect("Invalid message list")
        .into_vec();

    let welcome_message = messages
        .iter()
        .position(|m| matches!(m.wire_format(), WireFormat::Welcome))
        .expect("Didn't get a welcome message from the server.");
    let welcome_message = messages.remove(welcome_message);
    assert_eq!(welcome_msg, welcome_message.into());
    assert!(messages.is_empty());

    let welcome = match welcome_msg.body() {
        MlsMessageBodyOut::Welcome(welcome) => welcome,
        other => panic!("expected a welcome message, got {other:?}"),
    };

    let processed_welcome = ProcessedWelcome::new_from_welcome(
        crypto,
        mls_group_create_config.join_config(),
        welcome.clone(),
    )
    .unwrap();
    let mut group_on_client2 = JoinBuilder::new(crypto, processed_welcome)
        .with_ratchet_tree(group.export_ratchet_tree().into())
        .replace_old_group()
        .build()
        .unwrap()
        .into_group(crypto)
        .expect("Error creating group from staged join");

    assert_eq!(
        group.export_ratchet_tree(),
        group_on_client2.export_ratchet_tree(),
    );

    // === Client2 sends a message to the group ===
    let client2_message = b"Thanks for adding me Client1.";
    let signer_2 = signers.remove(0);
    let out_messages = group_on_client2
        .create_message(crypto, &signer_2, client2_message)
        .unwrap();

    // Send private_message to the group
    let msg = GroupMessage::new(out_messages.into(), &client_ids);
    let req = test::TestRequest::post()
        .uri("/send/message")
        .set_payload(Bytes::copy_from_slice(
            &msg.tls_serialize_detached().unwrap(),
        ))
        .to_request();
    let response = test::call_service(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Client1 retrieves messages from the DS
    let body = RecvMessageRequest {
        auth_token: client_data_vec[0].auth_token.clone(),
    };
    let path = "/recv/".to_owned() + &base64::engine::general_purpose::URL_SAFE.encode(clients[0]);
    let req = test::TestRequest::with_uri(&path)
        .set_payload(Bytes::copy_from_slice(
            &body.tls_serialize_detached().unwrap(),
        ))
        .to_request();
    let response = test::call_service(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response.into_body().try_into_bytes().unwrap();
    let mut messages = TlsVecU16::<MlsMessageIn>::tls_deserialize(&mut bytes.as_ref())
        .expect("Invalid message list");

    let mls_message = messages
        .iter()
        .position(|m| {
            matches!(
                m.wire_format(),
                WireFormat::PublicMessage | WireFormat::PrivateMessage
            )
        })
        .expect("Didn't get an MLS application message from the server.");
    let protocol_message: ProtocolMessage = match messages.remove(mls_message).extract() {
        MlsMessageBodyIn::PrivateMessage(m) => m.into(),
        MlsMessageBodyIn::PublicMessage(m) => m.into(),
        _ => panic!("This is not an MLS message."),
    };
    assert!(messages.is_empty());

    // Decrypt the message on Client1
    let processed_message = group
        .process_message(crypto, protocol_message)
        .expect("Could not process unverified message.");
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_message.into_content()
    {
        assert_eq!(client2_message, &application_message.into_bytes()[..]);
    } else {
        panic!("Expected application message");
    }
}

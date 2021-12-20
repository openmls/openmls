use super::*;
use actix_web::{dev::Body, http::StatusCode, test, web, web::Bytes, App};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;
use tls_codec::{TlsByteVecU8, TlsVecU16};

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
    let ciphersuite = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let crypto = &OpenMlsRustCrypto::default();
    let credential_bundle = CredentialBundle::new(
        client_name.as_bytes().to_vec(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite),
        crypto,
    )
    .unwrap();
    let client_id = credential_bundle.credential().identity().to_vec();
    let client_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &credential_bundle, crypto, vec![]).unwrap();
    let client_key_package = vec![(
        client_key_package_bundle
            .key_package()
            .hash(crypto)
            .unwrap(),
        client_key_package_bundle.key_package().clone(),
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
    let mut key_package_bundles = Vec::new();
    let mut credentials = Vec::new();
    let mut client_ids = Vec::new();
    for client_name in clients.iter() {
        let ciphersuite = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let credential_bundle = CredentialBundle::new(
            client_name.as_bytes().to_vec(),
            CredentialType::Basic,
            SignatureScheme::from(ciphersuite),
            crypto,
        )
        .unwrap();
        let client_key_package =
            KeyPackageBundle::new(&[ciphersuite], &credential_bundle, crypto, vec![]).unwrap();
        let client_data = ClientInfo::new(
            client_name.to_string(),
            vec![(
                client_key_package.key_package().hash(crypto).unwrap(),
                client_key_package.key_package().clone(),
            )],
        );
        key_package_bundles.push(client_key_package);
        client_ids.push(credential_bundle.credential().identity().to_vec());
        credentials.push(credential_bundle);
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
    let group_id = b"MyFirstGroup";
    let group_aad = b"MyFirstGroup AAD";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);
    let group_ciphersuite = key_package_bundles[0].key_package().ciphersuite_name();
    let mut group =
        CoreGroup::builder(GroupId::from_slice(group_id), key_package_bundles.remove(0))
            .build(crypto)
            .unwrap();

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
        .position(|(_hash, kp)| kp.ciphersuite_name() == group_ciphersuite)
        .expect("No key package with the group ciphersuite available");
    let (_client2_key_package_hash, client2_key_package) =
        client2_key_packages.remove(client2_key_package);

    // With the key package we can build a proposal.
    let client2_add_proposal = group
        .create_add_proposal(
            framing_parameters,
            &credentials[0],
            client2_key_package,
            crypto,
        )
        .unwrap();

    let proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(
            Config::ciphersuite(group_ciphersuite).expect("Unsupported ciphersuite."),
            crypto,
            client2_add_proposal,
        )
        .expect("Could not create StagedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&credentials[0])
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_results = group
        .create_commit(params, crypto)
        .expect("Error creating commit");
    let welcome_msg = create_commit_results
        .welcome_option
        .expect("Welcome message wasn't created by create_commit.");
    let staged_commit = group
        .stage_commit(&create_commit_results.commit, &proposal_store, &[], crypto)
        .expect("error applying commit");
    group
        .merge_commit(staged_commit)
        .expect("error merging commit");

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

    let mut group_on_client2 = CoreGroup::new_from_welcome(
        welcome_message,
        Some(group.treesync().export_nodes()), // delivered out of band
        key_package_bundles.remove(0),
        crypto,
    )
    .expect("Error creating group from Welcome");

    assert_eq!(
        group.treesync().export_nodes(),
        group_on_client2.treesync().export_nodes()
    );

    // === Client2 sends a message to the group ===
    let client2_message = b"Thanks for adding me Client1.";
    let mls_ciphertext = group_on_client2
        .create_application_message(&[], &client2_message[..], &credentials[1], 0, crypto)
        .unwrap();

    // Send mls_ciphertext to the group
    let msg = GroupMessage::new(DsMlsMessage::Ciphertext(mls_ciphertext), &client_ids);
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

    let mls_ciphertext = messages
        .iter()
        .position(|m| matches!(m, Message::MlsMessage(_)))
        .expect("Didn't get an MLS application message from the server.");
    let mls_ciphertext = match messages.remove(mls_ciphertext) {
        Message::MlsMessage(m) => match m {
            DsMlsMessage::Ciphertext(m) => m,
            _ => panic!("This is not an MlsCiphertext but an MlsPlaintext (or something else)."),
        },
        _ => panic!("This is not an MLS message."),
    };
    assert!(messages.is_empty());

    // Decrypt the message on Client1
    let mls_plaintext = group
        .decrypt(&mls_ciphertext, crypto)
        .expect("Error decrypting MlsCiphertext");
    let mls_plaintext = group
        .verify(mls_plaintext, crypto)
        .expect("Error verifying plaintext");
    assert_eq!(
        client2_message,
        mls_plaintext.as_application_message().unwrap()
    );
}

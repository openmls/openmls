use super::*;
use actix_web::{dev::Body, http::StatusCode, test, web, web::Bytes, App};

#[actix_rt::test]
async fn test_list_clients() {
    let data = web::Data::new(Mutex::new(DsData::default()));
    // TODO: re-use app from main
    let mut app = test::init_service(
        App::new()
            .app_data(data.clone())
            .route("/clients/register", web::post().to(register_client))
            .route("/clients/list", web::get().to(list_clients))
            .route("/clients/get/{name}", web::get().to(get_client)),
    )
    .await;

    // There is no client. So the response body is empty.
    let req = test::TestRequest::with_uri("/clients/list").to_request();

    let mut response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let response_body = response.response_mut().take_body();
    let response_body = response_body.as_ref().unwrap();

    assert_eq!(
        response_body,
        &Body::Bytes(Bytes::from(format!("I know these clients []!\n")))
    );

    // Add a client.
    let client_name = "Client1";
    let ciphersuite = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let credential_bundle = CredentialBundle::new(
        client_name.as_bytes().to_vec(),
        CredentialType::Basic,
        ciphersuite,
    )
    .unwrap();
    let client_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &credential_bundle, vec![]).unwrap();
    let client_key_package = vec![(
        client_key_package_bundle.get_key_package().hash(),
        client_key_package_bundle.get_key_package().clone(),
    )];
    let client_data = ClientInfo::new(client_name.to_string(), client_key_package.clone());
    let req = test::TestRequest::post()
        .uri("/clients/register")
        .set_payload(Bytes::copy_from_slice(
            &client_data.encode_detached().unwrap(),
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

    assert_eq!(
        response_body,
        &Body::Bytes(Bytes::from(format!(
            "I know these clients [\"Client1\"]!\n"
        )))
    );

    // Get Client1 key packages.
    let path = "/clients/get/".to_owned() + &client_name;
    let req = test::TestRequest::with_uri(&path).to_request();

    let mut response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let response_body = response.response_mut().take_body();
    let response_body = response_body.as_ref().unwrap();
    let key_packages = match response_body {
        Body::Bytes(b) => {
            ClientKeyPackages::decode(&mut Cursor::new(b.as_ref()))
                .expect("Invalid key package response")
                .0
        }
        _ => panic!("Unexpected server response."),
    };

    assert_eq!(client_key_package, key_packages);
}

#[actix_rt::test]
async fn test_group() {
    let data = web::Data::new(Mutex::new(DsData::default()));
    // TODO: re-use app from main
    let mut app = test::init_service(
        App::new()
            .app_data(data.clone())
            .route("/clients/register", web::post().to(register_client))
            .route("/clients/list", web::get().to(list_clients))
            .route("/clients/get/{name}", web::get().to(get_client))
            .service(msg_send_welcome)
            .service(msg_recv),
    )
    .await;

    // Add two clients.
    let clients = ["Client1", "Client2"];
    let mut key_package_bundles = Vec::new();
    let mut credentials = Vec::new();
    for client_name in clients.iter() {
        let ciphersuite = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let credential_bundle = CredentialBundle::new(
            client_name.as_bytes().to_vec(),
            CredentialType::Basic,
            ciphersuite,
        )
        .unwrap();
        let client_key_package =
            KeyPackageBundle::new(&[ciphersuite], &credential_bundle, vec![]).unwrap();
        let client_data = ClientInfo::new(
            client_name.to_string(),
            vec![(
                client_key_package.get_key_package().hash(),
                client_key_package.get_key_package().clone(),
            )],
        );
        key_package_bundles.push(client_key_package);
        credentials.push(credential_bundle);
        let req = test::TestRequest::post()
            .uri("/clients/register")
            .set_payload(Bytes::copy_from_slice(
                &client_data.encode_detached().unwrap(),
            ))
            .to_request();
        let response = test::call_service(&mut app, req).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Client1 creates MyFirstGroup
    let group_id = b"MyFristGroup";
    let group_aad = b"MyFirstGroup AAD";
    let group_ciphersuite = key_package_bundles[0].get_key_package().ciphersuite();
    let mut group = MlsGroup::new(
        group_id,
        group_ciphersuite,
        key_package_bundles.remove(0),
        GroupConfig::default(),
    )
    .unwrap();

    // === Client1 invites Client2 ===
    // First we need to get the key package for Client2 from the DS.
    let path = "/clients/get/".to_owned() + &clients[1];
    let req = test::TestRequest::with_uri(&path).to_request();

    let mut response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let response_body = response.response_mut().take_body();
    let response_body = response_body.as_ref().unwrap();
    let mut client2_key_packages = match response_body {
        Body::Bytes(b) => {
            ClientKeyPackages::decode(&mut Cursor::new(b.as_ref()))
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

    // With the key package we can build a proposal.
    let client2_add_proposal =
        group.create_add_proposal(group_aad, &credentials[0], client2_key_package);
    let epoch_proposals = vec![client2_add_proposal];
    let (commit, welcome_msg, _kpb) = group
        .create_commit(group_aad, &credentials[0], epoch_proposals.clone(), false)
        .expect("Error creating commit");
    let welcome_msg = welcome_msg.expect("Welcome message wasn't created by create_commit.");
    group
        .apply_commit(commit, epoch_proposals, &[])
        .expect("error applying commit");

    // Send welcome message for Client2
    let req = test::TestRequest::post()
        .uri("/msg/send/welcome")
        .set_payload(Bytes::copy_from_slice(
            &welcome_msg.encode_detached().unwrap(),
        ))
        .to_request();
    let response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    // There should be a welcome message now for Client2.
    let path = "/msg/recv/".to_owned() + &clients[1];
    let req = test::TestRequest::with_uri(&path).to_request();
    let mut response = test::call_service(&mut app, req).await;
    assert_eq!(response.status(), StatusCode::OK);

    let response_body = response.response_mut().take_body();
    let response_body = response_body.as_ref().unwrap();
    let mut messages: Vec<Message> = match response_body {
        Body::Bytes(b) => {
            decode_vec(VecSize::VecU16, &mut Cursor::new(b.as_ref())).expect("Invalid message list")
        }
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

    let group_on_client2 = MlsGroup::new_from_welcome(
        welcome_message,
        Some(group.tree().public_key_tree_copy()), // delivered out of band
        key_package_bundles.remove(0),
    )
    .expect("Error creating group from Welcome");

    assert_eq!(
        group.tree().public_key_tree(),
        group_on_client2.tree().public_key_tree()
    );
}

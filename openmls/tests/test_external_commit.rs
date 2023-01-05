use openmls::{prelude::*, test_utils::*, *};

#[apply(ciphersuites_and_backends)]
fn test_external_commit(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Alice creates a new group ...
    let alice_group = {
        let group_config = MlsGroupConfigBuilder::new()
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .build();

        let alice_cb = {
            let alice_cb = CredentialBundle::new(
                b"Alice".to_vec(),
                CredentialType::Basic,
                ciphersuite.signature_algorithm(),
                backend,
            )
            .expect("Creation of credential bundle failed.");

            let index = alice_cb
                .credential()
                .signature_key()
                .tls_serialize_detached()
                .expect("Serialization of signature public key failed.");

            backend
                .key_store()
                .store(&index, &alice_cb)
                .expect("Storing of signature public key failed.");

            alice_cb
        };

        MlsGroup::new(
            backend,
            &group_config,
            alice_cb.credential().signature_key(),
        )
        .expect("An unexpected error occurred.")
    };

    // ... and exports a group info (with ratchet_tree).
    let verifiable_group_info = {
        let group_info = alice_group.export_group_info(backend, true).unwrap();

        let serialized_group_info = group_info.tls_serialize_detached().unwrap();

        let mls_message_out =
            MlsMessageOut::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap();

        mls_message_out.into_group_info().unwrap()
    };

    let verifiable_group_info_broken = {
        let group_info = alice_group.export_group_info(backend, true).unwrap();

        let serialized_group_info = {
            let mut tmp = group_info.tls_serialize_detached().unwrap();

            // Simulate a bit-flip in the signature.
            let last = tmp.len().checked_sub(1).unwrap();
            tmp[last] ^= 1;

            tmp
        };

        let mls_message_out =
            MlsMessageOut::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap();

        mls_message_out.into_group_info().unwrap()
    };

    // ---------------------------------------------------------------------------------------------

    // Now, Bob wants to join Alice' group by an external commit. (Positive case.)
    {
        let bob_cb = CredentialBundle::new(
            b"Bob".to_vec(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("Creation of credential bundle failed.");

        let (_bob_group, _) = MlsGroup::join_by_external_commit(
            backend,
            None,
            verifiable_group_info,
            &MlsGroupConfigBuilder::new()
                .crypto_config(CryptoConfig::with_default_version(ciphersuite))
                .build(),
            b"",
            &bob_cb,
        )
        .unwrap();
    }

    // Now, Bob wants to join Alice' group by an external commit. (Negative case, broken signature.)
    {
        let bob_cb = CredentialBundle::new(
            b"Bob".to_vec(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("Creation of credential bundle failed.");

        let got_error = MlsGroup::join_by_external_commit(
            backend,
            None,
            verifiable_group_info_broken,
            &MlsGroupConfigBuilder::new()
                .crypto_config(CryptoConfig::with_default_version(ciphersuite))
                .build(),
            b"",
            &bob_cb,
        )
        .unwrap_err();

        assert_eq!(got_error, ExternalCommitError::InvalidGroupInfoSignature);
    }
}

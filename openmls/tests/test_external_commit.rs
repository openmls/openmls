use openmls::{prelude::*, test_utils::*, *};

#[apply(ciphersuites_and_backends)]
fn test_external_commit(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Alice creates a new group ...
    let alice_group = {
        let group_config = MlsGroupConfig::default();

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

        let alice_kph = {
            let alice_kpb = KeyPackageBundle::builder()
                .ciphersuite(ciphersuite)
                .build(backend, alice_cb)
                .expect("Creation of key package bundle failed.");

            let alice_kph = alice_kpb
                .key_package()
                .hash_ref(backend.crypto())
                .expect("Hashing of key package failed.");

            backend
                .key_store()
                .store(alice_kph.as_slice(), &alice_kpb)
                .expect("An unexpected error occurred.");

            alice_kph
        };

        MlsGroup::new(backend, &group_config, alice_kph.as_slice())
            .expect("An unexpected error occurred.")
    };

    // ... and exports a group info (with ratchet_tree).
    let verifiable_group_info = {
        let group_info = alice_group.export_group_info(backend, true).unwrap();

        let serialized_group_info = group_info.tls_serialize_detached().unwrap();

        VerifiableGroupInfo::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap()
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

        VerifiableGroupInfo::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap()
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
            &MlsGroupConfig::default(),
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
            &MlsGroupConfig::default(),
            b"",
            &bob_cb,
        )
        .unwrap_err();

        assert_eq!(got_error, ExternalCommitError::InvalidGroupInfoSignature);
    }
}

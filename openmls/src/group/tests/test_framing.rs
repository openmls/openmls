use super::utils::*;
use crate::{group::*, test_utils::*, *};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;

#[apply(backends)]
fn padding(backend: &impl OpenMlsCryptoProvider) {
    // Create a test config for a single client supporting all possible
    // ciphersuites.
    let alice_config = TestClientConfig {
        name: "alice",
        ciphersuites: backend.crypto().supported_ciphersuites(),
    };

    let mut test_group_configs = Vec::new();

    // Create a group config for each ciphersuite.
    for &ciphersuite in backend.crypto().supported_ciphersuites().iter() {
        let test_group = TestGroupConfig {
            ciphersuite,
            config: CoreGroupConfig::default(),
            members: vec![alice_config.clone()],
        };
        test_group_configs.push(test_group);
    }

    // Create the test setup config.
    let test_setup_config = TestSetupConfig {
        clients: vec![alice_config],
        groups: test_group_configs,
    };

    // Initialize the test setup according to config.
    let test_setup = setup(test_setup_config, backend);

    let test_clients = test_setup.clients.borrow();
    let alice = test_clients
        .get("alice")
        .expect("An unexpected error occurred.")
        .borrow();

    for padding_size in 0..50 {
        // Create a message in each group and test the padding.
        for group_state in alice.group_states.borrow_mut().values_mut() {
            let credential_bundle = alice
                .credential_bundles
                .get(&group_state.ciphersuite())
                .expect("An unexpected error occurred.");
            for _ in 0..10 {
                let message = randombytes(random_usize() % 1000);
                let aad = randombytes(random_usize() % 1000);
                let mls_ciphertext = group_state
                    .create_application_message(
                        &aad,
                        &message,
                        credential_bundle,
                        padding_size,
                        backend,
                    )
                    .expect("An unexpected error occurred.");
                let ciphertext = mls_ciphertext.ciphertext();
                let length = ciphertext.len();
                let overflow = if padding_size > 0 {
                    length % padding_size
                } else {
                    0
                };
                if overflow != 0 {
                    panic!(
                    "Error: padding overflow of {} bytes, message length: {}, padding block size: {}",
                    overflow, length, padding_size
                );
                }
            }
        }
    }
}

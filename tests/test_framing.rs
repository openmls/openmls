use openmls::prelude::*;
mod utils;
use utils::mls_utils::*;

#[test]
fn padding() {
    pretty_env_logger::init_timed();

    // Create a test config for a single client supporting all possible
    // ciphersuites.
    let alice_config = TestClientConfig {
        name: "alice",
        ciphersuites: Config::supported_ciphersuite_names().to_vec(),
    };

    let mut test_group_configs = Vec::new();

    // Create a group config for each ciphersuite.
    for ciphersuite_name in Config::supported_ciphersuite_names() {
        let test_group = TestGroupConfig {
            ciphersuite: *ciphersuite_name,
            config: GroupConfig::default(),
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
    let test_setup = setup(test_setup_config);

    let test_clients = test_setup.clients.borrow();
    let alice = test_clients.get("alice").unwrap().borrow();

    for padding_size in 0..50 {
        // Create a message in each group and test the padding.
        for group_state in alice.group_states.borrow_mut().values_mut() {
            let credential_bundle = alice
                .credential_bundles
                .get(&group_state.ciphersuite().name())
                .unwrap();
            for _ in 0..10 {
                let message = randombytes(random_usize() % 1000);
                let aad = randombytes(random_usize() % 1000);
                let encrypted_message = group_state
                    .create_application_message(&aad, &message, &credential_bundle, padding_size)
                    .unwrap()
                    .ciphertext;
                let ciphertext = encrypted_message.as_slice();
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

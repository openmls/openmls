use openmls::prelude::*;
mod utils;
use utils::*;

#[test]
fn padding() {
    let alice_config = TestClientConfig {
        name: "alice",
        ciphersuites: Config::supported_ciphersuite_names(),
    };

    let mut test_group_configs = Vec::new();

    for ciphersuite_name in Config::supported_ciphersuite_names() {
        let test_group = TestGroupConfig {
            ciphersuite: ciphersuite_name,
            config: GroupConfig::default(),
            members: vec![alice_config.clone()],
        };
        test_group_configs.push(test_group);
    }

    let test_setup_config = TestSetupConfig {
        clients: vec![alice_config],
        groups: test_group_configs,
    };

    let test_setup = setup(test_setup_config);

    let test_clients = test_setup.clients.borrow();
    let alice = test_clients.get("alice").unwrap().borrow();

    const PADDING_SIZE: usize = 10;

    for group_state in alice.group_states.borrow_mut().values_mut() {
        let credential_bundle = alice
            .credential_bundles
            .get(&group_state.ciphersuite().name())
            .unwrap();
        for _ in 0..100 {
            let message = randombytes(random_usize() % 1000);
            let aad = randombytes(random_usize() % 1000);
            let encrypted_message = group_state
                .create_application_message(&aad, &message, &credential_bundle)
                .ciphertext;
            let ciphertext = encrypted_message.as_slice();
            let length = ciphertext.len();
            let overflow = length % PADDING_SIZE;
            if overflow != 0 {
                panic!(
                    "Error: padding overflow of {} bytes, message length: {}, padding block size: {}",
                    overflow, length, PADDING_SIZE
                );
            }
        }
    }
}

use crate::ciphersuite::*;
use crate::config::*;
use evercrypt::prelude::get_random_vec;

use super::EpochSecrets;

#[test]
fn test_encryption_secret_removal() {
    for ciphersuite in Config::supported_ciphersuites() {
        let epoch_secret = Secret::from(get_random_vec(ciphersuite.hash_length()));
        let welcome_secret = Secret::from(get_random_vec(ciphersuite.hash_length()));
        let mut epoch_secrets =
            EpochSecrets::derive_epoch_secrets(ciphersuite, &epoch_secret, welcome_secret);
        // Getting the encryption secret once should not be a problem.
        let encryption_secret = epoch_secrets.remove_encryption_secret();
        assert!(encryption_secret.is_ok());
        // Getting it for a second time should yield an error.
        let encryption_secret = epoch_secrets.remove_encryption_secret();
        assert!(encryption_secret.is_err());
    }
}

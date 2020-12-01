//! A data structure holding information about the leaf node in the tree that
//! belongs to the current client.

use evercrypt::prelude::get_random_vec;
use hpke::HPKEKeyPair;

use crate::ciphersuite::*;

#[derive(Debug)]
pub(crate) struct CommitSecret {
    secret: Secret,
}

#[allow(dead_code)]
impl CommitSecret {
    /// Convert a `PathSecret`, which should be the result of calling
    /// `to_path_secret_and_key_pair` on the `PathSecret` corresponding to the
    /// root secret, to a `CommitSecret`, which can then be used in the key
    /// schedule.
    fn from_path_secret(root_secret: PathSecret) -> Self {
        CommitSecret {
            secret: root_secret.secret,
        }
    }
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }
}

#[derive(Debug)]
pub(crate) struct PathSecret {
    secret: Secret,
}

#[allow(dead_code)]
impl PathSecret {
    /// Derive a `PathSecret` and (via a an intermediate secret) an
    /// `HPKEKeyPair` from a `PathSecret`, consuming it in the process.
    pub(crate) fn to_key_pair_and_path_secret(
        self,
        ciphersuite: &Ciphersuite,
    ) -> (HPKEKeyPair, PathSecret) {
        let node_secret = self.secret.derive_secret(ciphersuite, "node");
        let hpke_key_pair = ciphersuite.derive_hpke_keypair(&node_secret);
        let path_secret_value = self.secret.derive_secret(ciphersuite, "path");
        let path_secret = PathSecret {
            secret: path_secret_value,
        };
        (hpke_key_pair, path_secret)
    }

    /// Decrypt a `PathSecret`.
    pub(crate) fn decrypt_path_secret(
        ciphersuite: &Ciphersuite,
        hpke_ciphertext: &HpkeCiphertext,
        hpke_private_key: &HPKEPrivateKey,
        group_context: &[u8],
    ) -> Self {
        let secret = Secret::from(ciphersuite.hpke_open(
            hpke_ciphertext,
            &hpke_private_key,
            group_context,
            &[],
        ));
        PathSecret { secret }
    }
}

/// The LeafSecret is essentially a path secret that is freshly sampled for one
/// of the leaves.
#[derive(Debug)]
pub(crate) struct LeafSecret {
    secret: Secret,
}

#[allow(dead_code)]
impl LeafSecret {
    /// Randomly sample a fresh `LeafSecret`
    pub(crate) fn random(length: usize) -> Self {
        let secret = Secret::from(get_random_vec(length));
        LeafSecret { secret }
    }

    /// Derive a `PathSecret` and (via a an intermediate secret) an
    /// `HPKEKeyPair` from a `LeafSecret`, consuming it in the process.
    pub(crate) fn to_key_pair_and_path_secret(
        self,
        ciphersuite: &Ciphersuite,
    ) -> (HPKEKeyPair, PathSecret) {
        let leaf_path_secret = PathSecret {
            secret: self.secret,
        };
        leaf_path_secret.to_key_pair_and_path_secret(ciphersuite)
    }
}

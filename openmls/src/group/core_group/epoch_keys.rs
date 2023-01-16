//! This module contains functions and struct definitions for a per-epoch key
//! store. The key store contains the private key material that corresponds to
//! public key material in the group's ratchet tree and has to be passed into
//! all [`CoreGroup`] functions that use public-key cryptography.
//!
//! The internal functions of [`CoreGroup`] can then use the methods exposed by
//! [`EpochPrivateKeys`] to decrypt or sign payloads.
//!
//! The [`NewEpochPrivateKeys`] struct can be returned by functions that
//!
//!
//! TODO:
//!   * Can we check at creation if the backend supports the ciphersuite?
//!   * Can we ask the tree to give us all the public keys to which we have
//!     private keys? That would allows to load the right keys and give us the
//!     confidence to hide errors later.
//!   * New private keys should be returned in a different

use std::collections::HashMap;

use crate::{
    ciphersuite::{HpkePrivateKey, HpkePublicKey, SignaturePrivateKey},
    group::GroupEpoch,
    versions::ProtocolVersion,
};

use openmls_traits::{
    crypto::OpenMlsCrypto,
    key_store::OpenMlsKeyStore,
    types::{Ciphersuite, CryptoError, HpkeCiphertext, HpkeKeyPair},
    OpenMlsCryptoProvider,
};

pub enum EpochPrivateKeysError {
    UnknownKey,
}

pub(crate) struct EpochPrivateKeys {
    /// The GroupEpoch is used to actually bind the epoch keys to a specific epoch.
    epoch: GroupEpoch,
    ciphersuite: Ciphersuite,
    version: ProtocolVersion,
    hpke_keys: HashMap<HpkePublicKey, HpkePrivateKey>,
}

impl EpochPrivateKeys {
    pub(crate) fn new(
        ciphersuite: Ciphersuite,
        version: ProtocolVersion,
        epoch: GroupEpoch,
        key_pairs: Vec<HpkeKeyPair>,
    ) -> Self {
        let hpke_keys = key_pairs
            .into_iter()
            .map(|keypair: HpkeKeyPair| (keypair.public.into(), keypair.private.into()))
            .collect();
        Self {
            epoch,
            ciphersuite,
            version,
            hpke_keys,
        }
    }
    pub(crate) fn load_from_key_store(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        version: ProtocolVersion,
        epoch: GroupEpoch,
        owned_keys: &[HpkePublicKey],
    ) -> Result<Self, EpochPrivateKeysError> {
        let hpke_keys = owned_keys
            .iter()
            .map(|key| {
                backend
                    .key_store()
                    .read(key.as_slice())
                    .map(|keypair: HpkeKeyPair| (keypair.public.into(), keypair.private.into()))
                    .ok_or(EpochPrivateKeysError::UnknownKey)
            })
            .collect::<Result<HashMap<HpkePublicKey, HpkePrivateKey>, EpochPrivateKeysError>>()?;
        Ok(Self {
            epoch,
            ciphersuite,
            version,
            hpke_keys,
        })
    }

    pub(crate) fn decrypt(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphertext: &HpkeCiphertext,
        pk: &HpkePublicKey,
        group_context: &[u8],
        epoch: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        // TODO: Remove unwrap
        let sk = self.hpke_keys.get(pk).unwrap();
        backend.crypto().hpke_open(
            self.ciphersuite.hpke_config(),
            ciphertext,
            sk.as_slice(),
            group_context,
            &[],
        )
    }
}

pub(crate) struct NewEpochPrivateKeys {
    hpke_keys: HashMap<HpkePublicKey, HpkePrivateKey>,
    leaf_key: Option<SignaturePrivateKey>,
}

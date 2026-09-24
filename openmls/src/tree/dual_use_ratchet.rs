//! [`SenderRatchet`](super::sender_ratchet::SenderRatchet) variant for the
//! `virtual-clients-draft` feature. The ratchet supports both encryption and
//! decryption of own messages, with explicit confirmation-based deletion of
//! emitted encryption secrets for forward secrecy.

use std::collections::BTreeMap;
use std::mem;

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::Ciphersuite;
use serde::{Deserialize, Serialize};

use crate::ciphersuite::Secret;
use crate::tree::secret_tree::SecretTreeError;
use crate::tree::sender_ratchet::{
    Generation, RatchetKeyMaterial, RatchetSecret, SenderRatchetConfiguration,
};
use crate::utils::vector_converter;

/// [`SenderRatchet`](super::sender_ratchet::SenderRatchet) used for own
/// ratchets when the `virtual-clients-draft` feature is enabled. It supports
/// both encryption and decryption: encryption is needed to send messages, while
/// decryption lets the local member also decrypt their own ciphertexts (e.g.
/// when receiving a message encrypted by another emulating client). Encryption
/// secrets are kept in a past-secrets window like a `DecryptionRatchet` until
/// they are explicitly dropped by confirming the corresponding generation via
/// [`Self::delete_secret_for_generation`].
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Clone))]
#[cfg_attr(any(feature = "crypto-debug", test), derive(Debug))]
pub(crate) struct DualUseRatchet {
    #[serde(with = "vector_converter")]
    past_secrets: BTreeMap<Generation, DualUsePastSecret>,
    ratchet_head: RatchetSecret,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Clone))]
#[cfg_attr(any(feature = "crypto-debug", test), derive(Debug))]
enum DualUsePastSecret {
    AwaitingConfirmation(RatchetKeyMaterial),
    RetainedForDecryption(RetainedDecryptionSecret),
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Clone))]
#[cfg_attr(any(feature = "crypto-debug", test), derive(Debug))]
enum RetainedDecryptionSecret {
    Available(RatchetKeyMaterial),
    Consumed,
}

impl DualUsePastSecret {
    fn take_for_decryption(&mut self) -> Result<RatchetKeyMaterial, SecretTreeError> {
        match mem::replace(
            self,
            Self::RetainedForDecryption(RetainedDecryptionSecret::Consumed),
        ) {
            Self::AwaitingConfirmation(ratchet_secret)
            | Self::RetainedForDecryption(RetainedDecryptionSecret::Available(ratchet_secret)) => {
                Ok(ratchet_secret)
            }
            Self::RetainedForDecryption(RetainedDecryptionSecret::Consumed) => {
                Err(SecretTreeError::SecretReuseError)
            }
        }
    }

    fn is_retained_for_decryption(&self) -> bool {
        matches!(self, Self::RetainedForDecryption(_))
    }
}

impl From<RatchetSecret> for DualUseRatchet {
    /// Promotes a plain [`RatchetSecret`] (the state of an `EncryptionRatchet`
    /// persisted before the `virtual-clients-draft` feature was enabled) into
    /// a fresh [`DualUseRatchet`] with no past secrets. This is used to
    /// upgrade own ratchets deserialized from state written by a build
    /// without the feature.
    fn from(ratchet_head: RatchetSecret) -> Self {
        Self {
            past_secrets: BTreeMap::new(),
            ratchet_head,
        }
    }
}

impl DualUseRatchet {
    pub(crate) fn new(secret: Secret) -> Self {
        Self {
            past_secrets: BTreeMap::new(),
            ratchet_head: RatchetSecret::initial_ratchet_secret(secret),
        }
    }

    pub(crate) fn generation(&self) -> Generation {
        self.ratchet_head.generation()
    }

    /// Discard the cached encryption secret for a previously emitted
    /// generation. Call this to confirm a sent message and drop the
    /// corresponding key material for forward secrecy.
    ///
    /// No-op if the requested generation is at or beyond the ratchet head
    /// (i.e. nothing has been emitted yet for that generation).
    pub(crate) fn delete_secret_for_generation(&mut self, generation: Generation) {
        let head = self.generation();
        if generation >= head {
            return;
        }
        if matches!(
            self.past_secrets.get(&generation),
            Some(DualUsePastSecret::AwaitingConfirmation(_))
        ) {
            self.past_secrets.remove(&generation);
        }
    }

    /// Gets a secret for encryption. The secret is also recorded in the
    /// past-secrets window so the caller can later confirm and drop it. This
    /// requires cloning the [`RatchetKeyMaterial`] with one clone returned and
    /// the other retained until confirmation or use for decryption.
    ///
    /// The cache is not pruned here: emitted encryption secrets are only
    /// cleared by an explicit call to [`Self::delete_secret_for_generation`]
    /// (i.e. confirming the message). Auto-pruning at this point could drop
    /// unconfirmed secrets the caller still intends to confirm.
    pub(crate) fn secret_for_encryption(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<(Generation, RatchetKeyMaterial), SecretTreeError> {
        let generation = self.ratchet_head.generation();
        let ratchet_secrets = self
            .ratchet_head
            .ratchet_forward(crypto, ciphersuite)
            .map(|(_, key_material)| key_material)?;
        self.past_secrets.insert(
            generation,
            DualUsePastSecret::AwaitingConfirmation(ratchet_secrets.clone()),
        );
        Ok((generation, ratchet_secrets))
    }

    /// Gets a secret for decryption.
    ///
    /// The receive-side retention window is computed only from generations
    /// retained for decryption because encryption also advances the derivation
    /// head. Local sends don't enter this window. Unconfirmed encryption secrets
    /// are retained even if they fall outside the receive window.
    pub(crate) fn secret_for_decryption(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        generation: Generation,
        configuration: &SenderRatchetConfiguration,
    ) -> Result<RatchetKeyMaterial, SecretTreeError> {
        log::debug!("secret_for_decryption");
        let head_generation = self.ratchet_head.generation();
        if head_generation < u32::MAX - configuration.maximum_forward_distance()
            && generation > head_generation + configuration.maximum_forward_distance()
        {
            return Err(SecretTreeError::TooDistantInTheFuture);
        }

        let ratchet_secrets = if generation >= head_generation {
            for skipped_generation in head_generation..generation {
                let ratchet_secrets = self
                    .ratchet_head
                    .ratchet_forward(crypto, ciphersuite)
                    .map(|(_, key_material)| key_material)?;
                self.past_secrets.insert(
                    skipped_generation,
                    DualUsePastSecret::RetainedForDecryption(RetainedDecryptionSecret::Available(
                        ratchet_secrets,
                    )),
                );
            }
            let ratchet_secrets = self
                .ratchet_head
                .ratchet_forward(crypto, ciphersuite)
                .map(|(_, key_material)| key_material)?;
            self.past_secrets.insert(
                generation,
                DualUsePastSecret::RetainedForDecryption(RetainedDecryptionSecret::Consumed),
            );
            ratchet_secrets
        } else {
            let Some(entry) = self.past_secrets.get_mut(&generation) else {
                return Err(self.error_for_missing_past_secret(generation));
            };
            entry.take_for_decryption()?
        };

        self.prune_past_secrets(configuration);
        Ok(ratchet_secrets)
    }

    fn error_for_missing_past_secret(&self, generation: Generation) -> SecretTreeError {
        if self
            .past_secrets
            .iter()
            .find(|(_, entry)| entry.is_retained_for_decryption())
            .is_some_and(|(oldest_generation, _)| generation < *oldest_generation)
        {
            log::error!("  Generation is too far in the past (not in the window).");
            SecretTreeError::TooDistantInThePast
        } else {
            SecretTreeError::SecretReuseError
        }
    }

    fn prune_past_secrets(&mut self, configuration: &SenderRatchetConfiguration) {
        let excess_retained_decryption_secrets = self
            .past_secrets
            .values()
            .filter(|entry| entry.is_retained_for_decryption())
            .count()
            .saturating_sub(configuration.out_of_order_tolerance() as usize);

        let generations_to_prune = self
            .past_secrets
            .iter()
            .filter_map(|(generation, entry)| {
                entry.is_retained_for_decryption().then_some(*generation)
            })
            .take(excess_retained_decryption_secrets)
            .collect::<Vec<_>>();

        for generation in generations_to_prune {
            self.past_secrets.remove(&generation);
        }
    }
}

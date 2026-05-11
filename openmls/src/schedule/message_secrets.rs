//! This module defines the [`MessageSecrets`] struct that can be used for message decryption & verification

#[cfg(not(target_arch = "wasm32"))]
use std::time::SystemTime;
#[cfg(target_arch = "wasm32")]
use web_time::SystemTime;

use super::*;

/// Combined message secrets that need to be stored for later decryption/verification
//
// IMPORTANT: this struct is part of the persisted on-disk format (it lives
// inside `MessageSecretsStore`, which is written by the storage provider).
// The first five fields are the openmls-0.7.x shape and MUST NOT be reordered
// or have fields inserted between them. The trailing `added_at` field is
// always serialized but is deserialized *tolerantly*: a custom
// `Deserialize` impl probes for the field via `SeqAccess::next_element` and
// treats any error (e.g. bincode EOF past the 0.7.x five-field boundary) as
// "field absent, default to `None`". This lets the same struct round-trip:
//
// * post-0.8 data that already contains the field (any format),
// * 0.7.x data that predates the field, in both self-describing formats
//   (JSON, CBOR — via `#[serde(default)]` semantics on the map path) and
//   non-self-describing formats (bincode, postcard — via the EOF-tolerant
//   seq path).
//
// Caveat for non-self-describing formats: this struct must be the **last
// field** of any containing struct for the EOF-tolerant fallback to work
// safely. In `MessageSecretsStore` that is the case. Within `EpochTree`,
// `MessageSecrets` precedes `leaves`, so 0.7.x EpochTree bytes (which lack
// `added_at`) cannot be read tolerantly here — the deserializer would
// interpret leaves-length bytes as the `Option<SystemTime>` tag.
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct MessageSecrets {
    sender_data_secret: SenderDataSecret,
    membership_key: MembershipKey,
    confirmation_key: ConfirmationKey,
    serialized_context: Vec<u8>,
    secret_tree: SecretTree,
    /// When the secrets were added to the store.
    ///
    /// `None` if no timestamp is available — including when reading data
    /// that predates this field (see the struct-level doc comment for the
    /// tolerant-deserialization rules).
    ///
    /// NOTE: SystemTime is not guaranteed to be monotonic.
    added_at: Option<SystemTime>,
}

const MESSAGE_SECRETS_FIELDS: &[&str] = &[
    "sender_data_secret",
    "membership_key",
    "confirmation_key",
    "serialized_context",
    "secret_tree",
    "added_at",
];

impl Serialize for MessageSecrets {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let mut s = serializer.serialize_struct("MessageSecrets", MESSAGE_SECRETS_FIELDS.len())?;
        s.serialize_field("sender_data_secret", &self.sender_data_secret)?;
        s.serialize_field("membership_key", &self.membership_key)?;
        s.serialize_field("confirmation_key", &self.confirmation_key)?;
        s.serialize_field("serialized_context", &self.serialized_context)?;
        s.serialize_field("secret_tree", &self.secret_tree)?;
        s.serialize_field("added_at", &self.added_at)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for MessageSecrets {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_struct(
            "MessageSecrets",
            MESSAGE_SECRETS_FIELDS,
            MessageSecretsVisitor,
        )
    }
}

struct MessageSecretsVisitor;

impl<'de> serde::de::Visitor<'de> for MessageSecretsVisitor {
    type Value = MessageSecrets;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("struct MessageSecrets")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> Result<MessageSecrets, A::Error> {
        use serde::de::Error;

        let sender_data_secret = seq
            .next_element::<SenderDataSecret>()?
            .ok_or_else(|| Error::missing_field("sender_data_secret"))?;
        let membership_key = seq
            .next_element::<MembershipKey>()?
            .ok_or_else(|| Error::missing_field("membership_key"))?;
        let confirmation_key = seq
            .next_element::<ConfirmationKey>()?
            .ok_or_else(|| Error::missing_field("confirmation_key"))?;
        let serialized_context = seq
            .next_element::<Vec<u8>>()?
            .ok_or_else(|| Error::missing_field("serialized_context"))?;
        let secret_tree = seq
            .next_element::<SecretTree>()?
            .ok_or_else(|| Error::missing_field("secret_tree"))?;

        // Tolerant tail read: post-0.8 data has a sixth field
        // `added_at: Option<SystemTime>`. 0.7.x data does not. Any failure
        // here — `Ok(None)` from self-describing formats, EOF from bincode
        // and friends — is treated as "field absent" and defaults to `None`.
        // See the struct-level comment for the safety constraint that
        // requires this to be the last field of any containing struct.
        let added_at = seq
            .next_element::<Option<SystemTime>>()
            .unwrap_or(None)
            .flatten();

        Ok(MessageSecrets {
            sender_data_secret,
            membership_key,
            confirmation_key,
            serialized_context,
            secret_tree,
            added_at,
        })
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> Result<MessageSecrets, A::Error> {
        use serde::de::Error;

        let mut sender_data_secret: Option<SenderDataSecret> = None;
        let mut membership_key: Option<MembershipKey> = None;
        let mut confirmation_key: Option<ConfirmationKey> = None;
        let mut serialized_context: Option<Vec<u8>> = None;
        let mut secret_tree: Option<SecretTree> = None;
        let mut added_at: Option<Option<SystemTime>> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "sender_data_secret" => {
                    if sender_data_secret.is_some() {
                        return Err(Error::duplicate_field("sender_data_secret"));
                    }
                    sender_data_secret = Some(map.next_value()?);
                }
                "membership_key" => {
                    if membership_key.is_some() {
                        return Err(Error::duplicate_field("membership_key"));
                    }
                    membership_key = Some(map.next_value()?);
                }
                "confirmation_key" => {
                    if confirmation_key.is_some() {
                        return Err(Error::duplicate_field("confirmation_key"));
                    }
                    confirmation_key = Some(map.next_value()?);
                }
                "serialized_context" => {
                    if serialized_context.is_some() {
                        return Err(Error::duplicate_field("serialized_context"));
                    }
                    serialized_context = Some(map.next_value()?);
                }
                "secret_tree" => {
                    if secret_tree.is_some() {
                        return Err(Error::duplicate_field("secret_tree"));
                    }
                    secret_tree = Some(map.next_value()?);
                }
                "added_at" => {
                    if added_at.is_some() {
                        return Err(Error::duplicate_field("added_at"));
                    }
                    added_at = Some(map.next_value()?);
                }
                _ => {
                    // Ignore unknown fields for forward compatibility.
                    let _: serde::de::IgnoredAny = map.next_value()?;
                }
            }
        }

        Ok(MessageSecrets {
            sender_data_secret: sender_data_secret
                .ok_or_else(|| Error::missing_field("sender_data_secret"))?,
            membership_key: membership_key.ok_or_else(|| Error::missing_field("membership_key"))?,
            confirmation_key: confirmation_key
                .ok_or_else(|| Error::missing_field("confirmation_key"))?,
            serialized_context: serialized_context
                .ok_or_else(|| Error::missing_field("serialized_context"))?,
            secret_tree: secret_tree.ok_or_else(|| Error::missing_field("secret_tree"))?,
            added_at: added_at.unwrap_or(None),
        })
    }
}

#[cfg(not(feature = "crypto-debug"))]
impl core::fmt::Debug for MessageSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageSecrets")
            .field("sender_data_secret", &"***")
            .field("membership_key", &"***")
            .field("confirmation_key", &"***")
            .field("serialized_context", &"***")
            .field("secret_tree", &"***")
            .finish()
    }
}

// Public functions
impl MessageSecrets {
    ///Create new `MessageSecrets`
    pub(crate) fn new(
        sender_data_secret: SenderDataSecret,
        membership_key: MembershipKey,
        confirmation_key: ConfirmationKey,
        serialized_context: Vec<u8>,
        secret_tree: SecretTree,
    ) -> Self {
        Self {
            sender_data_secret,
            membership_key,
            confirmation_key,
            serialized_context,
            secret_tree,
            added_at: None,
        }
    }

    /// Get a reference to the message secrets's sender data secret.
    pub(crate) fn sender_data_secret(&self) -> &SenderDataSecret {
        &self.sender_data_secret
    }

    /// Get a reference to the message secrets's membership key.
    pub(crate) fn membership_key(&self) -> &MembershipKey {
        &self.membership_key
    }

    /// Get a reference to the message secrets's confirmation key.
    pub(crate) fn confirmation_key(&self) -> &ConfirmationKey {
        &self.confirmation_key
    }

    /// Get a reference to the message secrets's serialized context.
    pub(crate) fn serialized_context(&self) -> &[u8] {
        self.serialized_context.as_ref()
    }

    /// Get a mutable reference to the message secrets's secret tree.
    pub(crate) fn secret_tree_mut(&mut self) -> &mut SecretTree {
        &mut self.secret_tree
    }

    pub(crate) fn timestamp(&self) -> Option<SystemTime> {
        self.added_at
    }

    pub(crate) fn with_timestamp(self, timestamp: impl Into<Option<SystemTime>>) -> Self {
        Self {
            added_at: timestamp.into(),
            ..self
        }
    }

    /// Helper function to create a `MessageSecrets` with `None` timestamp
    #[cfg(test)]
    pub(crate) fn without_timestamp(self) -> Self {
        Self {
            added_at: None,
            ..self
        }
    }
}

// Test functions
impl MessageSecrets {
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn sender_data_secret_mut(&mut self) -> &mut SenderDataSecret {
        &mut self.sender_data_secret
    }

    #[cfg(test)]
    /// Update the message secrets's serialized context.
    pub(crate) fn set_serialized_context(&mut self, serialized_context: Vec<u8>) {
        self.serialized_context = serialized_context;
    }

    #[cfg(test)]
    /// Update the membership key.
    pub(crate) fn set_membership_key(&mut self, membership_key: Secret) {
        self.membership_key = MembershipKey::from_secret(membership_key);
    }

    #[cfg(test)]
    pub(crate) fn random(
        ciphersuite: Ciphersuite,
        rng: &impl OpenMlsRand,
        own_index: LeafNodeIndex,
    ) -> Self {
        Self {
            sender_data_secret: SenderDataSecret::random(ciphersuite, rng),
            membership_key: MembershipKey::random(ciphersuite, rng),
            confirmation_key: ConfirmationKey::random(ciphersuite, rng),
            serialized_context: rng.random_vec(10).expect("Not enough randomness."),
            secret_tree: SecretTree::new(
                EncryptionSecret::random(ciphersuite, rng),
                TreeSize::new(10),
                own_index,
            ),
            added_at: None,
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn replace_secret_tree(&mut self, secret_tree: SecretTree) -> SecretTree {
        std::mem::replace(&mut self.secret_tree, secret_tree)
    }
}

// In tests we allow comparing secrets.
#[cfg(any(test, feature = "test-utils"))]
impl PartialEq for MessageSecrets {
    fn eq(&self, other: &Self) -> bool {
        self.sender_data_secret == other.sender_data_secret
            && self.membership_key == other.membership_key
            && self.confirmation_key == other.confirmation_key
            && self.secret_tree == other.secret_tree
    }
}

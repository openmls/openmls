//! ### Don't Panic!
//!
//! Functions in this module should never panic. However, if there is a bug in
//! the implementation, a function will return an unrecoverable `LibraryError`.
//! This means that some functions that are not expected to fail and throw an
//! error, will still return a `Result` since they may throw a `LibraryError`.

use std::collections::VecDeque;

use crate::ciphersuite::{AeadNonce, *};

use super::*;

/// The generation of a given [`SenderRatchet`].
pub(crate) type Generation = u32;
/// Stores the configuration parameters for `DecryptionRatchet`s.
///
/// **Parameters**
///
/// - out_of_order_tolerance:
///   This parameter defines a window for which decryption secrets are kept.
///   This is useful in case the DS cannot guarantee that all application messages have total order within an epoch.
///   Use this carefully, since keeping decryption secrets affects forward secrecy within an epoch.
///   The default value is 5.
/// - maximum_forward_distance:
///   This parameter defines how many incoming messages can be skipped. This is useful if the DS
///   drops application messages. The default value is 1000.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderRatchetConfiguration {
    out_of_order_tolerance: Generation,
    maximum_forward_distance: Generation,
}

/// The key material derived from a [`RatchetSecret`] meant for use with a
/// nonce-based symmetric encryption scheme.
pub(crate) type RatchetKeyMaterial = (AeadKey, AeadNonce);

/// A ratchet that can output key material either for encryption
/// ([`EncryptionRatchet`](SenderRatchet)) or decryption
/// ([`DecryptionRatchet`]). A [`DecryptionRatchet`] can be configured with an
/// `out_of_order_tolerance` and a `maximum_forward_distance` (see
/// [`SenderRatchetConfiguration`]) while an Encryption Ratchet never keeps past
/// secrets around.
#[derive(Serialize, Deserialize)]
pub(crate) enum SenderRatchet {
    EncryptionRatchet(RatchetSecret),
    DecryptionRatchet(DecryptionRatchet),
}

/// The core of both types of [`SenderRatchet`]. It contains the current head of
/// the ratchet chain, as well as its current [`Generation`]. It can be
/// initialized with a given secret and then ratcheted forward, outputting
/// [`RatchetKeyMaterial`] and increasing its [`Generation`] each time.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RatchetSecret {
    secret: Secret,
    generation: Generation,
}

/// [`SenderRatchet`] used to derive key material for decryption. It keeps the
/// [`RatchetKeyMaterial`] of epochs around until they are retrieved. This
/// behaviour can be configured via the `out_of_order_tolerance` and
/// `maximum_forward_distance` of the given [`SenderRatchetConfiguration`].
#[derive(Serialize, Deserialize)]
pub struct DecryptionRatchet {
    past_secrets: VecDeque<Option<RatchetKeyMaterial>>,
    ratchet_head: RatchetSecret,
}

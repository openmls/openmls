//! # Key Schedule
//!
//! This module defines types and implementations for key schedule operations.
//! It provides the [`EpochAuthenticator`] and [`ResumptionPskSecret`] types.
//!
//! ## Internal Documentation
//!
//! The key schedule is described in Section 9 of the MLS specification. It
//! evolves in epochs, with new key material injected in each epoch.
//!
//! The key schedule flow (from Section 9 of the MLS specification) is as follows:
//
// ```text
//                  init_secret_[n-1]
//                         |
//                         V
//    commit_secret -> KDF.Extract
//                         |
//                         V
//                   DeriveSecret(., "joiner")
//                         |
//                         V
//                    joiner_secret
//                         |
//                         V
// psk_secret (or 0) -> KDF.Extract (= intermediary_secret)
//                         |
//                         +--> DeriveSecret(., "welcome")
//                         |    = welcome_secret
//                         |
//                         V
//                   ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh)
//                         |
//                         V
//                    epoch_secret
//                         |
//                         +--> DeriveSecret(., <label>)
//                         |    = <secret>
//                         |
//                         V
//                   DeriveSecret(., "init")
//                         |
//                         V
//                   init_secret_[n]
// ```
//
// Each secret in the key schedule (except welcome_secret) has its own struct to
// prevent confusion or out-of-order derivation. This ensures clarity and safety
// in the key schedule operations.
//
// ## Key schedule structure
// The spec's key schedule isn't a single linear process. The `joiner_secret`
// serves as both an intermediate and output value, which violates key schedule
// principles. The actual key schedule begins with the `joiner_secret`, as seen
// when initializing a group from a welcome message.
//
// The `joiner_secret` is computed as
//
// ```text
//     DeriveSecret(KDF.Extract(init_secret_[n-1], commit_secret), "joiner")
// ```
//
// or
//
// ```text
//                  init_secret_[n-1]
//                         |
//                         V
//    commit_secret -> KDF.Extract
//                         |
//                         V
//                   DeriveSecret(., "joiner")
//                         |
//                         V
//                    joiner_secret
// ```
//
// The key schedule continues with `joiner_secret` and `psk_secret`. The graph
// below includes `GroupContext_[n]` as input, which is omitted in the spec. The
// derivation of secrets from `epoch_secret` is simplified for clarity.
//
// ```text
//                    joiner_secret
//                         |
//                         V
// psk_secret (or 0) -> KDF.Extract
//                         |
//                         +--> DeriveSecret(., "welcome")
//                         |    = welcome_secret
//                         |
//                         V
// GroupContext_[n] -> ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh)
//                         |
//                         V
//                    epoch_secret
//                         |
//                         v
//                 DeriveSecret(., <label>)
//                     = <secret>
// ```
//
// with
//
// ```text
// | secret                  | label           |
// |:------------------------|:----------------|
// | `init_secret`           | "init"          |
// | `sender_data_secret`    | "sender data"   |
// | `encryption_secret`     | "encryption"    |
// | `exporter_secret`       | "exporter"      |
// | `epoch_authenticator`   | "authentication"|
// | `external_secret`       | "external"      |
// | `confirmation_key`      | "confirm"       |
// | `membership_key`        | "membership"    |
// | `resumption_psk`        | "resumption"    |
// ```

use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{ciphersuite::Secret, tree::secret_tree::SecretTree};

// Public
pub mod errors;
#[cfg(feature = "extensions-draft-08")]
mod pprf;
pub mod psk;

// Crate
#[cfg(feature = "extensions-draft-08")]
pub(crate) mod application_export_tree;
pub(crate) mod message_secrets;

// Public types
pub use psk::{ExternalPsk, PreSharedKeyId, Psk};

/// A group secret that can be used among members to prove that a member was
/// part of a group in a given epoch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResumptionPskSecret {
    secret: Secret,
}

/// A secret that can be used among members to make sure everyone has the same
/// group state.
#[derive(Debug, Serialize, Deserialize)]
pub struct EpochAuthenticator {
    secret: Secret,
}

// Crate-only types

/// The `InitSecret` is used to connect the next epoch to the current one.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct InitSecret {
    secret: Secret,
}

#[derive(Debug, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize)]
pub(crate) struct JoinerSecret {
    secret: Secret,
}

/// A secret that we can derive secrets from, that are used outside of OpenMLS.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ExporterSecret {
    secret: Secret,
}

/// A secret that we can derive secrets from, that are used outside of OpenMLS.
/// In contrast to `[ExporterSecret]`, the `[ApplicationExportSecret]` is not
/// persisted. It can be deleted after use to achieve forward secrecy.
#[cfg(feature = "extensions-draft-08")]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApplicationExportSecret {
    secret: Secret,
}

/// A secret used when joining a group with an external Commit.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ExternalSecret {
    secret: Secret,
}

/// The confirmation key is used to calculate the `ConfirmationTag`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ConfirmationKey {
    secret: Secret,
}

/// The membership key is used to calculate the `MembershipTag`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MembershipKey {
    secret: Secret,
}

/// A key that can be used to derive an `AeadKey` and an `AeadNonce`.
#[derive(Serialize, Deserialize)]
pub(crate) struct SenderDataSecret {
    secret: Secret,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct GroupEpochSecrets {
    init_secret: InitSecret,
    exporter_secret: ExporterSecret,
    epoch_authenticator: EpochAuthenticator,
    external_secret: ExternalSecret,
    resumption_psk: ResumptionPskSecret,
}

impl std::fmt::Debug for GroupEpochSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GroupEpochSecrets { *** }")
    }
}

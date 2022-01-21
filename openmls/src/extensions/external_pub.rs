//! # ExternalPub Extension
//!
//! The ExternalPub extension is a GroupInfo extension that is needed if a party
//! wants to join a group through an External Commit. It contains the public key
//! which is used in the process of the External Commit to encrypt the init
//! secret of the new epoch.
//!
//! ```text
//! struct {
//!     HPKEPublicKey external_pub;
//! } ExternalPub;
//! ```

use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::ciphersuite::HpkePublicKey;

#[derive(
    PartialEq, Clone, Debug, Serialize, Deserialize, TlsSize, TlsSerialize, TlsDeserialize,
)]
pub struct ExternalPubExtension {
    external_pub: HpkePublicKey,
}

impl ExternalPubExtension {
    /// Create a new capabilities extension with the given configuration.
    /// Any argument that is `None` is filled with the default values from the
    /// global configuration.
    pub fn new(external_pub: HpkePublicKey) -> Self {
        Self { external_pub }
    }

    /// Get a reference to the contained external public key.
    pub fn external_pub(&self) -> &HpkePublicKey {
        &self.external_pub
    }
}

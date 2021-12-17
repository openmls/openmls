//! # Message framing
//!
//! This module implements framing for MLS messages.
//!
//! See [`MlsPlaintext`] and [`MlsCiphertext`] for details.

use crate::ciphersuite::*;
use crate::credentials::*;
use crate::group::*;
use crate::messages::{proposals::*, *};
use crate::schedule::*;
use crate::treesync::*;

pub(crate) use serde::{Deserialize, Serialize};

pub mod ciphertext;
#[doc(hidden)]
pub mod codec;
pub mod errors;
pub mod message;
pub mod plaintext;
pub mod sender;
pub mod validation;
pub use ciphertext::*;
pub use errors::*;
pub use message::*;
pub use plaintext::*;
pub use sender::*;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};
pub use validation::*;

#[cfg(test)]
mod test_framing;

#[derive(
    PartialEq, Clone, Copy, Debug, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
#[repr(u8)]
pub enum WireFormat {
    MlsPlaintext = 1,
    MlsCiphertext = 2,
}

/// This struct is used to group common framing parameters
/// in order to reduce the number of arguments in function calls.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct FramingParameters<'a> {
    aad: &'a [u8],
    wire_format: WireFormat,
}

impl<'a> FramingParameters<'a> {
    pub fn new(aad: &'a [u8], wire_format: WireFormat) -> Self {
        Self { aad, wire_format }
    }
    pub fn aad(&self) -> &'a [u8] {
        self.aad
    }
    pub fn wire_format(&self) -> WireFormat {
        self.wire_format
    }
}

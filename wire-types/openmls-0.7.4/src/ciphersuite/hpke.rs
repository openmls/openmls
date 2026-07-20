//! ### Public-Key Encryption
//!
//! As with signing, MLS includes a label and context in encryption operations to
//! avoid confusion between ciphertexts produced for different purposes.  Encryption
//! and decryption including this label and context are done as follows:
//!
//! ```text
//! EncryptWithLabel(PublicKey, Label, Context, Plaintext) =
//!   SealBase(PublicKey, EncryptContext, "", Plaintext)
//!
//! DecryptWithLabel(PrivateKey, Label, Context, KEMOutput, Ciphertext) =
//!   OpenBase(KEMOutput, PrivateKey, EncryptContext, "", Ciphertext)
//! ```
//!
//! Where EncryptContext is specified as:
//!
//! ```text
//! struct {
//!   opaque label<V>;
//!   opaque context<V>;
//! } EncryptContext;
//! ```
//!
//! And its fields set to:
//!
//! ```text
//! label = "MLS 1.0 " + Label;
//! context = Context;
//! ```
//!
//! Here, the functions `SealBase` and `OpenBase` are defined RFC9180, using the
//! HPKE algorithms specified by the group's ciphersuite.  If MLS extensions
//! require HPKE encryption operations, they should re-use the EncryptWithLabel
//! construction, using a distinct label.  To avoid collisions in these labels, an
//! IANA registry is defined in mls-public-key-encryption-labels.

use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

/// Context for HPKE encryption
#[derive(Debug, Clone, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
pub struct EncryptContext {
    label: VLBytes,
    context: VLBytes,
}

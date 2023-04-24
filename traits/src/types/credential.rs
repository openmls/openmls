use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

/// CredentialType.
///
/// This enum contains variants for the different Credential Types.
///
/// ```c
/// // See IANA registry for registered values
/// uint16 CredentialType;
/// ```
///
/// **IANA Considerations**
///
/// | Value            | Name                     | R | Ref      |
/// |:-----------------|:-------------------------|:--|:---------|
/// | 0x0000           | RESERVED                 | - | RFC XXXX |
/// | 0x0001           | basic                    | Y | RFC XXXX |
/// | 0x0002           | x509                     | Y | RFC XXXX |
/// | 0x0A0A           | GREASE                   | Y | RFC XXXX |
/// | 0x1A1A           | GREASE                   | Y | RFC XXXX |
/// | 0x2A2A           | GREASE                   | Y | RFC XXXX |
/// | 0x3A3A           | GREASE                   | Y | RFC XXXX |
/// | 0x4A4A           | GREASE                   | Y | RFC XXXX |
/// | 0x5A5A           | GREASE                   | Y | RFC XXXX |
/// | 0x6A6A           | GREASE                   | Y | RFC XXXX |
/// | 0x7A7A           | GREASE                   | Y | RFC XXXX |
/// | 0x8A8A           | GREASE                   | Y | RFC XXXX |
/// | 0x9A9A           | GREASE                   | Y | RFC XXXX |
/// | 0xAAAA           | GREASE                   | Y | RFC XXXX |
/// | 0xBABA           | GREASE                   | Y | RFC XXXX |
/// | 0xCACA           | GREASE                   | Y | RFC XXXX |
/// | 0xDADA           | GREASE                   | Y | RFC XXXX |
/// | 0xEAEA           | GREASE                   | Y | RFC XXXX |
/// | 0xF000  - 0xFFFF | Reserved for Private Use | - | RFC XXXX |
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CredentialType {
    /// A [`BasicCredential`]
    Basic,
    /// An X.509 [`Certificate`]
    X509,
    /// A currently unknown credential.
    Unknown(u16),
}

mod serialization {
    use super::*;
    use std::io::{Read, Write};

    impl tls_codec::Size for CredentialType {
        fn tls_serialized_len(&self) -> usize {
            2
        }
    }

    impl tls_codec::Deserialize for CredentialType {
        fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
        where
            Self: Sized,
        {
            let mut extension_type = [0u8; 2];
            bytes.read_exact(&mut extension_type)?;

            Ok(CredentialType::from(u16::from_be_bytes(extension_type)))
        }
    }

    impl tls_codec::Serialize for CredentialType {
        fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
            writer.write_all(&u16::from(*self).to_be_bytes())?;

            Ok(2)
        }
    }

    impl tls_codec::Size for Credential {
        #[inline]
        fn tls_serialized_len(&self) -> usize {
            self.credential_type.tls_serialized_len()
                + match &self.credential {
                    MlsCredentialType::Basic(c) => c.tls_serialized_len(),
                    MlsCredentialType::X509(_) => unimplemented!(),
                }
        }
    }

    impl tls_codec::Serialize for Credential {
        fn tls_serialize<W: std::io::Write>(
            &self,
            writer: &mut W,
        ) -> Result<usize, tls_codec::Error> {
            match &self.credential {
                MlsCredentialType::Basic(basic_credential) => {
                    let written = CredentialType::Basic.tls_serialize(writer)?;
                    basic_credential.tls_serialize(writer).map(|l| l + written)
                }
                // TODO #134: implement encoding for X509 certificates
                MlsCredentialType::X509(_) => Err(tls_codec::Error::EncodingError(
                    "X509 certificates are not yet implemented.".to_string(),
                )),
            }
        }
    }

    impl tls_codec::Deserialize for Credential {
        fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
            let val = u16::tls_deserialize(bytes)?;
            let credential_type = CredentialType::try_from(val)
                .map_err(|e| tls_codec::Error::DecodingError(e.to_string()))?;
            match credential_type {
                CredentialType::Basic => Ok(Credential::from(MlsCredentialType::Basic(
                    BasicCredential::tls_deserialize(bytes)?,
                ))),
                _ => Err(tls_codec::Error::DecodingError(format!(
                    "{credential_type:?} can not be deserialized."
                ))),
            }
        }
    }
}

mod conversion {
    use super::*;

    impl From<u16> for CredentialType {
        fn from(value: u16) -> Self {
            match value {
                1 => CredentialType::Basic,
                2 => CredentialType::X509,
                unknown => CredentialType::Unknown(unknown),
            }
        }
    }

    impl From<CredentialType> for u16 {
        fn from(value: CredentialType) -> Self {
            match value {
                CredentialType::Basic => 1,
                CredentialType::X509 => 2,
                CredentialType::Unknown(unknown) => unknown,
            }
        }
    }

    impl From<MlsCredentialType> for Credential {
        fn from(mls_credential_type: MlsCredentialType) -> Self {
            Credential {
                credential_type: match mls_credential_type {
                    MlsCredentialType::Basic(_) => CredentialType::Basic,
                    MlsCredentialType::X509(_) => CredentialType::X509,
                },
                credential: mls_credential_type,
            }
        }
    }
}

/// Basic Credential.
///
/// A `BasicCredential` as defined in the MLS protocol spec. It exposes only an
/// `identity` to represent the client.
///
/// Note that this credential does not contain any key material or any other
/// information.
///
/// OpenMLS provides an implementation of signature keys for convenience in the
/// `openmls_basic_credential` crate.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct BasicCredential {
    identity: VLBytes,
}

impl BasicCredential {
    pub fn new(identity: VLBytes) -> Self {
        Self { identity }
    }
}

/// X.509 Certificate.
///
/// This struct contains an X.509 certificate.
///
/// ```c
/// struct {
///     opaque cert_data<V>;
/// } Certificate;
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Certificate {
    cert_data: Vec<u8>,
}

/// MlsCredentialType.
///
/// This enum contains variants containing the different available credentials.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum MlsCredentialType {
    /// A [`BasicCredential`]
    Basic(BasicCredential),
    /// An X.509 [`Certificate`] chain
    X509(Vec<Certificate>),
}

/// Credential.
///
/// This struct contains MLS credential data, where the data depends on the
/// type. The [`CredentialType`] always matches the [`MlsCredentialType`].
///
/// ```c
/// struct {
///     CredentialType credential_type;
///     select (Credential.credential_type) {
///         case basic:
///             opaque identity<V>;
///
///         case x509:
///             Certificate certificates<V>;
///     };
/// } Credential;
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Credential {
    credential_type: CredentialType,
    credential: MlsCredentialType,
}

impl Credential {
    /// Returns the credential type.
    pub fn credential_type(&self) -> CredentialType {
        self.credential_type
    }

    /// Creates and returns a new [`Credential`] of the given
    /// [`CredentialType`] for the given identity.
    /// If the credential holds key material, this is generated and stored in
    /// the key store.
    ///
    /// Returns an error if the given [`CredentialType`] is not supported.
    pub fn new(credential: MlsCredentialType) -> Self {
        Self {
            credential_type: match credential {
                MlsCredentialType::Basic(_) => CredentialType::Basic,
                MlsCredentialType::X509(_) => CredentialType::X509,
            },
            credential,
        }
    }

    /// Returns the identity of a given credential.
    pub fn identity(&self) -> &[u8] {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => basic_credential.identity.as_slice(),
            // TODO: implement getter for identity for X509 certificates. See issue #134.
            MlsCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
    }
}

/// An error that occurs in methods of a [`Credential`].
#[derive(Debug, PartialEq, Clone)]
pub enum CredentialError {
    /// The type of credential is not supported.
    UnsupportedCredentialType,
    /// Verifying the signature with this credential failed.
    InvalidSignature,
}

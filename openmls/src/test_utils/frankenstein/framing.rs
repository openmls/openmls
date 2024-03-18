use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer, types::Ciphersuite, OpenMlsProvider};
use tls_codec::*;

use super::key_package::FrankenKeyPackage;

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenMlsMessage {
    pub version: u16,
    pub body: FrankenMlsMessageBody,
}

#[allow(clippy::large_enum_variant)]
#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
#[repr(u16)]
pub enum FrankenMlsMessageBody {
    /// Plaintext message
    #[tls_codec(discriminant = 1)]
    PublicMessage(FrankenPublicMessage),

    /// Ciphertext message
    #[tls_codec(discriminant = 2)]
    PrivateMessage(FrankenPrivateMessage),

    /// Welcome message
    #[tls_codec(discriminant = 3)]
    Welcome(FrankenWelcome),

    /// Group information
    #[tls_codec(discriminant = 4)]
    GroupInfo(FrankenGroupInfo),

    /// KeyPackage
    #[tls_codec(discriminant = 5)]
    KeyPackage(FrankenKeyPackage),
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenPublicMessage;

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenPrivateMessage;

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenWelcome;

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenGroupInfo;

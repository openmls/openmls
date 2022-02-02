//! # Message errors

use openmls_traits::types::CryptoError;
use tls_codec::Error as TlsCodecError;

implement_error! {
    pub enum ProposalError {
        Simple {}
        Complex {
            CodecError(TlsCodecError) =
                "TLS (de)serialization error occurred.",
            CryptoError(CryptoError) =
                "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
        }
    }
}

implement_error! {
    pub enum ProposalOrRefTypeError {
        UnknownValue = "Invalid value for ProposalOrRefType was found.",
    }
}

impl From<ProposalOrRefTypeError> for tls_codec::Error {
    fn from(e: ProposalOrRefTypeError) -> Self {
        tls_codec::Error::DecodingError(format!("{:?}", e))
    }
}

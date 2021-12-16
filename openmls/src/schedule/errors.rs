use openmls_traits::types::CryptoError;
use tls_codec::Error as TlsCodecError;

implement_error! {
    pub enum ErrorState {
        Init = "Expected to be in initial state.",
        Epoch = "Expected to be in epoch state.",
        Context = "Expected to be in a state where the context is added.",
    }
}

implement_error! {
    pub enum KeyScheduleError {
        Simple {
            LibraryError = "An unrecoverable error has occurred due to a bug in the implementation.",
        }
        Complex {
            InvalidState(ErrorState) =
                "The requested operation is not valid on the key schedule state.",
            CryptoError(CryptoError) =
                "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
        }
    }
}

implement_error! {
    pub enum ExporterError {
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
    pub enum PskSecretError {
        Simple {
            TooManyKeys = "More than 2^16 PSKs were provided.",
            KeyNotFound = "The PSK could not be found in the key store.",
            EncodingError = "Error serializing the PSK label.",
        }
        Complex {
            CryptoError(CryptoError) = "See [`CryptoError`] for more details.",
        }
    }
}

implement_error! {
    pub enum MembershipKeyError {
        Simple {}
        Complex {
            CodecError(TlsCodecError) =
                "TLS (de)serialization error occurred.",
            CryptoError(CryptoError) =
                "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
implement_error! {
    pub enum KsTestVectorError {
        JoinerSecretMismatch = "The computed joiner secret doesn't match the one in the test vector.",
        WelcomeSecretMismatch = "The computed welcome secret doesn't match the one in the test vector.",
        InitSecretMismatch = "The computed init secret doesn't match the one in the test vector.",
        GroupContextMismatch = "The group context doesn't match the one in the test vector.",
        SenderDataSecretMismatch = "The computed sender data secret doesn't match the one in the test vector.",
        EncryptionSecretMismatch = "The computed encryption secret doesn't match the one in the test vector.",
        ExporterSecretMismatch = "The computed exporter secret doesn't match the one in the test vector.",
        AuthenticationSecretMismatch = "The computed authentication secret doesn't match the one in the test vector.",
        ExternalSecretMismatch = "The computed external secret doesn't match the one in the test vector.",
        ConfirmationKeyMismatch = "The computed confirmation key doesn't match the one in the test vector.",
        MembershipKeyMismatch = "The computed membership key doesn't match the one in the test vector.",
        ResumptionSecretMismatch = "The computed resumption secret doesn't match the one in the test vector.",
        ExternalPubMismatch = "The computed external public key doesn't match the one in the test vector.",
    }
}

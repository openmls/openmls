implement_error! {
    pub enum ErrorState {
        NotInit = "Expected to be in initial state.",
        NotEpoch = "Expected to be in epoch state.",
        NotContext = "Expected to be in a state where the context is added.",
    }
}

implement_error! {
    pub enum KeyScheduleError {
        InvalidState(ErrorState) =
            "The requested operation is not valid on the key schedule state.",
    }
}

implement_error! {
    pub enum PskSecretError {
        TooManyKeys = "More than 2^16 PSKS were provided.",
        DifferentLength = "The IDs and secrets vectors have different lengths.",
    }
}

// TODO: Shouldn't need to allow dead code in here.
#[allow(dead_code)]
#[cfg(any(feature = "expose-test-vectors", test))]
implement_error! {
    pub enum KSTestVectorError {
        JoinerSecretMismatch = "The computed joiner secret doesn't match the one in the test vector.",
        WelcomeSecretMismatch = "The computed welcome secret doesn't match the one in the test vector.",
        InitSecretMismatch = "The computed init secret doesn't match the one in the test vector.",
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

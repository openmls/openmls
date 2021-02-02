implement_error! {
    pub enum ErrorState {
        NotInit = "Expected to be in initial state.",
        NotEpoch = "Expected to be in epoch state.",
        NotContext = "Expected to be in a state where the context is added.",
        NotEpochOrInit = "Expected to be in epoch or init state.",
        NotInitSecret = "Expected to be in the state to derive the init secret.",
        NotEpochSecrets = "Expected to be in the state to derive the epoch secrets.",
        NotDone = "Expected to be in done state.",
    }
}

implement_error! {
    pub enum KeyScheduleError {
        InvalidState(ErrorState) =
            "The requested operation is not valid on the key schedule state.",
    }
}

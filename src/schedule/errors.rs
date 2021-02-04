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

use crate::config::ConfigError;

// There should only be simple codec errors.
// Each module should wrap the `CodecError` for more information.
implement_error! {
    pub enum CodecError {
        EncodingError = "Error encoding.",
        DecodingError = "Error decoding.",
        Other = "Some other error occurred.",
    }
}

impl From<ConfigError> for CodecError {
    // This happens only when decoding a value that's unsupported by the config.
    fn from(_e: ConfigError) -> CodecError {
        CodecError::DecodingError
    }
}

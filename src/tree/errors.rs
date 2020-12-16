use crate::config::ConfigError;

implement_error! {
    pub enum TreeError {
        Simple {
            InvalidArguments = "Invalid arguments.",
            InvalidUpdatePath = "The computed update path is invalid.",
            InvalidTree = "The tree is not valid.",
        }
        Complex {
            ConfigError(ConfigError) =
                "See [`ConfigError`](`crate::config::ConfigError`) for details.",
        }
    }
}

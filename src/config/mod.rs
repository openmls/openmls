//! This config contains all structs, enums and functions to configure MLS.

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{env, fs::File, io::BufReader};

use crate::ciphersuite::{Ciphersuite, CiphersuiteName};
use crate::codec::{Codec, CodecError, Cursor};
use crate::extensions::ExtensionType;

pub mod errors;
pub(crate) use errors::ConfigError;

/// This value is used as the default lifetime of `KeyPackage`s if no default
/// lifetime is configured. The value is in seconds and amounts to 3 * 28 Days,
/// i.e. about 3 months.
const DEFAULT_KEY_PACKAGE_LIFETIME: u64 = 60 * 60 * 24 * 28 * 3; // in Seconds
/// This value is used as the default amount of time (in seconds) the lifetime
/// of a `KeyPackage` is extended into the past to allow for skewed clocks. The
/// value is in seconds and amounts to 1h.
const DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN: u64 = 60 * 60; // in Seconds

lazy_static! {
     static ref CONFIG: Config = {
        if let Ok(path) = env::var("OPENMLS_CONFIG") {
            let file = match File::open(path) {
                Ok(f) => f,
                Err(e) => panic!("Couldn't open file {}.\nPlease set \
                                  OPENMLS_CONFIG to a valid path or unset it to \
                                  use the default configuration.", e),
            };
            let reader = BufReader::new(file);
            let config: PersistentConfig = match serde_json::from_reader(reader) {
                Ok(r) => r,
                Err(e) => panic!("Error reading configuration file.\n{:?}", e),
            };
            config.into()
        } else {
            // Without a config file everything is enabled.
            let constants = Constants {
                default_key_package_lifetime: DEFAULT_KEY_PACKAGE_LIFETIME,
                key_package_lifetime_margin: DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN,
            };
            let config = PersistentConfig {
                protocol_versions: vec![ProtocolVersion::Mls10],
                ciphersuites: vec![
                    Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).unwrap(),
                    Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519).unwrap(),
                    Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256).unwrap()],
                    extensions: vec![ExtensionType::Capabilities, ExtensionType::Lifetime, ExtensionType::KeyID],
                constants,
            };
            config.into()
        }
    };
}

/// Constants that are used throughout the library.
#[derive(Debug, Deserialize)]
struct Constants {
    /// The default lifetime of a key package in seconds.
    default_key_package_lifetime: u64, // in Seconds
    /// The amount of time (in seconds) the lifetime of a `KeyPackage` is
    /// extended into the past to allow for skewed clocks.
    key_package_lifetime_margin: u64, // in Seconds
}

/// The configuration we use for the library (`Config`) is not exactly the same
/// as the one we persist.
#[derive(Debug, Deserialize)]
struct PersistentConfig {
    protocol_versions: Vec<ProtocolVersion>,
    ciphersuites: Vec<Ciphersuite>,
    extensions: Vec<ExtensionType>,
    constants: Constants,
}

/// # OpenMLS Configuration
///
/// This is the global configuration for OpenMLS.
#[derive(Debug)]
pub struct Config {
    protocol_versions: Vec<ProtocolVersion>,
    ciphersuites: Vec<Ciphersuite>,
    extensions: Vec<ExtensionType>,
    constants: Constants,
}

// Convert a config that's being read from a file to the config we use.
impl From<PersistentConfig> for Config {
    fn from(config: PersistentConfig) -> Self {
        Self {
            protocol_versions: config.protocol_versions,
            ciphersuites: config.ciphersuites,
            extensions: config.extensions,
            constants: config.constants,
        }
    }
}

impl Config {
    /// Get a list of the supported extension types.
    pub fn supported_extensions() -> &'static [ExtensionType] {
        &CONFIG.extensions
    }

    /// Get a list of the supported cipher suites.
    pub fn supported_ciphersuites() -> &'static [Ciphersuite] {
        &CONFIG.ciphersuites
    }

    /// Get a list of the supported cipher suites names.
    pub fn supported_ciphersuite_names() -> Vec<CiphersuiteName> {
        CONFIG
            .ciphersuites
            .iter()
            .map(|suite| suite.name())
            .collect()
    }

    /// Get a list of the supported protocol versions.
    pub fn supported_versions() -> &'static [ProtocolVersion] {
        &CONFIG.protocol_versions
    }

    /// Get the ciphersuite of the given name.
    pub fn ciphersuite(ciphersuite: CiphersuiteName) -> Result<&'static Ciphersuite, ConfigError> {
        match CONFIG.ciphersuites.iter().find(|s| s.name() == ciphersuite) {
            Some(c) => Ok(c),
            None => Err(ConfigError::UnsupportedCiphersuite),
        }
    }

    /// Get the default `KeyPackage` lifetime (in seconds).
    pub fn default_key_package_lifetime() -> &'static u64 {
        &CONFIG.constants.default_key_package_lifetime
    }

    /// Get the margin in which `KeyPackage` lifetimes are already considered
    /// valid. (in seconds).
    pub fn key_package_lifetime_margin() -> &'static u64 {
        &CONFIG.constants.key_package_lifetime_margin
    }
}

/// # Protocol Version
///
/// 7. Key Packages
///
/// ```text
/// enum {
///     reserved(0),
///     mls10(1),
///     (255)
/// } ProtocolVersion;
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProtocolVersion {
    Reserved = 0,
    Mls10 = 1,
}

/// There's only one version right now, which is the default.
impl Default for ProtocolVersion {
    fn default() -> Self {
        ProtocolVersion::Mls10
    }
}

impl Codec for ProtocolVersion {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(Self::from(u8::decode(cursor)?)?)
    }
}

impl ProtocolVersion {
    /// Convert an integer to the corresponding protocol version.
    ///
    /// Returns an error if the protocol version is not supported.
    pub fn from(v: u8) -> Result<ProtocolVersion, ConfigError> {
        match v {
            1 => Ok(ProtocolVersion::Mls10),
            _ => Err(ConfigError::UnsupportedMlsVersion),
        }
    }
}

impl CiphersuiteName {
    /// Returns `true` if the ciphersuite is supported in the current
    /// configuration.
    pub(crate) fn is_supported(&self) -> bool {
        for suite in CONFIG.ciphersuites.iter() {
            if self == &suite.name() {
                return true;
            }
        }
        false
    }
}

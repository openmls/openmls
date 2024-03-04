use std::sync::RwLock;

use libcrux::drbg::Drbg;
use openmls_traits::random::OpenMlsRand;

/// The libcrux-backed randomness provider for OpenMLS
pub struct RandProvider {
    drbg: RwLock<Drbg>,
}

/// An error occurred when trying to generate a random value
#[derive(Clone, Debug, PartialEq)]
pub enum RandError {
    /// Invalid input.
    InvalidInput,
    /// The requested digest is not supported.
    UnsupportedAlgorithm,
    /// Unable to generate the requested randomness.
    UnableToGenerate,
}

impl std::fmt::Display for RandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RandError::InvalidInput => write!(f, "Invalid input."),
            RandError::UnsupportedAlgorithm => write!(f, "Unsupported algorithm."),
            RandError::UnableToGenerate => write!(f, "Unable to generate."),
        }
    }
}

impl From<libcrux::drbg::Error> for RandError {
    fn from(value: libcrux::drbg::Error) -> Self {
        match value {
            libcrux::drbg::Error::InvalidInput => RandError::InvalidInput,
            libcrux::drbg::Error::UnsupportedAlgorithm => RandError::UnsupportedAlgorithm,
            libcrux::drbg::Error::UnableToGenerate => RandError::UnableToGenerate,
        }
    }
}

impl std::error::Error for RandError {}

impl OpenMlsRand for RandProvider {
    type Error = RandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        self.drbg
            .write()
            .unwrap()
            .generate_array()
            .map_err(<RandError as From<libcrux::drbg::Error>>::from)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.drbg
            .write()
            .unwrap()
            .generate_vec(len)
            .map_err(<RandError as From<libcrux::drbg::Error>>::from)
    }
}

impl Default for RandProvider {
    fn default() -> Self {
        let mut seed = [0u8; 256];
        getrandom::getrandom(&mut seed).unwrap();
        Self {
            drbg: RwLock::new(
                Drbg::new_with_entropy(libcrux::digest::Algorithm::Sha256, &seed).unwrap(),
            ),
        }
    }
}

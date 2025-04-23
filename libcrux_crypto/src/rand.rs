use openmls_traits::random::OpenMlsRand;

use rand::TryRngCore;

use crate::CryptoProvider;

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
impl std::error::Error for RandError {}

impl OpenMlsRand for CryptoProvider {
    type Error = RandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut rng = self.rng.lock().map_err(|_| RandError::UnableToGenerate)?;

        let mut output = [0u8; N];

        rng.try_fill_bytes(&mut output)
            .map_err(|_| RandError::UnableToGenerate)?;

        Ok(output)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut rng = self.rng.lock().map_err(|_| RandError::UnableToGenerate)?;

        let mut output = vec![0u8; len];

        rng.try_fill_bytes(&mut output)
            .map_err(|_| RandError::UnableToGenerate)?;

        Ok(output)
    }
}

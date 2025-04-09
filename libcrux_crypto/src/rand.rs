use std::sync::RwLock;

use openmls_traits::random::OpenMlsRand;

use rand::{rngs::OsRng, rngs::ReseedingRng, RngCore};
use rand_chacha::ChaCha20Core;

/// The libcrux-backed randomness provider for OpenMLS
pub struct RandProvider {
    rng: RwLock<ReseedingRng<ChaCha20Core, OsRng>>,
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
impl std::error::Error for RandError {}

impl OpenMlsRand for RandProvider {
    type Error = RandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut rng = self.rng.write().unwrap();

        let mut output = [0u8; N];
        // TODO: evaluate whether try_fill_bytes() should be used here
        rng.fill_bytes(&mut output);

        Ok(output)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut rng = self.rng.write().unwrap();

        let mut output = vec![0u8; len];
        // TODO: evaluate whether try_fill_bytes() should be used here
        rng.fill_bytes(&mut output);

        Ok(output)
    }
}

impl Default for RandProvider {
    fn default() -> Self {
        let reseeding_rng = ReseedingRng::<ChaCha20Core, _>::new(0x100000000, OsRng).unwrap();
        Self {
            rng: RwLock::new(reseeding_rng),
        }
    }
}

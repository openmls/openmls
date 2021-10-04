use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Initialize the rng with entropy.
///
/// Note that we use this to reseed as there's no way to reseed right now.
/// We should re-implement this or better delegate it to the crypto provider.
pub(crate) fn init() -> ChaCha20Rng {
    ChaCha20Rng::from_entropy()
}

/// Generate a random array.
/// *PANICS* if randomness generation fails.
pub(crate) fn random_array<const N: usize>(rng: &mut ChaCha20Rng) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}

/// Generate a random byte vector of length `len`.
/// *PANICS* if randomness generation fails.
pub(crate) fn random_vec(rng: &mut ChaCha20Rng, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}

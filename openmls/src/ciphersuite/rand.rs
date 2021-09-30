use openmls_traits::random::OpenMlsRand;

/// Generate a random array.
/// *PANICS* if randomness generation fails.
pub(crate) fn random_array<const N: usize>(rng: &mut impl OpenMlsRand) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}

/// Generate a random byte vector of length `len`.
/// *PANICS* if randomness generation fails.
pub(crate) fn random_vec(rng: &mut impl OpenMlsRand, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}

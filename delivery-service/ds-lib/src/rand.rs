use openmls_traits::random::OpenMlsRand;
use rand_chacha::rand_core::{self, CryptoRng, RngCore, SeedableRng};

pub struct DsRand {
    rng: rand_chacha::ChaCha20Rng,
}
impl OpenMlsRand for DsRand {}
impl RngCore for DsRand {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.rng.try_fill_bytes(dest)
    }
}
impl CryptoRng for DsRand {}
impl DsRand {
    pub fn new() -> Self {
        Self {
            rng: rand_chacha::ChaCha20Rng::from_entropy(),
        }
    }
}

use std::convert::Infallible;

pub(crate) struct RandCore0_10<R>(pub(crate) R);

impl<R> rand_core_0_10::TryCryptoRng for RandCore0_10<R> where
    R: rand_core::RngCore + rand_core::CryptoRng
{
}

impl<R> rand_core_0_10::TryRng for RandCore0_10<R>
where
    R: rand_core::RngCore,
{
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

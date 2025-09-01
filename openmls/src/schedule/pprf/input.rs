use std::borrow::Cow;

pub trait AsIndexBytes {
    fn as_index_bytes(&self) -> Cow<'_, [u8]>;
}

// Byte-based inputs
impl AsIndexBytes for &[u8] {
    fn as_index_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(*self)
    }
}
impl AsIndexBytes for Vec<u8> {
    fn as_index_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_slice())
    }
}
impl<const N: usize> AsIndexBytes for [u8; N] {
    fn as_index_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_slice())
    }
}

// Integer inputs
impl AsIndexBytes for u16 {
    fn as_index_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_be_bytes().to_vec())
    }
}
impl AsIndexBytes for u32 {
    fn as_index_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_be_bytes().to_vec())
    }
}
impl AsIndexBytes for u64 {
    fn as_index_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_be_bytes().to_vec())
    }
}
impl AsIndexBytes for u128 {
    fn as_index_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_be_bytes().to_vec())
    }
}

// === The folowing functions aren't necessarily cryptographically secure!

#[cfg(any(feature = "test-utils", test))]
use rand::{rngs::OsRng, RngCore};

#[cfg(any(feature = "test-utils", test))]
pub fn random_u32() -> u32 {
    OsRng.next_u32()
}

#[cfg(any(feature = "test-utils", test))]
pub fn random_u64() -> u64 {
    OsRng.next_u64()
}

#[cfg(any(feature = "test-utils", test))]
pub fn random_u8() -> u8 {
    let mut b = [0u8; 1];
    OsRng.fill_bytes(&mut b);
    b[0]
}

// With the crypto-debug feature enabled sensitive crypto parts can be logged.
#[cfg(feature = "crypto-debug")]
macro_rules! log_crypto {
    (debug, $($arg:tt)*) => ({
        log::debug!($($arg)*);
    });
    (trace, $($arg:tt)*) => ({
        log::trace!($($arg)*);
    })
}

// With the content-debug feature enabled sensitive message content parts can be logged.
#[cfg(feature = "content-debug")]
macro_rules! log_content {
    (debug, $($arg:tt)*) => ({
        log::debug!($($arg)*);
    });
    (trace, $($arg:tt)*) => ({
        log::trace!($($arg)*);
    })
}

#[cfg(not(feature = "crypto-debug"))]
macro_rules! log_crypto {
    (debug, $($arg:tt)*) => {{}};
    (trace, $($arg:tt)*) => {{}};
}

#[cfg(not(feature = "content-debug"))]
macro_rules! log_content {
    (debug, $($arg:tt)*) => {{}};
    (trace, $($arg:tt)*) => {{}};
}

/// Helper mod that converts a objects that implement FromIterator<_,_> (like a
/// HashMap or a BTreeMap) into a vector of tuples and vice versa.
pub mod vector_converter {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<'a, T, K, V, S>(target: T, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: IntoIterator<Item = (&'a K, &'a V)>,
        K: Serialize + 'a,
        V: Serialize + 'a,
    {
        let container: Vec<_> = target.into_iter().collect();
        serde::Serialize::serialize(&container, ser)
    }

    pub fn deserialize<'de, T, K, V, D>(des: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromIterator<(K, V)>,
        K: Deserialize<'de>,
        V: Deserialize<'de>,
    {
        let container: Vec<_> = serde::Deserialize::deserialize(des)?;
        Ok(T::from_iter(container))
    }
}

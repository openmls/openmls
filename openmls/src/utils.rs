// === The folowing functions aren't necessarily cryptographically secure!

#[cfg(any(feature = "test-utils", test))]
use rand::{rngs::OsRng, RngCore, TryRngCore};

#[cfg(any(feature = "test-utils", test))]
pub fn random_u32() -> u32 {
    OsRng.unwrap_mut().next_u32()
}

#[cfg(any(feature = "test-utils", test))]
pub fn random_u64() -> u64 {
    OsRng.unwrap_mut().next_u64()
}

#[cfg(any(feature = "test-utils", test))]
pub fn random_u8() -> u8 {
    let mut b = [0u8; 1];
    OsRng.unwrap_mut().fill_bytes(&mut b);
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

/// Serde helper for serializing a `usize` field as a fixed-width `u64`.
///
/// `usize` is 32 bits on `wasm32` and 64 bits on most host targets. The
/// derived `Serialize`/`Deserialize` for `usize` writes a platform-native
/// width, which makes persisted bytes non-portable across builds.
///
/// Fields that participate in the storage format should opt into this helper
/// via `#[serde(with = "crate::utils::usize_as_u64")]` so the wire shape is
/// always 8 bytes for non-self-describing formats and an unambiguous JSON
/// number for self-describing formats.
pub(crate) mod usize_as_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &usize, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(*value as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<usize, D::Error> {
        let value = u64::deserialize(deserializer)?;
        usize::try_from(value).map_err(serde::de::Error::custom)
    }
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

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

/// Test-only `serde::Serializer` that captures the `(variant_index, variant)`
/// arguments of a `serialize_*_variant` call and returns them as the serializer
/// `Ok` value. Used by per-enum tests to pin the bincode/postcard wire
/// indices of persisted enums (`CredentialType`, `ExtensionType`, `Extension`,
/// `ProposalType`, `Proposal`).
///
/// Every other `Serializer` method returns an error: the probe is intentionally
/// minimal and is only meant to be driven against enum variants. Payloads of
/// newtype / tuple variants are accepted but never recursed into, so payload
/// types do not need to be cheaply constructible for the probe to work.
#[cfg(test)]
pub(crate) mod variant_index_probe {
    use core::fmt;
    use serde::ser::{Impossible, SerializeTupleVariant};
    use serde::{ser, Serialize, Serializer};

    pub(crate) type Captured = (u32, &'static str);

    /// Serialize `value` through the probe and return the
    /// `(variant_index, variant_name)` of the variant call it issued.
    pub(crate) fn probe<T: Serialize>(value: &T) -> Result<Captured, ProbeError> {
        value.serialize(IndexProbe)
    }

    #[derive(Debug)]
    pub(crate) struct ProbeError(pub(crate) String);

    impl fmt::Display for ProbeError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for ProbeError {}

    impl ser::Error for ProbeError {
        fn custom<T: fmt::Display>(msg: T) -> Self {
            ProbeError(msg.to_string())
        }
    }

    pub(crate) struct IndexProbe;

    fn reject<T>(method: &'static str) -> Result<T, ProbeError> {
        Err(ProbeError(format!(
            "IndexProbe::{method} unexpectedly called"
        )))
    }

    impl Serializer for IndexProbe {
        type Ok = Captured;
        type Error = ProbeError;
        type SerializeSeq = Impossible<Captured, ProbeError>;
        type SerializeTuple = Impossible<Captured, ProbeError>;
        type SerializeTupleStruct = Impossible<Captured, ProbeError>;
        type SerializeTupleVariant = TupleVariantCapture;
        type SerializeMap = Impossible<Captured, ProbeError>;
        type SerializeStruct = Impossible<Captured, ProbeError>;
        type SerializeStructVariant = Impossible<Captured, ProbeError>;

        fn serialize_unit_variant(
            self,
            _name: &'static str,
            variant_index: u32,
            variant: &'static str,
        ) -> Result<Self::Ok, Self::Error> {
            Ok((variant_index, variant))
        }

        fn serialize_newtype_variant<T: ?Sized + Serialize>(
            self,
            _name: &'static str,
            variant_index: u32,
            variant: &'static str,
            _value: &T,
        ) -> Result<Self::Ok, Self::Error> {
            Ok((variant_index, variant))
        }

        fn serialize_tuple_variant(
            self,
            _name: &'static str,
            variant_index: u32,
            variant: &'static str,
            _len: usize,
        ) -> Result<Self::SerializeTupleVariant, Self::Error> {
            Ok(TupleVariantCapture {
                captured: (variant_index, variant),
            })
        }

        // Every other Serializer method is unexpected for the probe's use
        // case (variant-index assertion on `serde`-derived enum
        // serialization). Stub them out with an error so a misuse fails the
        // test loudly rather than silently producing a bogus result.
        fn serialize_bool(self, _v: bool) -> Result<Self::Ok, Self::Error> {
            reject("serialize_bool")
        }
        fn serialize_i8(self, _v: i8) -> Result<Self::Ok, Self::Error> {
            reject("serialize_i8")
        }
        fn serialize_i16(self, _v: i16) -> Result<Self::Ok, Self::Error> {
            reject("serialize_i16")
        }
        fn serialize_i32(self, _v: i32) -> Result<Self::Ok, Self::Error> {
            reject("serialize_i32")
        }
        fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
            reject("serialize_i64")
        }
        fn serialize_u8(self, _v: u8) -> Result<Self::Ok, Self::Error> {
            reject("serialize_u8")
        }
        fn serialize_u16(self, _v: u16) -> Result<Self::Ok, Self::Error> {
            reject("serialize_u16")
        }
        fn serialize_u32(self, _v: u32) -> Result<Self::Ok, Self::Error> {
            reject("serialize_u32")
        }
        fn serialize_u64(self, _v: u64) -> Result<Self::Ok, Self::Error> {
            reject("serialize_u64")
        }
        fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
            reject("serialize_f32")
        }
        fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
            reject("serialize_f64")
        }
        fn serialize_char(self, _v: char) -> Result<Self::Ok, Self::Error> {
            reject("serialize_char")
        }
        fn serialize_str(self, _v: &str) -> Result<Self::Ok, Self::Error> {
            reject("serialize_str")
        }
        fn serialize_bytes(self, _v: &[u8]) -> Result<Self::Ok, Self::Error> {
            reject("serialize_bytes")
        }
        fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
            reject("serialize_none")
        }
        fn serialize_some<T: ?Sized + Serialize>(
            self,
            _value: &T,
        ) -> Result<Self::Ok, Self::Error> {
            reject("serialize_some")
        }
        fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
            reject("serialize_unit")
        }
        fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
            reject("serialize_unit_struct")
        }
        fn serialize_newtype_struct<T: ?Sized + Serialize>(
            self,
            _name: &'static str,
            _value: &T,
        ) -> Result<Self::Ok, Self::Error> {
            reject("serialize_newtype_struct")
        }
        fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
            reject("serialize_seq")
        }
        fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
            reject("serialize_tuple")
        }
        fn serialize_tuple_struct(
            self,
            _name: &'static str,
            _len: usize,
        ) -> Result<Self::SerializeTupleStruct, Self::Error> {
            reject("serialize_tuple_struct")
        }
        fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
            reject("serialize_map")
        }
        fn serialize_struct(
            self,
            _name: &'static str,
            _len: usize,
        ) -> Result<Self::SerializeStruct, Self::Error> {
            reject("serialize_struct")
        }
        fn serialize_struct_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
            _len: usize,
        ) -> Result<Self::SerializeStructVariant, Self::Error> {
            reject("serialize_struct_variant")
        }
    }

    pub(crate) struct TupleVariantCapture {
        captured: Captured,
    }

    impl SerializeTupleVariant for TupleVariantCapture {
        type Ok = Captured;
        type Error = ProbeError;

        fn serialize_field<T: ?Sized + Serialize>(
            &mut self,
            _value: &T,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            Ok(self.captured)
        }
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

//! A vector with a length field for TLS serialisation.
//! Use this for any vector that is serialised.

use serde::ser::SerializeStruct;
use std::convert::TryInto;

use crate::{Cursor, Deserialize, Error, Serialize};

macro_rules! impl_tls_vec {
    ($size:ty, $name:ident) => {
        #[derive(PartialEq, Clone, Debug)]
        pub struct $name<T: Serialize + Deserialize + Clone + PartialEq> {
            vec: Vec<T>,
        }

        impl<T: Serialize + Deserialize + Clone + PartialEq> $name<T> {
            /// Create a new `TlsVec` from a Rust Vec.
            pub fn new(vec: Vec<T>) -> Self {
                Self { vec }
            }

            /// Create a new `TlsVec` from a slice.
            pub fn from_slice(slice: &[T]) -> Self {
                Self {
                    vec: slice.to_vec(),
                }
            }

            /// Get a slice to the raw vector.
            pub fn as_slice(&self) -> &[T] {
                &self.vec
            }

            /// Get a copy of the underlying vector.
            pub fn to_vec(&self) -> Vec<T> {
                self.vec.clone()
            }

            /// Add an element to this.
            pub fn push(&mut self, value: T) {
                self.vec.push(value);
            }

            /// Remove the last element.
            pub fn pop(&mut self) -> Option<T> {
                self.vec.pop()
            }
        }

        impl<T: Serialize + Deserialize + Clone + PartialEq> From<Vec<T>> for $name<T> {
            fn from(v: Vec<T>) -> Self {
                Self::new(v)
            }
        }

        impl<T: Serialize + Deserialize + Clone + PartialEq> From<&[T]> for $name<T> {
            fn from(v: &[T]) -> Self {
                Self::from_slice(v)
            }
        }

        impl<T: Serialize + Deserialize + Clone + PartialEq> Into<Vec<T>> for $name<T> {
            fn into(self) -> Vec<T> {
                self.vec
            }
        }

        impl<T: Serialize + Deserialize + Clone + PartialEq> Default for $name<T> {
            fn default() -> Self {
                Self { vec: Vec::new() }
            }
        }

        impl<T> serde::Serialize for $name<T>
        where
            T: Serialize + Deserialize + Clone + PartialEq + serde::Serialize,
        {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let mut state = serializer.serialize_struct(stringify!($name), 1)?;
                state.serialize_field("vec", &self.vec)?;
                state.end()
            }
        }

        impl<'de, T> serde::de::Deserialize<'de> for $name<T>
        where
            T: Serialize + Deserialize + Clone + PartialEq + serde::de::Deserialize<'de>,
        {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                enum Field {
                    Vec,
                }

                impl<'de> serde::de::Deserialize<'de> for Field {
                    fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
                    where
                        D: serde::de::Deserializer<'de>,
                    {
                        struct FieldVisitor;

                        impl<'de> serde::de::Visitor<'de> for FieldVisitor {
                            type Value = Field;

                            fn expecting(
                                &self,
                                formatter: &mut std::fmt::Formatter,
                            ) -> std::fmt::Result {
                                formatter.write_str("`vec`")
                            }

                            fn visit_str<E>(self, value: &str) -> Result<Field, E>
                            where
                                E: serde::de::Error,
                            {
                                match value {
                                    "vec" => Ok(Field::Vec),
                                    _ => Err(serde::de::Error::unknown_field(value, &["vec"])),
                                }
                            }
                        }

                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }

                struct TlsVecVisitor<T> {
                    data: std::marker::PhantomData<T>,
                }

                impl<'de, T> serde::de::Visitor<'de> for TlsVecVisitor<T>
                where
                    T: Serialize + Deserialize + Clone + PartialEq + serde::de::Deserialize<'de>,
                {
                    type Value = $name<T>;
                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_fmt(format_args!("struct {}<T>", stringify!($name)))
                    }
                    fn visit_seq<V>(self, mut seq: V) -> Result<$name<T>, V::Error>
                    where
                        V: serde::de::SeqAccess<'de>,
                    {
                        let vec = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                        Ok($name::<T>::new(vec))
                    }
                    fn visit_map<V>(self, mut map: V) -> Result<$name<T>, V::Error>
                    where
                        V: serde::de::MapAccess<'de>,
                    {
                        let mut vec = None;
                        while let Some(key) = map.next_key()? {
                            match key {
                                Field::Vec => {
                                    if vec.is_some() {
                                        return Err(serde::de::Error::duplicate_field("vec"));
                                    }
                                    vec = Some(map.next_value()?);
                                }
                            }
                        }
                        let vec = vec.ok_or_else(|| serde::de::Error::missing_field("vec"))?;
                        Ok($name::<T>::new(vec))
                    }
                }
                deserializer.deserialize_struct(
                    stringify!($name),
                    &["vec"],
                    TlsVecVisitor {
                        data: std::marker::PhantomData,
                    },
                )
            }
        }

        impl<T: Serialize + Deserialize + Clone + PartialEq> Serialize for $name<T> {
            fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
                let len = self.vec.len();
                if len > (<$size>::MAX as usize) {
                    return Err(Error::InvalidVectorLength);
                }
                (self.vec.len() as $size).tls_serialize(buffer)?;
                for e in self.vec.iter() {
                    e.tls_serialize(buffer)?;
                }
                Ok(())
            }
        }

        impl<T: Serialize + Deserialize + Clone + PartialEq> Deserialize for $name<T> {
            fn tls_deserialize(cursor: &Cursor) -> Result<Self, Error> {
                let mut result = Self { vec: Vec::new() };
                let len = <$size>::tls_deserialize(cursor)?;
                let sub_cursor = cursor.sub_cursor(len.try_into()?)?;
                while sub_cursor.has_more() {
                    result.push(T::tls_deserialize(&sub_cursor)?);
                }
                Ok(result)
            }
        }
    };
}

impl_tls_vec!(u8, TlsVecU8);
impl_tls_vec!(u16, TlsVecU16);
impl_tls_vec!(u32, TlsVecU32);
impl_tls_vec!(u64, TlsVecU64);

impl From<std::num::TryFromIntError> for Error {
    fn from(_e: std::num::TryFromIntError) -> Self {
        Self::InvalidVectorLength
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(_e: std::convert::Infallible) -> Self {
        Self::InvalidVectorLength
    }
}

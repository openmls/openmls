//! This module exports the [`StorageTags`] struct, which can be used to retrieve the storage tags
//! used for non-self-describing and self-describing [`serde`] serializations of enum variants.

use serde::ser::{Error, Impossible, Serialize};

#[derive(PartialEq, Debug)]
/// The [`serde`] storage tags for an enum variant.
pub struct StorageTags {
    pub self_describing: &'static str,
    pub non_self_describing: u32,
}

/// A serializer that retrieves the [`serde`] storage tags
/// for an enum variant.
struct TagSerializer {
    tags: Option<StorageTags>,
}

/// An error when retrieving the [`serde`] storage tags for an enum variant.
#[derive(Debug, thiserror::Error)]
#[error("an error when retrieving the storage tags")]
pub struct StorageTagError(String);

impl serde::ser::Error for StorageTagError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        StorageTagError(msg.to_string())
    }
}

macro_rules! noop {
    ($($m:ident($($t:ty),*)),* $(,)?) => {
        $(fn $m(self $(, _: $t)*) -> Result<Self::Ok, Self::Error> { Ok(()) })*
    };
}

impl TagSerializer {
    fn update_tags(&mut self, storage_tags: StorageTags) -> Result<(), StorageTagError> {
        if self.tags.is_some() {
            return Err(Error::custom("storage tags were already retrieved"));
        }

        let _ = self.tags.insert(storage_tags);

        Ok(())
    }
}

impl serde::ser::Serializer for &mut TagSerializer {
    type Ok = ();
    type Error = StorageTagError;
    type SerializeSeq = Impossible<(), StorageTagError>;
    type SerializeTuple = Impossible<(), StorageTagError>;
    type SerializeTupleStruct = Impossible<(), StorageTagError>;
    type SerializeTupleVariant = Self;
    type SerializeMap = Impossible<(), StorageTagError>;
    type SerializeStruct = Impossible<(), StorageTagError>;
    type SerializeStructVariant = Self;

    noop!(
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_char(char),
        serialize_str(&str),
        serialize_bytes(&[u8]),
        serialize_none(),
        serialize_unit(),
        serialize_unit_struct(&'static str),
    );

    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<(), StorageTagError> {
        Ok(())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<(), StorageTagError> {
        Ok(())
    }

    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, StorageTagError> {
        Err(StorageTagError("seq".into()))
    }
    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, StorageTagError> {
        Err(StorageTagError("tuple".into()))
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, StorageTagError> {
        Err(StorageTagError("ts".into()))
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, StorageTagError> {
        Err(StorageTagError("map".into()))
    }
    fn serialize_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStruct, StorageTagError> {
        Err(StorageTagError("struct".into()))
    }

    fn serialize_unit_variant(
        self,
        _: &'static str,
        i: u32,
        v: &'static str,
    ) -> Result<(), Self::Error> {
        self.update_tags(StorageTags {
            non_self_describing: i,
            self_describing: v,
        })
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        i: u32,
        v: &'static str,
        _: &T,
    ) -> Result<(), Self::Error> {
        self.update_tags(StorageTags {
            non_self_describing: i,
            self_describing: v,
        })
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        i: u32,
        v: &'static str,
        _: usize,
    ) -> Result<Self, Self::Error> {
        self.update_tags(StorageTags {
            non_self_describing: i,
            self_describing: v,
        })?;
        Ok(self)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        i: u32,
        v: &'static str,
        _: usize,
    ) -> Result<Self, Self::Error> {
        self.update_tags(StorageTags {
            non_self_describing: i,
            self_describing: v,
        })?;
        Ok(self)
    }
}

impl serde::ser::SerializeTupleVariant for &mut TagSerializer {
    type Ok = ();
    type Error = StorageTagError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, _: &T) -> Result<(), Self::Error> {
        Ok(())
    }
    fn end(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl serde::ser::SerializeStructVariant for &mut TagSerializer {
    type Ok = ();
    type Error = StorageTagError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _: &'static str,
        _: &T,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
    fn end(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl StorageTags {
    /// Returns the [`StorageTags`] for a provided struct.
    ///
    /// This method returns `Some(StorageTags {..})` if the provided
    /// struct is an enum variant.
    pub fn for_enum_variant<T: Serialize>(value: &T) -> Result<Self, StorageTagError> {
        let mut c = TagSerializer { tags: None };
        value.serialize(&mut c)?;
        c.tags
            .ok_or(StorageTagError::custom("no storage tag could be retrieved"))
    }
}

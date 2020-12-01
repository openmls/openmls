use crate::ciphersuite::*;

use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};
use std::fmt;

impl Serialize for Ciphersuite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        //serializer.serialize_enum(self.name)
        let mut state = serializer.serialize_struct("Ciphersuite", 1)?;
        state.serialize_field("name", &self.name)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Ciphersuite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Name,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`name`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "name" => Ok(Field::Name),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct CiphersuiteVisitor;

        impl<'de> Visitor<'de> for CiphersuiteVisitor {
            type Value = Ciphersuite;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Ciphersuite")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Ciphersuite, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let name = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                match Ciphersuite::new(name) {
                    Ok(c) => Ok(c),
                    Err(_) => Err(de::Error::custom("Unsupported ciphersuite")),
                }
            }

            fn visit_map<V>(self, mut map: V) -> Result<Ciphersuite, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut name = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Name => {
                            if name.is_some() {
                                return Err(de::Error::duplicate_field("name"));
                            }
                            name = Some(map.next_value()?);
                        }
                    }
                }
                let name = name.ok_or_else(|| de::Error::missing_field("name"))?;
                match Ciphersuite::new(name) {
                    Ok(c) => Ok(c),
                    Err(_) => Err(de::Error::custom("Unsupported ciphersuite")),
                }
            }
        }

        const FIELDS: &[&str] = &["name"];
        deserializer.deserialize_struct("Duration", FIELDS, CiphersuiteVisitor)
    }
}

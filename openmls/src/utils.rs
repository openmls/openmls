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

pub(crate) fn zero(length: usize) -> Vec<u8> {
    vec![0u8; length]
}

fn _bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::new();
    for b in bytes {
        hex += &format!("{:02X}", *b);
    }
    hex
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

// Pretty ugly helper to count the number of arguments.
macro_rules! count {
    () => (0usize);
    ( $x:tt $($xs:tt)* ) => (1usize + count!($($xs)*));
}

/// The struct must contain a field `ciphersuite: Ciphersuite`, which
/// is not added to the macro invocation.

macro_rules! implement_persistence {
    ($name:ident, $( $fields:ident ),*) => {
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                const NUM_FIELDS: usize = count!($($fields)*) + 1;
                static FIELDS: [&'static str; NUM_FIELDS] = [
                $(
                    stringify!($fields),
                )*
                    "ciphersuite",
                ];

                #[derive(Deserialize)]
                #[serde(field_identifier, rename_all = "lowercase")]
                #[allow(non_camel_case_types)]
                enum Field {
                    $(
                        $fields,
                    )*
                    ciphersuite,
                }

                struct MyVisitor;

                impl<'de> Visitor<'de> for MyVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str(&format!("struct {}", stringify!($name)))
                    }

                    fn visit_seq<V>(self, mut seq: V) -> Result<$name, V::Error>
                    where
                        V: SeqAccess<'de>,
                    {
                        let mut ctr = 0usize;
                        $(
                            let $fields = seq
                                .next_element()?
                                .ok_or_else(|| de::Error::invalid_length(ctr, &self))?;
                            ctr += 1;
                        )*
                        let ciphersuite = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(ctr, &self))?;
                        Ok($name {
                            ciphersuite: match Config::ciphersuite(ciphersuite) {
                                Ok(c) => c,
                                Err(_) => return Err(de::Error::custom("Unsupported ciphersuite")),
                            },
                            $(
                                $fields,
                            )*
                        })
                    }

                    fn visit_map<V>(self, mut map: V) -> Result<$name, V::Error>
                    where
                        V: MapAccess<'de>,
                    {
                        $(
                            let mut $fields = None;
                        )*
                        let mut ciphersuite = None;
                        while let Some(key) = map.next_key()? {
                            match key {
                                Field::ciphersuite => {
                                    if ciphersuite.is_some() {
                                        return Err(de::Error::duplicate_field("ciphersuite"));
                                    }
                                    ciphersuite = Some(map.next_value()?);
                                }
                                $(
                                    Field::$fields => {
                                        if $fields.is_some() {
                                            return Err(de::Error::duplicate_field(stringify!($fields)));
                                        }
                                        $fields = Some(map.next_value()?);
                                    }
                                )*
                            }
                        }
                        let ciphersuite =
                            ciphersuite.ok_or_else(|| de::Error::missing_field("ciphersuite"))?;
                        $(
                            let $fields = $fields.ok_or_else(|| de::Error::missing_field(stringify!($fields)))?;
                        )*
                        Ok($name {
                            ciphersuite: match Config::ciphersuite(ciphersuite) {
                                Ok(c) => c,
                                Err(_) => return Err(de::Error::custom("Unsupported ciphersuite")),
                            },
                            $(
                                $fields,
                            )*
                        })
                    }
                }
                deserializer.deserialize_struct(
                        stringify!($name),
                        &FIELDS,
                        MyVisitor,
                )
            }
        }

        impl Serialize for $name {
            #[allow(clippy::vec_init_then_push)]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut fields = Vec::new();
                $(
                    fields.push(stringify!($fields));
                )*
                let mut state = serializer.serialize_struct(stringify!($name), fields.len()+1)?;
                $(
                    state.serialize_field(stringify!($fields), &self.$fields)?;
                )*
                state.serialize_field("ciphersuite", &self.ciphersuite)?;
                state.end()
            }
        }
    };
}

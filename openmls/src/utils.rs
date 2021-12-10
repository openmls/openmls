use crate::treesync::node::Node;
use crate::treesync::TreeSync;

// === The folowing functions aren't necessarily cryptographically secure!

#[cfg(any(feature = "test-utils", test))]
use rand::{rngs::OsRng, RngCore};

#[cfg(any(feature = "test-utils", test))]
pub(crate) fn random_u32() -> u32 {
    OsRng.next_u32()
}

#[cfg(any(feature = "test-utils", test))]
pub(crate) fn random_u64() -> u64 {
    OsRng.next_u64()
}

#[cfg(any(feature = "test-utils", test))]
pub(crate) fn random_u8() -> u8 {
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

/// The struct must contain a field `ciphersuite: &'static Ciphersuite`, which
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
                state.serialize_field("ciphersuite", &self.ciphersuite.name())?;
                state.end()
            }
        }
    };
}

// Implement std::fmt::Display for a given enum type.
macro_rules! implement_enum_display {
    ($error:ty) => {
        impl std::fmt::Display for $error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_fmt(format_args!("{:?}", self))
            }
        }
    };
}

fn log2(x: u32) -> usize {
    if x == 0 {
        return 0;
    }
    let mut k = 0;
    while (x >> k) > 0 {
        k += 1
    }
    k - 1
}

fn level(index: u32) -> usize {
    let x = index;
    if (x & 0x01) == 0 {
        return 0;
    }
    let mut k = 0;
    while ((x >> k) & 0x01) == 1 {
        k += 1;
    }
    k
}

fn root(size: u32) -> u32 {
    (1 << log2(size)) - 1
}

pub fn _print_tree(tree: &TreeSync, message: &str) {
    let factor = 3;
    println!("{}", message);
    let nodes = tree.export_nodes();
    let tree_size = nodes.len() as u32;
    for (i, node) in nodes.iter().enumerate() {
        let level = level(i as u32);
        print!("{:04}", i);
        if let Some(node) = node {
            let (key_bytes, parent_hash_bytes) = match node {
                Node::LeafNode(leaf_node) => {
                    print!("\tL");
                    let key_bytes = leaf_node.public_key().as_slice();
                    let parent_hash_bytes = node.parent_hash().unwrap();
                    (key_bytes, parent_hash_bytes.unwrap_or_default())
                }
                Node::ParentNode(parent_node) => {
                    if root(tree_size) == i as u32 {
                        print!("\tP(R)");
                    } else {
                        print!("\tP");
                    }
                    let key_bytes = parent_node.public_key().as_slice();
                    let parent_hash_bytes = node.parent_hash().unwrap();
                    (key_bytes, parent_hash_bytes.unwrap_or_default())
                }
            };
            print!("\tPK: {}", _bytes_to_hex(key_bytes));

            print!("\tPH: {}", _bytes_to_hex(parent_hash_bytes));
            print!("\t| ");
            for _ in 0..level * factor {
                print!(" ");
            }
            print!("◼︎");
        } else {
            if root(tree_size) == i as u32 {
                print!("\tB(R)\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t| ");
            } else {
                print!("\tB\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t| ");
            }
            for _ in 0..level * factor {
                print!(" ");
            }
            print!("❑");
        }
        println!();
    }
}

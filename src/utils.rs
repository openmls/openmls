use crate::extensions::*;
use crate::tree::{index::*, node::*, *};
use evercrypt::prelude::*;

use rand::rngs::OsRng;
use rand::RngCore;

pub(crate) fn randombytes(n: usize) -> Vec<u8> {
    get_random_vec(n)
}

pub(crate) fn random_u32() -> u32 {
    OsRng.next_u32()
}

#[cfg(test)]
pub(crate) fn random_u8() -> u8 {
    get_random_vec(1)[0]
}

#[inline]
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

pub fn _print_tree(tree: &RatchetTree, message: &str) {
    let factor = 3;
    println!("{}", message);
    for (i, node) in tree.nodes.iter().enumerate() {
        let level = treemath::level(NodeIndex::from(i));
        print!("{:04}", i);
        if !node.is_blank() {
            let (key_bytes, parent_hash_bytes) = match node.node_type {
                NodeType::Leaf => {
                    print!("\tL");
                    let key_bytes = if let Some(kp) = &node.key_package {
                        kp.hpke_init_key().as_slice()
                    } else {
                        &[]
                    };
                    let parent_hash_bytes = if let Some(kp) = &node.key_package {
                        if let Some(phe) = kp.extension_with_type(ExtensionType::ParentHash) {
                            let parent_hash_extension: &ParentHashExtension = phe
                                .as_any()
                                .downcast_ref::<ParentHashExtension>()
                                .expect("Library error");
                            parent_hash_extension.parent_hash().to_vec()
                        } else {
                            vec![]
                        }
                    } else {
                        vec![]
                    };
                    (key_bytes, parent_hash_bytes)
                }
                NodeType::Parent => {
                    if treemath::root(tree.leaf_count()) == NodeIndex::from(i) {
                        print!("\tP(R)");
                    } else {
                        print!("\tP");
                    }
                    let key_bytes = if let Some(n) = &node.node {
                        n.public_key().as_slice()
                    } else {
                        &[]
                    };
                    let parent_hash_bytes = if let Some(ph) = node.parent_hash() {
                        ph
                    } else {
                        vec![]
                    };
                    (key_bytes, parent_hash_bytes)
                }
                _ => unreachable!(),
            };
            if !key_bytes.is_empty() {
                print!("\tPK: {}", _bytes_to_hex(&key_bytes));
            } else {
                print!("\tPK:\t\t\t");
            }

            if !parent_hash_bytes.is_empty() {
                print!("\tPH: {}", _bytes_to_hex(&parent_hash_bytes));
            } else {
                print!("\tPH:\t\t\t\t\t\t\t\t");
            }
            print!("\t| ");
            for _ in 0..level * factor {
                print!(" ");
            }
            print!("◼︎");
        } else {
            if treemath::root(tree.leaf_count()) == NodeIndex::from(i) {
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

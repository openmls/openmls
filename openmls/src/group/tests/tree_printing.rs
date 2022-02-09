//! A framework to create integration tests of the "raw" core_group API.
//! # Test utils
//!
//! Most tests require to set up groups, clients, credentials, and identities.
//! This module implements helpers to do that.

use crate::{group::*, test_utils::*, treesync::node::Node};

#[cfg(any(feature = "test-utils", test))]
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

#[cfg(any(feature = "test-utils", test))]
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

#[cfg(any(feature = "test-utils", test))]
fn root(size: u32) -> u32 {
    (1 << log2(size)) - 1
}

pub(crate) fn print_tree(group: &CoreGroup, message: &str) {
    let tree = group.treesync();
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
                    let parent_hash_bytes =
                        node.parent_hash().expect("An unexpected error occurred.");
                    (key_bytes, parent_hash_bytes.unwrap_or_default())
                }
                Node::ParentNode(parent_node) => {
                    if root(tree_size) == i as u32 {
                        print!("\tP(R)");
                    } else {
                        print!("\tP");
                    }
                    let key_bytes = parent_node.public_key().as_slice();
                    let parent_hash_bytes =
                        node.parent_hash().expect("An unexpected error occurred.");
                    (key_bytes, parent_hash_bytes.unwrap_or_default())
                }
            };
            print!("\tPK: {}", bytes_to_hex(key_bytes));

            print!("\tPH: {}", bytes_to_hex(parent_hash_bytes));
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

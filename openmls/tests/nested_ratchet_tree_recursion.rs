//! Reproduction for unbounded recursion while decoding nested `ratchet_tree`
//! extensions (GHSA-gc79-23g3-8g52).
//!
//! `Extension::tls_deserialize` decodes an extension body as soon as the
//! extension type is known. For `ratchet_tree` that means decoding a full
//! `RatchetTreeIn`, whose leaf nodes carry `Extensions<LeafNode>` lists, which
//! decode their extension bodies in turn. A `ratchet_tree` extension is not
//! valid inside a leaf node, but that check only runs in
//! `Extensions::<T>::try_from`, after the bodies were already decoded. The
//! recursion depth of the decoder is therefore controlled by the input.
//!
//! The nested fixture is built iteratively at the byte level so that the
//! fixture builder itself never recurses.

use openmls::treesync::RatchetTreeIn;
use tls_codec::{Deserialize, DeserializeBytes};

/// Append a QUIC-style variable-length integer as used by tls_codec 0.5 for
/// `Vec` and `VLBytes` length prefixes. MLS caps lengths at 30 bits.
fn push_varint(len: usize, out: &mut Vec<u8>) {
    if len <= 0x3f {
        out.push(len as u8);
    } else if len <= 0x3f_ff {
        out.extend_from_slice(&((len as u16) | 0x4000).to_be_bytes());
    } else if len <= 0x3f_ff_ff_ff {
        out.extend_from_slice(&((len as u32) | 0x8000_0000).to_be_bytes());
    } else {
        panic!("length beyond 30 bits");
    }
}

/// Serialize a minimal decodable leaf node whose extension list content is
/// `extensions_content` (an empty slice yields an empty extension list). No
/// field needs to be cryptographically valid: `LeafNodeIn` decoding performs
/// no signature or lifetime validation.
fn leaf_bytes(extensions_content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + extensions_content.len());
    out.push(0x00); // encryption_key: empty VLBytes
    out.push(0x00); // signature_key: empty VLBytes
    out.extend_from_slice(&[0x00, 0x01, 0x00]); // credential: Basic, empty content
    out.extend_from_slice(&[0x00; 5]); // capabilities: five empty vectors
    out.push(0x01); // leaf_node_source: KeyPackage
    out.extend_from_slice(&[0u8; 16]); // Lifetime: not_before, not_after
    push_varint(extensions_content.len(), &mut out);
    out.extend_from_slice(extensions_content);
    out.push(0x00); // signature: empty VLBytes
    out
}

/// Serialize a `RatchetTreeIn` holding exactly one leaf node.
fn single_leaf_tree(leaf: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(2 + leaf.len());
    content.push(0x01); // Option::Some
    content.push(0x01); // NodeIn::LeafNode
    content.extend_from_slice(leaf);
    let mut out = Vec::with_capacity(4 + content.len());
    push_varint(content.len(), &mut out);
    out.extend_from_slice(&content);
    out
}

/// Serialize one `ratchet_tree` extension whose body is `tree`.
fn ratchet_tree_extension(tree: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + tree.len());
    out.extend_from_slice(&[0x00, 0x02]); // ExtensionType::RatchetTree
    push_varint(tree.len(), &mut out);
    out.extend_from_slice(tree);
    out
}

/// Build a ratchet tree nested `depth` levels deep, iteratively.
///
/// `nested_tree(0)` is a plain single-leaf tree. `nested_tree(d)` contains a
/// leaf whose extension list holds a `ratchet_tree` extension wrapping
/// `nested_tree(d - 1)`. The structure is invalid MLS; a decoder that applies
/// the leaf-context type rule before reading extension bodies rejects it
/// immediately.
fn nested_tree(depth: usize) -> Vec<u8> {
    let mut tree = single_leaf_tree(&leaf_bytes(&[]));
    for _ in 0..depth {
        let extension = ratchet_tree_extension(&tree);
        tree = single_leaf_tree(&leaf_bytes(&extension));
    }
    tree
}

#[test]
fn depth_zero_tree_decodes() {
    let bytes = nested_tree(0);
    RatchetTreeIn::tls_deserialize_exact(&bytes).expect("plain single-leaf tree must decode");
}

#[test]
fn shallow_nested_tree_returns_decode_error() {
    for depth in [1_usize, 2, 8] {
        let bytes = nested_tree(depth);
        assert!(
            RatchetTreeIn::tls_deserialize_exact(&bytes).is_err(),
            "nested ratchet_tree (depth {depth}) must be rejected"
        );
    }
}

/// Regression test for GHSA-gc79-23g3-8g52: the decoder must reject the
/// forbidden extension type before entering the body, so this returns an
/// error. If a change reintroduces body-before-type decoding, the decoder
/// recurses once per nesting level and this test aborts the process with a
/// stack overflow instead of failing normally — which is still a loud CI
/// signal.
#[test]
fn deep_nested_tree_drives_decoder_recursion() {
    let bytes = nested_tree(2_000);
    assert!(
        RatchetTreeIn::tls_deserialize_exact(&bytes).is_err(),
        "deeply nested ratchet_tree must be a decoding error, not unbounded recursion"
    );
}

/// The context-free `Extension` decoder has no list context of its own, so it
/// must not reject a `ratchet_tree` body outright. The recursion cycle is only
/// broken inside that body, where the leaf extension lists reject a nested
/// `ratchet_tree` before decoding it. This must hold no matter which entry
/// point the bytes arrive through.
#[test]
fn deep_nested_tree_via_raw_extension_entry_is_bounded() {
    let tree = nested_tree(2_000);
    let bytes = ratchet_tree_extension(&tree);
    let _ = openmls::extensions::Extension::tls_deserialize_bytes(&bytes);
}

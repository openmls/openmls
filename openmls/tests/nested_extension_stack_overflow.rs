//! Regression test for GHSA-gc79-23g3-8g52: nested MLS extensions must not
//! drive unbounded decoder recursion.
//!
//! ## The bug this guards against
//!
//! The extension decoder used to decode an extension's *body* before checking
//! whether that extension type is permitted in its enclosing context. A
//! `ratchet_tree` extension is not allowed inside a leaf node's extension list,
//! but its body was decoded (recursively) *before* the leaf-node restriction was
//! applied by `Extensions::<LeafNode>::try_from`.
//!
//! Because a `ratchet_tree` extension body is a `RatchetTreeIn`, which contains
//! leaf nodes, whose payload contains `Extensions<LeafNode>`, a `ratchet_tree`
//! extension nested inside a leaf node's extensions formed an unbounded decode
//! cycle:
//!
//! ```text
//! Extensions<LeafNode>  (Vec<Extension> decoded, THEN validated)
//!   -> Extension::RatchetTree body decoded eagerly
//!     -> RatchetTreeIn = Vec<Option<NodeIn>>
//!       -> NodeIn::LeafNode(Box<LeafNodeIn>)
//!         -> LeafNodePayload.extensions: Extensions<LeafNode>   (cycle)
//! ```
//!
//! Each nesting level added a stack frame during the *descent* of
//! `Vec<Extension>::tls_deserialize`, before any `try_from` validation ran at
//! any level. Sufficient nesting exhausted the thread stack and aborted the
//! process instead of returning `Err`.
//!
//! The fix validates the extension type against the enclosing context *before*
//! decoding the body, so the cycle is cut at the first nesting level and the
//! decoder's recursion depth no longer depends on the input.
//!
//! ## What this test checks
//!
//! 1. `builder_matches_frankenstein_wire_format` — the hand-built malicious
//!    bytes are byte-for-byte identical to what the (validation-free)
//!    Frankenstein serializers produce, so the crafted input really is a
//!    well-formed nested `ratchet_tree`/leaf structure on the wire.
//! 2. `shallow_nesting_returns_err_not_panic` — a shallow nested `ratchet_tree`
//!    extension is rejected with `Err`, because a `ratchet_tree` is not valid
//!    inside a leaf node and the type check now runs before the body is read.
//! 3. `valid_ratchet_tree_still_decodes` — a legitimate tree still decodes, so
//!    the fix did not simply reject everything.
//! 4. `deeply_nested_ratchet_tree_does_not_overflow_the_stack` — the real
//!    regression check. Deep nesting fed to `RatchetTreeIn::tls_deserialize`
//!    must return `Err` promptly instead of recursing. The decode runs in a
//!    child process on a deliberately small stack, so a reintroduced
//!    body-before-type decode overflows that stack and is reported as the child
//!    dying by signal rather than taking down this test runner.
//!
//! The advisory was recorded on Windows (abort status 0xC00000FD). On Unix the
//! same defect manifests as the process being killed by a signal (the Rust
//! runtime's stack-overflow guard aborts the process), which is what the child
//! process below is inspected for. The core parser-descent logic is platform
//! independent.

// The child process is inspected via Unix signal semantics.
#![cfg(unix)]

use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use openmls::prelude::{Credential, CredentialType, RatchetTreeIn};
use openmls::test_utils::frankenstein::{
    FrankenCapabilities, FrankenExtension, FrankenLeafNode, FrankenLeafNodePayload,
    FrankenLeafNodeSource, FrankenNode, FrankenRatchetTreeExtension,
};
use tls_codec::{Deserialize, Serialize};

// -------------------------------------------------------------------------
// Hand-built wire encoding of the malicious nested structure.
//
// The layout is derived directly from the field order of the real types and is
// cross-checked against the Frankenstein serializers in
// `builder_matches_frankenstein_wire_format`.
// -------------------------------------------------------------------------

/// Fixed leaf-node payload bytes up to (but excluding) the `extensions` field.
///
/// `LeafNodePayload` = encryption_key, signature_key, credential, capabilities,
/// leaf_node_source, extensions. We fill everything before `extensions` with the
/// smallest well-formed values.
const LEAF_PREFIX: &[u8] = &[
    0x00, // encryption_key: empty VLBytes
    0x00, // signature_key: empty VLBytes
    0x00, 0x01, 0x00, // credential: type = Basic (u16 = 1), empty content VLBytes
    0x00, 0x00, 0x00, 0x00, 0x00, // capabilities: five empty vectors
    0x02, // leaf_node_source = Update (no trailing data in the LeafNode wire format)
];

/// The `signature` field that trails a `LeafNodeIn` (empty VLBytes).
const LEAF_SIGNATURE: u8 = 0x00;

/// `ExtensionType::RatchetTree` encoded as a big-endian `u16`.
const EXTENSION_TYPE_RATCHET_TREE: [u8; 2] = [0x00, 0x02];

/// TLS "variable-length" length prefix (QUIC-style varint), matching the
/// encoding tls_codec uses for `Vec<T>` and `VLBytes`.
fn var_len_prefix(len: usize) -> Vec<u8> {
    if len <= 0x3f {
        vec![len as u8]
    } else if len <= 0x3fff {
        (len as u16 | 0x4000).to_be_bytes().to_vec()
    } else if len <= 0x3fff_ffff {
        (len as u32 | 0x8000_0000).to_be_bytes().to_vec()
    } else {
        (len as u64 | 0xc000_0000_0000_0000).to_be_bytes().to_vec()
    }
}

/// Prepend a variable-length length prefix to `body`.
fn var_len_bytes(body: &[u8]) -> Vec<u8> {
    let mut out = var_len_prefix(body.len());
    out.extend_from_slice(body);
    out
}

/// A `RatchetTreeIn` (= `Vec<Option<NodeIn>>`) containing exactly one leaf node
/// whose already-encoded `extensions` field is `extensions_field`.
fn ratchet_tree_with_leaf(extensions_field: &[u8]) -> Vec<u8> {
    // LeafNodeIn = payload (prefix ++ extensions) ++ signature
    let mut leaf = LEAF_PREFIX.to_vec();
    leaf.extend_from_slice(extensions_field);
    leaf.push(LEAF_SIGNATURE);

    // NodeIn::LeafNode has discriminant 1.
    let mut node = vec![0x01];
    node.extend_from_slice(&leaf);

    // Option::Some tag is 1.
    let mut opt = vec![0x01];
    opt.extend_from_slice(&node);

    // Vec<Option<NodeIn>> framing.
    var_len_bytes(&opt)
}

/// The innermost tree: a single leaf node with an empty extension list.
fn base_ratchet_tree() -> Vec<u8> {
    ratchet_tree_with_leaf(&var_len_bytes(&[]))
}

/// Build the encoded bytes for a `ratchet_tree` nested `depth` levels deep.
///
/// `depth == 0` is the base tree (one leaf, empty extensions). Each additional
/// level wraps the previous tree inside a leaf's `ratchet_tree` extension.
///
/// This is built inside-out in O(depth) time and memory: every level shares one
/// trailing `signature` byte and a small, self-similar "open" segment whose only
/// variable part is the length prefixes. Crucially, the builder itself does
/// *no* deep recursion, so constructing the payload cannot overflow the harness
/// stack.
fn build_nested_ratchet_tree(depth: usize) -> Vec<u8> {
    let base = base_ratchet_tree();
    if depth == 0 {
        return base;
    }

    // Everything that appears *before* the inner tree at each level, outermost
    // first once reversed.
    let mut open_segments: Vec<Vec<u8>> = Vec::with_capacity(depth);
    let mut inner_len = base.len();

    for _ in 0..depth {
        let body_prefix = var_len_prefix(inner_len);
        let extension_len = EXTENSION_TYPE_RATCHET_TREE.len() + body_prefix.len() + inner_len;
        let extensions_prefix = var_len_prefix(extension_len);
        let leaf_len =
            LEAF_PREFIX.len() + extensions_prefix.len() + extension_len + 1 /* signature */;
        let node_len = 1 /* NodeIn discriminant */ + leaf_len;
        let opt_len = 1 /* Option::Some */ + node_len;
        let tree_prefix = var_len_prefix(opt_len);

        let mut open = Vec::new();
        open.extend_from_slice(&tree_prefix);
        open.push(0x01); // Option::Some
        open.push(0x01); // NodeIn::LeafNode
        open.extend_from_slice(LEAF_PREFIX);
        open.extend_from_slice(&extensions_prefix);
        open.extend_from_slice(&EXTENSION_TYPE_RATCHET_TREE);
        open.extend_from_slice(&body_prefix);
        open_segments.push(open);

        inner_len = tree_prefix.len() + opt_len;
    }

    let mut out = Vec::with_capacity(inner_len);
    for open in open_segments.iter().rev() {
        out.extend_from_slice(open);
    }
    out.extend_from_slice(&base);
    // One trailing leaf `signature` byte (0x00) per wrapping level. All levels
    // share the same value, so ordering is irrelevant.
    out.extend(std::iter::repeat_n(LEAF_SIGNATURE, depth));
    out
}

// -------------------------------------------------------------------------
// Frankenstein reference (validation-free) construction, used to prove the
// hand-built bytes are a faithful nested wire encoding.
// -------------------------------------------------------------------------

fn franken_leaf(extensions: Vec<FrankenExtension>) -> FrankenLeafNode {
    FrankenLeafNode {
        payload: FrankenLeafNodePayload {
            encryption_key: vec![].into(),
            signature_key: vec![].into(),
            credential: Credential::new(CredentialType::Basic, vec![]).into(),
            capabilities: FrankenCapabilities {
                versions: vec![],
                ciphersuites: vec![],
                extensions: vec![],
                proposals: vec![],
                credentials: vec![],
            },
            leaf_node_source: FrankenLeafNodeSource::Update,
            extensions,
        },
        signature: vec![].into(),
    }
}

/// Same structure as `build_nested_ratchet_tree`, built with the Frankenstein
/// serializers. Used only for the wire-format cross-check at small depths.
fn build_nested_ratchet_tree_frankenstein(depth: usize) -> Vec<u8> {
    let mut tree: Vec<Option<FrankenNode>> =
        vec![Some(FrankenNode::LeafNode(franken_leaf(vec![])))];
    for _ in 0..depth {
        let extension =
            FrankenExtension::RatchetTree(FrankenRatchetTreeExtension { ratchet_tree: tree });
        tree = vec![Some(FrankenNode::LeafNode(franken_leaf(vec![extension])))];
    }
    tree.tls_serialize_detached().unwrap()
}

#[test]
fn builder_matches_frankenstein_wire_format() {
    for depth in 0..=4 {
        let hand = build_nested_ratchet_tree(depth);
        let franken = build_nested_ratchet_tree_frankenstein(depth);
        assert_eq!(
            hand, franken,
            "hand-built bytes must equal the Frankenstein wire encoding at depth {depth}"
        );
    }
}

#[test]
fn valid_ratchet_tree_still_decodes() {
    // The base tree (a single leaf with no extensions) is structurally valid and
    // must still deserialize successfully.
    let bytes = build_nested_ratchet_tree(0);
    let decoded = RatchetTreeIn::tls_deserialize(&mut bytes.as_slice());
    assert!(
        decoded.is_ok(),
        "a valid ratchet tree must still decode, got {decoded:?}"
    );
}

#[test]
fn shallow_nesting_returns_err_not_panic() {
    // A `ratchet_tree` extension is not permitted inside a leaf node, so the
    // leaf-node context validation rejects it before its body is read. The
    // correct, non-crashing behavior is `Err`.
    let bytes = build_nested_ratchet_tree(2);
    let decoded = RatchetTreeIn::tls_deserialize(&mut bytes.as_slice());
    assert!(
        decoded.is_err(),
        "a ratchet_tree extension is not valid inside a leaf node and must be \
         rejected with Err, got Ok"
    );
}

// -------------------------------------------------------------------------
// The denial-of-service regression check.
//
// The decode is run in a *child process* on a bounded-stack thread. On the
// fixed crate the decode returns `Err` immediately and the child exits
// normally; a regression would make the recursive descent overflow that stack,
// and the Rust runtime would abort the child (a signal on Unix). Isolating the
// decode in a child process means such a regression fails this test instead of
// killing the test runner.
// -------------------------------------------------------------------------

const CHILD_ENV: &str = "OPENMLS_NESTED_EXT_REPRO_CHILD";
/// Nesting depth. Far more than fits in the bounded child stack below, so a
/// regression overflows during descent long before the whole payload is
/// consumed.
const REPRO_DEPTH: usize = 100_000;
/// Bounded stack for the decode thread in the child, so a regression shows up
/// quickly and deterministically regardless of the platform's default stack
/// size.
const REPRO_CHILD_STACK: usize = 256 * 1024;

#[test]
fn deeply_nested_ratchet_tree_does_not_overflow_the_stack() {
    // Child branch: perform the real decode and report what it returned.
    if std::env::var(CHILD_ENV).is_ok() {
        run_decoder_child();
        return;
    }

    // Parent branch: re-exec this test binary, running only this test, with the
    // child marker set.
    let exe = std::env::current_exe().expect("current test executable");
    let output = Command::new(&exe)
        .args([
            "--exact",
            "deeply_nested_ratchet_tree_does_not_overflow_the_stack",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .expect("failed to spawn child test process");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // The decode must have run to completion. If this marker is missing the
    // child died mid-decode, which is what a reintroduced unbounded recursion
    // looks like.
    assert!(
        stderr.contains("CHILD_SURVIVED"),
        "the decoder did not return; it most likely overflowed the stack on the \
         nested input. Child stderr:\n{stderr}"
    );

    // ... and it must have rejected the input rather than accepting the nested
    // `ratchet_tree`, which is not valid inside a leaf node.
    assert!(
        stderr.contains("CHILD_SURVIVED: decoder returned is_err=true"),
        "the decoder accepted a nested ratchet_tree inside a leaf node. Child \
         stderr:\n{stderr}"
    );

    // The child must have exited normally rather than being aborted by the
    // runtime's stack-overflow guard.
    assert!(
        output.status.code().is_some(),
        "expected the child to exit with a status code, but it was aborted \
         without one; status was {:?}",
        output.status
    );
    assert!(
        output.status.signal().is_none(),
        "expected the child to exit normally, but it was killed by a signal \
         (stack-overflow abort); status was {:?}",
        output.status
    );
}

fn run_decoder_child() {
    let depth: usize = std::env::var("OPENMLS_NESTED_EXT_REPRO_DEPTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(REPRO_DEPTH);
    let stack: usize = std::env::var("OPENMLS_NESTED_EXT_REPRO_STACK")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(REPRO_CHILD_STACK);

    // Building the payload must not itself recurse, so that a stack overflow
    // here can only come from the decoder.
    let bytes = build_nested_ratchet_tree(depth);
    eprintln!("child built {} bytes at depth {depth}", bytes.len());

    // Run the real decoder on a thread with a bounded stack. If the decoder
    // recurses per nesting level again, the overflow aborts this whole child
    // process via the Rust runtime's guard-page handler and the parent sees no
    // `CHILD_SURVIVED` marker.
    let handle = std::thread::Builder::new()
        .stack_size(stack)
        .name("nested-extension-decoder".into())
        .spawn(move || {
            let result = RatchetTreeIn::tls_deserialize(&mut bytes.as_slice());
            // Only reached if the decoder returned instead of overflowing.
            eprintln!(
                "CHILD_SURVIVED: decoder returned is_err={}",
                result.is_err()
            );
        })
        .expect("failed to spawn decoder thread");

    let _ = handle.join();
    // Only reached if no overflow occurred.

    eprintln!("CHILD_COMPLETED_WITHOUT_ABORT");
}

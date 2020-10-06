//! A bunch of test utilities for tree tests.

#[cfg(test)]
use super::index::NodeIndex;
#[cfg(test)]
use crate::utils::*;

#[cfg(test)]
/// Generate a random sequence of node indices.
/// Note that this can be an endless loop if len > u8::MAX
pub(crate) fn generate_path_u8(len: usize) -> Vec<NodeIndex> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let mut v = NodeIndex::from(random_u8() as u32);
        while out.contains(&v) {
            v = NodeIndex::from(random_u8() as u32);
        }
        out.push(v)
    }
    out
}

#[cfg(test)]
/// Generate a random sequence of node indices.
/// Note that this can be an endless loop if len > u32::MAX
pub(crate) fn generate_path_u32(len: usize) -> Vec<NodeIndex> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let mut v = NodeIndex::from(random_u32());
        while out.contains(&v) {
            v = NodeIndex::from(random_u32());
        }
        out.push(v)
    }
    out
}
use crate::codec::*;

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub struct NodeIndex(u32);

impl NodeIndex {
    pub fn as_u32(self) -> u32 {
        self.0
    }
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl From<u32> for NodeIndex {
    fn from(i: u32) -> NodeIndex {
        NodeIndex(i)
    }
}

impl From<usize> for NodeIndex {
    fn from(i: usize) -> NodeIndex {
        NodeIndex(i as u32)
    }
}

impl From<LeafIndex> for NodeIndex {
    fn from(node_index: LeafIndex) -> NodeIndex {
        NodeIndex(node_index.as_u32() * 2)
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub struct LeafIndex(u32);

impl LeafIndex {
    pub fn as_u32(self) -> u32 {
        self.0
    }
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl From<u32> for LeafIndex {
    fn from(i: u32) -> LeafIndex {
        LeafIndex(i)
    }
}

impl Into<u32> for LeafIndex {
    fn into(self) -> u32 {
        self.0
    }
}

impl Into<usize> for LeafIndex {
    fn into(self) -> usize {
        self.0 as usize
    }
}

impl From<usize> for LeafIndex {
    fn from(i: usize) -> LeafIndex {
        LeafIndex(i as u32)
    }
}

impl From<NodeIndex> for LeafIndex {
    fn from(tree_index: NodeIndex) -> LeafIndex {
        LeafIndex((tree_index.as_u32() + 1) / 2)
    }
}

impl Codec for LeafIndex {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(buffer)
    }
}

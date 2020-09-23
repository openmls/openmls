//! A data structure holding information about the leaf node in the tree that
//! belongs to the current client.
//!
//! * TODO: functions should operate on `self`.

use super::{index::NodeIndex, path_key_pairs::PathKeypairs};
use crate::ciphersuite::{Ciphersuite, HPKEKeyPair};
use crate::codec::{Codec, CodecError};
use crate::key_packages::KeyPackageBundle;
use crate::messages::CommitSecret;
use crate::schedule::hkdf_expand_label;

#[derive(Debug, Clone)]
pub(crate) struct OwnLeaf {
    kpb: KeyPackageBundle,
    node_index: NodeIndex,
    path_keypairs: PathKeypairs,
}

impl OwnLeaf {
    pub(crate) fn new(
        kpb: KeyPackageBundle,
        node_index: NodeIndex,
        path_keypairs: PathKeypairs,
    ) -> Self {
        Self {
            kpb,
            node_index,
            path_keypairs,
        }
    }

    pub(crate) fn get_kpb(&self) -> &KeyPackageBundle {
        &self.kpb
    }
    pub(crate) fn get_node_index(&self) -> NodeIndex {
        self.node_index
    }
    pub(crate) fn get_path_key_pairs(&self) -> &PathKeypairs {
        &self.path_keypairs
    }
    pub(crate) fn get_path_key_pairs_mut(&mut self) -> &mut PathKeypairs {
        &mut self.path_keypairs
    }
    pub(crate) fn set_path_key_pairs(&mut self, new_key_pairs: PathKeypairs) {
        self.path_keypairs = new_key_pairs;
    }

    /// Generate `n` path secrets with the given `start_secret`:
    /// `path_secret[0] = DeriveSecret(leaf_secret, "path")`
    pub(crate) fn generate_path_secrets(
        ciphersuite: &Ciphersuite,
        start_secret: &[u8],
        start_on_leaf: bool,
        n: usize,
    ) -> (Vec<Vec<u8>>, CommitSecret) {
        let hash_len = ciphersuite.hash_length();
        let start_secret = if start_on_leaf {
            hkdf_expand_label(ciphersuite, start_secret, "path", &[], hash_len)
        } else {
            start_secret.to_vec()
        };
        let mut path_secrets = vec![start_secret];
        for i in 0..n - 1 {
            let path_secret =
                hkdf_expand_label(ciphersuite, &path_secrets[i], "path", &[], hash_len);
            path_secrets.push(path_secret);
        }
        let commit_secret = CommitSecret(hkdf_expand_label(
            ciphersuite,
            &path_secrets.last().unwrap(),
            "path",
            &[],
            hash_len,
        ));
        (path_secrets, commit_secret)
    }

    pub(crate) fn generate_path_keypairs(
        ciphersuite: &Ciphersuite,
        path_secrets: &[Vec<u8>],
    ) -> Vec<HPKEKeyPair> {
        let hash_len = ciphersuite.hash_length();
        let mut keypairs = vec![];
        for path_secret in path_secrets {
            let node_secret = hkdf_expand_label(ciphersuite, &path_secret, "node", &[], hash_len);
            let keypair = HPKEKeyPair::derive(&node_secret, ciphersuite);
            keypairs.push(keypair);
        }
        keypairs
    }
}

impl Codec for OwnLeaf {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.kpb.encode(buffer)?;
        self.node_index.as_u32().encode(buffer)?;
        self.path_keypairs.encode(buffer)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let kpb = KeyPackageBundle::decode(cursor)?;
    //     let node_index = NodeIndex::from(u32::decode(cursor)?);
    //     let path_keypairs = PathKeypairs::decode(cursor)?;
    //     Ok(OwnLeaf {
    //         kpb,
    //         node_index,
    //         path_keypairs,
    //     })
    // }
}

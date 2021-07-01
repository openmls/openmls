use std::collections::HashSet;

use hpke::HpkePublicKey;

use crate::{
    ciphersuite::{Ciphersuite, Secret},
    extensions::RatchetTreeExtension,
    group::{GroupEpoch, MlsGroup},
    messages::PathSecret,
    node::Node,
    prelude::{
        KeyPackageBundle, LeafIndex, MlsCiphertext, MlsCiphertextError, MlsPlaintext,
        ProtocolVersion,
    },
    tree::{
        treemath::{common_ancestor_index, parent_direct_path, root, TreeMathError},
        NodeIndex, RatchetTree, TreeError, UpdatePath,
    },
};

impl RatchetTree {
    pub fn update_path_test(
        &mut self,
        sender: LeafIndex,
        update_path: &UpdatePath,
        group_context: &[u8],
        new_leaves_indexes: HashSet<&LeafIndex>,
    ) -> Result<&[u8], TreeError> {
        self.update_path(sender, update_path, group_context, new_leaves_indexes)
            .map(|commit_secret| commit_secret.as_slice())
    }

    pub fn path_secrets_test(&self) -> &[PathSecret] {
        self.private_tree().path_secrets()
    }

    pub fn path_secret_test(&self, index: NodeIndex) -> Option<&PathSecret> {
        self.path_secret(index)
    }

    pub fn own_node_index_test(&self) -> LeafIndex {
        self.own_node_index()
    }

    pub fn new_from_nodes_test(
        kpb: KeyPackageBundle,
        node_options: &[Option<Node>],
    ) -> Result<RatchetTree, TreeError> {
        RatchetTree::new_from_nodes(kpb, node_options)
    }

    pub fn continue_path_secrets_test(
        &mut self,
        ciphersuite: &Ciphersuite,
        start_secret: PathSecret,
        path: &[NodeIndex],
    ) -> Vec<HpkePublicKey> {
        self.private_tree_mut()
            .continue_path_secrets(ciphersuite, start_secret, path)
    }

    pub fn tree_hash_test(&self) -> Vec<u8> {
        self.tree_hash()
    }
}

impl Secret {
    pub fn from_slice_test(
        bytes: &[u8],
        mls_version: ProtocolVersion,
        ciphersuite: &'static Ciphersuite,
    ) -> Self {
        Self::from_slice(bytes, mls_version, ciphersuite)
    }

    pub fn random_test(
        ciphersuite: &'static Ciphersuite,
        version: impl Into<Option<ProtocolVersion>>,
    ) -> Self {
        Self::random(ciphersuite, version)
    }
}

impl RatchetTreeExtension {
    pub fn into_vector_test(self) -> Vec<Option<Node>> {
        self.into_vector()
    }
}

pub fn common_ancestor_index_test(x: NodeIndex, y: NodeIndex) -> NodeIndex {
    common_ancestor_index(x, y)
}

pub fn parent_direct_path_test(
    node_index: NodeIndex,
    size: LeafIndex,
) -> Result<Vec<NodeIndex>, TreeMathError> {
    parent_direct_path(node_index, size)
}

pub fn root_test(size: LeafIndex) -> NodeIndex {
    root(size)
}

impl MlsGroup {
    pub fn set_epoch(&mut self, epoch: GroupEpoch) {
        self.context.set_epoch(epoch)
    }
}

impl MlsCiphertext {
    pub fn try_from_plaintext_test(
        mls_plaintext: &MlsPlaintext,
        group: &MlsGroup,
        sender: LeafIndex,
        padding_size: usize,
    ) -> Result<MlsCiphertext, MlsCiphertextError> {
        MlsCiphertext::try_from_plaintext(
            mls_plaintext,
            group.ciphersuite(),
            group.context(),
            sender,
            group.epoch_secrets(),
            &mut group.secret_tree_mut(),
            padding_size,
        )
    }
}

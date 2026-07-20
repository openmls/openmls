use super::*;
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicStagedCommitState {
    pub(super) staged_diff: StagedPublicGroupDiff,
    pub(super) update_path_leaf_node: Option<LeafNode>,
}

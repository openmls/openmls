use crate::binary_tree::LeafNodeIndex;

use crate::{
    group::{
        commit_builder::{CommitBuilder, Initial},
        fork_resolution::complement,
        Member, MlsGroup,
    },
    prelude::KeyPackage,
};

pub struct ReAddExpectKeyPackages {
    complement_partition: Vec<Member>,
}

impl MlsGroup {
    fn recover_fork_by_readding(
        &mut self,
        own_partition: &[LeafNodeIndex],
    ) -> Result<CommitBuilder<ReAddExpectKeyPackages>, ReAddError> {
        // Load member info. This is None of at least one of the indexes is not a valid member
        let own_partition: Option<Vec<_>> = own_partition
            .iter()
            .cloned()
            .map(|leaf_index| self.member_at(leaf_index))
            .collect();

        // check that a
        let own_partition = own_partition.ok_or(ReAddError::InvalidLeafNodeIndex)?;

        let complement_partition = complement(&own_partition, self.members()).collect();

        let stage = ReAddExpectKeyPackages {
            complement_partition,
        };

        Ok(self.commit_builder().into_stage(stage))
    }
}

impl<'a> CommitBuilder<'a, ReAddExpectKeyPackages> {
    pub fn complement_partition(&self) -> &[Member] {
        self.stage().complement_partition.as_slice()
    }

    pub fn provide_key_packages(
        self,
        new_key_packages: Vec<KeyPackage>,
    ) -> CommitBuilder<'a, Initial> {
        let (stage, builder) = self.replace_stage(Initial::default());

        builder
            .propose_removals(stage.complement_partition.iter().map(|member| member.index))
            .propose_adds(new_key_packages)
    }
}

enum ReAddError {
    InvalidLeafNodeIndex,
}

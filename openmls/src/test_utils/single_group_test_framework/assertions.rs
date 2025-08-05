use super::*;

impl<Provider: OpenMlsProvider> MemberState<'_, Provider> {
    pub fn assert_group_storage_state_matches(&self, to_compare: GroupStorageState) {
        let state_now = self.group_storage_state();
        assert!(to_compare == state_now);
    }
    pub fn assert_non_proposal_group_storage_state_matches(&self, to_compare: GroupStorageState) {
        let state_now = self.group_storage_state();
        assert!(to_compare.non_proposal_state() == state_now.non_proposal_state());
    }
}
impl<Provider: OpenMlsProvider> GroupState<'_, Provider> {
    pub fn assert_membership(&self) {
        let mut names = self
            .members
            .keys()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        names.sort();

        for state in self.members.values() {
            let mut names_in_group = state
                .group
                .members()
                .map(|member| {
                    let credential: BasicCredential = member.credential.try_into().unwrap();

                    String::from_utf8(credential.identity().to_owned()).unwrap()
                })
                .collect::<Vec<_>>();

            names_in_group.sort();

            assert_eq!(names, names_in_group);
        }
    }
}

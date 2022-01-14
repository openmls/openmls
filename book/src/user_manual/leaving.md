# Leaving a group

Members can indicate to the other members of the group that they wish to leave the group by creating and sending a Remove Proposal for their own identifier. It is not possible for the member to create a Commit message that covers this proposal, as that would violate the Post-compromise Security guarantees of MLS because the member would know the epoch secrets of the next epoch.

After successfully sending the proposal to the DS for fanout, it is safe for the member to tear down the local group state and ignore all subsequent messages for that group.

For details on how to create Remove Proposals, see [Removing members from a group](remove_members.md).

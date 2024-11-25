use std::marker::PhantomData;

use openmls_traits::storage::{
    traits::ProposalRef as ProposalRefTrait, Entity, Key, CURRENT_VERSION,
};
use rusqlite::params;

use crate::{
    codec::Codec,
    storage_provider::StorableGroupIdRef,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
    Storable,
};

pub(crate) struct StorableProposal<
    Proposal: Entity<CURRENT_VERSION>,
    ProposalRef: Entity<CURRENT_VERSION>,
>(pub ProposalRef, pub Proposal);

impl<Proposal: Entity<CURRENT_VERSION>, ProposalRef: Entity<CURRENT_VERSION>> Storable
    for StorableProposal<Proposal, ProposalRef>
{
    const CREATE_TABLE_STATEMENT: &'static str = "CREATE TABLE IF NOT EXISTS proposals (
        group_id BLOB NOT NULL,
        proposal_ref BLOB NOT NULL,
        proposal BLOB NOT NULL,
        PRIMARY KEY (group_id, proposal_ref)
    );";

    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(proposal_ref, ..) = row.get(0)?;
        let EntityWrapper::<C, _>(proposal, ..) = row.get(1)?;
        Ok(Self(proposal_ref, proposal))
    }
}

impl<Proposal: Entity<CURRENT_VERSION>, ProposalRef: Entity<CURRENT_VERSION>>
    StorableProposal<Proposal, ProposalRef>
{
    pub(super) fn load<C: Codec, GroupId: Key<CURRENT_VERSION>>(
        connection: &rusqlite::Connection,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, Proposal)>, rusqlite::Error> {
        let mut stmt = connection
            .prepare("SELECT proposal_ref, proposal FROM proposals WHERE group_id = ?1")?;
        let proposals = stmt
            .query_map(
                params![KeyRefWrapper::<C, _>(group_id, PhantomData)],
                |row| Self::from_row::<C>(row).map(|x| (x.0, x.1)),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(proposals)
    }

    pub(super) fn load_refs<C: Codec, GroupId: Key<CURRENT_VERSION>>(
        connection: &rusqlite::Connection,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, rusqlite::Error> {
        let mut stmt =
            connection.prepare("SELECT proposal_ref FROM proposals WHERE group_id = ?1")?;
        let proposal_refs = stmt
            .query_map(
                params![KeyRefWrapper::<C, _>(group_id, PhantomData)],
                |row| {
                    let EntityWrapper::<C, _>(proposal_ref, PhantomData) = row.get(0)?;
                    Ok(proposal_ref)
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(proposal_refs)
    }
}

pub(super) struct StorableProposalRef<
    'a,
    Proposal: Entity<CURRENT_VERSION>,
    ProposalRef: Entity<CURRENT_VERSION>,
>(pub &'a ProposalRef, pub &'a Proposal);

impl<'a, Proposal: Entity<CURRENT_VERSION>, ProposalRef: Entity<CURRENT_VERSION>>
    StorableProposalRef<'a, Proposal, ProposalRef>
{
    pub(super) fn store<C: Codec, GroupId: Key<CURRENT_VERSION>>(
        &self,
        connection: &rusqlite::Connection,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "INSERT INTO proposals (group_id, proposal_ref, proposal) VALUES (?1, ?2, ?3)",
            params![
                KeyRefWrapper::<C, _>(group_id, PhantomData),
                EntityRefWrapper::<C, _>(self.0, PhantomData),
                EntityRefWrapper::<C, _>(self.1, PhantomData),
            ],
        )?;
        Ok(())
    }
}

impl<'a, GroupId: Key<CURRENT_VERSION>> StorableGroupIdRef<'a, GroupId> {
    pub(super) fn delete_all_proposals<C: Codec>(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM proposals WHERE group_id = ?1",
            params![KeyRefWrapper::<C, _>(self.0, PhantomData)],
        )?;
        Ok(())
    }

    pub(super) fn delete_proposal<C: Codec, ProposalRef: ProposalRefTrait<CURRENT_VERSION>>(
        &self,
        connection: &rusqlite::Connection,
        proposal_ref: &ProposalRef,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            "DELETE FROM proposals WHERE group_id = ?1 AND proposal_ref = ?2",
            params![
                KeyRefWrapper::<C, _>(self.0, PhantomData),
                KeyRefWrapper::<C, _>(proposal_ref, PhantomData)
            ],
        )?;
        Ok(())
    }
}

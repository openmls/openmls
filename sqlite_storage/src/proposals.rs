use std::marker::PhantomData;

use openmls_traits::storage::{Entity, Key, traits::ProposalRef as ProposalRefTrait};
use rusqlite::{Connection, params};

use crate::{
    STORAGE_PROVIDER_VERSION,
    codec::Codec,
    storage_provider::StorableGroupIdRef,
    wrappers::{EntityRefWrapper, EntityWrapper, KeyRefWrapper},
};

pub(crate) struct StorableProposal<
    Proposal: Entity<STORAGE_PROVIDER_VERSION>,
    ProposalRef: Entity<STORAGE_PROVIDER_VERSION>,
>(pub ProposalRef, pub Proposal);

impl<Proposal: Entity<STORAGE_PROVIDER_VERSION>, ProposalRef: Entity<STORAGE_PROVIDER_VERSION>>
    StorableProposal<Proposal, ProposalRef>
{
    fn from_row<C: Codec>(row: &rusqlite::Row) -> Result<Self, rusqlite::Error> {
        let EntityWrapper::<C, _>(proposal_ref, ..) = row.get(0)?;
        let EntityWrapper::<C, _>(proposal, ..) = row.get(1)?;
        Ok(Self(proposal_ref, proposal))
    }

    pub(super) fn load<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &Connection,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, Proposal)>, rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "SELECT proposal_ref, proposal
            FROM openmls_proposals
            WHERE group_id = ?1
                AND provider_version = ?2",
        )?;
        let proposals = stmt
            .query_map(
                params![
                    KeyRefWrapper::<C, _>(group_id, PhantomData),
                    STORAGE_PROVIDER_VERSION
                ],
                |row| Self::from_row::<C>(row).map(|x| (x.0, x.1)),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(proposals)
    }

    pub(super) fn load_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, Proposal)>, rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "SELECT proposal_ref, proposal
            FROM openmls_proposals
            WHERE group_id = ?1
                AND provider_version = ?2",
        )?;
        let proposals = stmt
            .query_map(
                params![
                    KeyRefWrapper::<C, _>(group_id, PhantomData),
                    STORAGE_PROVIDER_VERSION
                ],
                |row| Self::from_row::<C>(row).map(|x| (x.0, x.1)),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(proposals)
    }

    pub(super) fn load_refs<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        connection: &Connection,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "SELECT proposal_ref
                FROM openmls_proposals
                WHERE group_id = ?1
                    AND provider_version = ?2",
        )?;
        let proposal_refs = stmt
            .query_map(
                params![
                    KeyRefWrapper::<C, _>(group_id, PhantomData),
                    STORAGE_PROVIDER_VERSION
                ],
                |row| {
                    let EntityWrapper::<C, _>(proposal_ref, PhantomData) = row.get(0)?;
                    Ok(proposal_ref)
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(proposal_refs)
    }

    pub(super) fn load_refs_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "SELECT proposal_ref
                FROM openmls_proposals
                WHERE group_id = ?1
                    AND provider_version = ?2",
        )?;
        let proposal_refs = stmt
            .query_map(
                params![
                    KeyRefWrapper::<C, _>(group_id, PhantomData),
                    STORAGE_PROVIDER_VERSION
                ],
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
    Proposal: Entity<STORAGE_PROVIDER_VERSION>,
    ProposalRef: Entity<STORAGE_PROVIDER_VERSION>,
>(pub &'a ProposalRef, pub &'a Proposal);

impl<Proposal: Entity<STORAGE_PROVIDER_VERSION>, ProposalRef: Entity<STORAGE_PROVIDER_VERSION>>
    StorableProposalRef<'_, Proposal, ProposalRef>
{
    pub(super) fn store<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        connection: &Connection,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        // We insert or ignore here, because if the proposal ref matches, the
        // content will match as well.
        let mut stmt = connection.prepare_cached(
            "INSERT OR IGNORE INTO openmls_proposals (group_id, proposal_ref, proposal, provider_version)
            VALUES (?1, ?2, ?3, ?4)",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(group_id, PhantomData),
            EntityRefWrapper::<C, _>(self.0, PhantomData),
            EntityRefWrapper::<C, _>(self.1, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }

    pub(super) fn store_in_tx<C: Codec, GroupId: Key<STORAGE_PROVIDER_VERSION>>(
        &self,
        tx: &rusqlite::Transaction<'_>,
        group_id: &GroupId,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO openmls_proposals (group_id, proposal_ref, proposal, provider_version)
            VALUES (?1, ?2, ?3, ?4)",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(group_id, PhantomData),
            EntityRefWrapper::<C, _>(self.0, PhantomData),
            EntityRefWrapper::<C, _>(self.1, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }
}

impl<GroupId: Key<STORAGE_PROVIDER_VERSION>> StorableGroupIdRef<'_, GroupId> {
    pub(super) fn delete_all_proposals<C: Codec>(
        &self,
        connection: &Connection,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "DELETE FROM openmls_proposals
            WHERE group_id = ?1
                AND provider_version = ?2",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }

    pub(super) fn delete_all_proposals_in_tx<C: Codec>(
        &self,
        tx: &rusqlite::Transaction<'_>,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "DELETE FROM openmls_proposals
            WHERE group_id = ?1
                AND provider_version = ?2",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(self.0, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }

    pub(super) fn delete_proposal<
        C: Codec,
        ProposalRef: ProposalRefTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        connection: &Connection,
        proposal_ref: &ProposalRef,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = connection.prepare_cached(
            "DELETE FROM openmls_proposals
            WHERE group_id = ?1
                AND proposal_ref = ?2
                AND provider_version = ?3",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(self.0, PhantomData),
            KeyRefWrapper::<C, _>(proposal_ref, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }

    pub(super) fn delete_proposal_in_tx<
        C: Codec,
        ProposalRef: ProposalRefTrait<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        tx: &rusqlite::Transaction<'_>,
        proposal_ref: &ProposalRef,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = tx.prepare_cached(
            "DELETE FROM openmls_proposals
            WHERE group_id = ?1
                AND proposal_ref = ?2
                AND provider_version = ?3",
        )?;
        stmt.execute(params![
            KeyRefWrapper::<C, _>(self.0, PhantomData),
            KeyRefWrapper::<C, _>(proposal_ref, PhantomData),
            STORAGE_PROVIDER_VERSION
        ])?;
        Ok(())
    }
}

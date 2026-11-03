//! Compile-time checks that the futures of the reinit and subgroup branch APIs
//! are `Send` for every provider that is `Sync`.
//!
//! The group flow in the `tests` module does not reach these APIs. Each check
//! only builds the future, so the module compiles only if the future can be
//! spawned on a multi-threaded runtime.

use std::future::Future;

use openmls::{credentials::CredentialWithKey, prelude::*};
use openmls_basic_credential::SignatureKeyPair;

fn build_reinit<'a, P: OpenMlsProvider + Sync>(
    builder: ReInitGroupBuilder,
    provider: &'a P,
    signer: &'a SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    members: Vec<KeyPackage>,
) -> impl Future + Send + 'a {
    builder.build_reinit(provider, signer, credential_with_key, members)
}

fn build_branch<'a, P: OpenMlsProvider + Sync>(
    builder: BranchGroupBuilder,
    provider: &'a P,
    signer: &'a SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    members: Vec<KeyPackage>,
) -> impl Future + Send + 'a {
    builder.build_branch(provider, signer, credential_with_key, members)
}

fn propose_reinit<'a, P: OpenMlsProvider + Sync>(
    group: &'a mut MlsGroup,
    provider: &'a P,
    proposal: ReInitProposal,
    signer: &'a SignatureKeyPair,
) -> impl Future + Send + 'a {
    group.propose_reinit(provider, proposal, signer)
}

fn staged_welcome_build_from_reinit<'a, P: OpenMlsProvider + Sync>(
    provider: &'a P,
    config: &'a MlsGroupJoinConfig,
    welcome: Welcome,
    reinit_info: ReInitInfo,
) -> impl Future + Send + 'a {
    StagedWelcome::build_from_reinit(provider, config, welcome, reinit_info)
}

fn staged_welcome_build_from_branch<'a, P: OpenMlsProvider + Sync>(
    provider: &'a P,
    config: &'a MlsGroupJoinConfig,
    welcome: Welcome,
    branch_info: BranchInfo,
) -> impl Future + Send + 'a {
    StagedWelcome::build_from_branch(provider, config, welcome, branch_info)
}

fn process_resuming_welcome<'a, P: OpenMlsProvider + Sync>(
    provider: &'a P,
    config: &'a MlsGroupJoinConfig,
    welcome: Welcome,
) -> impl Future + Send + 'a {
    StagedWelcome::process_resuming_welcome(provider, config, welcome)
}

fn pending_build<'a, P: OpenMlsProvider + Sync>(
    pending: PendingResumingWelcome,
    provider: &'a P,
) -> impl Future + Send + 'a {
    pending.build(provider)
}

fn pending_build_from_reinit<'a, P: OpenMlsProvider + Sync>(
    pending: PendingResumingWelcome,
    provider: &'a P,
    reinit_info: ReInitInfo,
) -> impl Future + Send + 'a {
    pending.build_from_reinit(provider, reinit_info)
}

fn pending_build_from_branch<'a, P: OpenMlsProvider + Sync>(
    pending: PendingResumingWelcome,
    provider: &'a P,
    branch_info: BranchInfo,
) -> impl Future + Send + 'a {
    pending.build_from_branch(provider, branch_info)
}

fn join_builder_build<'a, P: OpenMlsProvider + Sync>(
    builder: JoinBuilder<'a, P>,
) -> impl Future + Send + 'a {
    builder.build()
}

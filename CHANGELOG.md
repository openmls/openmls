# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- [#1688](https://github.com/openmls/openmls/pull/1688): Add `unknown()` getter method to `Extensions`.
- [#1666](https://github.com/openmls/openmls/pull/1666): Add `members()` and `group_context()` getter methods to `StagedWelcome`.
- [#1672](https://github.com/openmls/openmls/pull/1672): Add `epoch()` getter method to `VerifiableGroupInfo`.
- [#1673](https://github.com/openmls/openmls/pull/1673): Return more specific error when attempting to decrypt own messages: `ProcessMessageError::ValidationError(ValidationError::CannotDecryptOwnMessage)`.
- [#1735](https://github.com/openmls/openmls/pull/1735): Add `self_update_with_new_signer` function to `MlsGroup`, as well as a `build_with_new_signer` build option for the `CommitBuilder`. Both can be used to create commits that rotate the creator's signature key.
- [#1673](https://github.com/openmls/openmls/pull/1673): Return more specific error when attemtping to decrypt own messages: `ProcessMessageError::ValidationError(ValidationError::CannotDecryptOwnMessage)`.
- [#1731](https://github.com/openmls/openmls/pull/1731): Add helpers to recover from group state forks, hidden behind the new `fork-resolution` feature flag.

### Fixed

- [#1703](https://github.com/openmls/openmls/pull/1703): Fix a bug where updates proposals were not properly cleared if a remove proposal is present for the same group member.

### Changed

- [#1700](https://github.com/openmls/openmls/pull/1700): During commit processing, OpenMLS will now return a `StorageError` if the storage provider fails while fetching `encryption_epoch_key_pairs`. Previously, it would ignore any error returned by the storage provider and just assume that no keys could be found (which typically lead to an error later during commit processing).

## 0.6.0 (2024-09-04)

### Added

- [#1639](https://github.com/openmls/openmls/pull/1639): Introduce `PublicStorageProvider` trait to independently allow for the storage of `PublicGroup` instances.
- [#1641](https://github.com/openmls/openmls/pull/1641): Extend the `PublicGroup` API with `add_proposal()`, `remove_proposal()`, and `queued_proposals()`.

### Changed

- [#1637](https://github.com/openmls/openmls/pull/1637): Remove `serde` from `MlsGroup`.
- [#1638](https://github.com/openmls/openmls/pull/1638): Remove `serde` from `PublicGroup`. `PublicGroup::load()` becomes public to load a group from the storage provider.
- [#1642](https://github.com/openmls/openmls/pull/1642): `OpenMlsProvider` is no longer required for the `PublicGroup` API. The `PublicGroup` API now uses the `PublicStorageProvider` trait directly. `ProcessMessageError::InvalidSignature` was removed and replaced with `ValidationError::InvalidSignature`.

### Removed

### Fixed

- [#1641](https://github.com/openmls/openmls/pull/1641): Fixed missing storage of queued proposals & clearing of the queued proposals.

## 0.6.0-pre.1 (2024-07-22)

### Added

- [#1629](https://github.com/openmls/openmls/pull/1629): Add `add_members_without_update` function to `MlsGroup` to allow the creation of add-only commits
- [#1506](https://github.com/openmls/openmls/pull/1506): Add `StagedWelcome` and `StagedCoreWelcome` to make joining a group staged in order to inspect the `Welcome` message. This was followed up with PR [#1533](https://github.com/openmls/openmls/pull/1533) to adjust the API.
- [#1516](https://github.com/openmls/openmls/pull/1516): Add `MlsGroup::clear_pending_proposals` to the public API; this allows users to clear a group's internal `ProposalStore`
- [#1565](https://github.com/openmls/openmls/pull/1565): Add new `StorageProvider` trait to the `openmls_traits` crate.

### Changed

- [#1464](https://github.com/openmls/openmls/pull/1464): Add builder pattern for `MlsGroup`; split `MlsGroupJoinConfig` into `MlsGroupCreateConfig` and `MlsGroupJoinConfig`
- [#1473](https://github.com/openmls/openmls/pull/1473): Allow setting group context extensions when building an MlsGroup(Config).
- [#1475](https://github.com/openmls/openmls/pull/1475): Fully process GroupContextExtension proposals
- [#1477](https://github.com/openmls/openmls/pull/1477): Allow setting leaf node extensions and capabilities of the group creator when creating an MlsGroup(Config)
- [#1478](https://github.com/openmls/openmls/pull/1478): Remove explicit functions to set `RequiredCapabilitiesExtension` and `ExternalSendersExtension` when building an MlsGroup(Config) in favor of the more general function to set group context extensions
- [#1479](https://github.com/openmls/openmls/pull/1479): Allow the use of extensions with `ExtensionType::Unknown` in group context, key packages and leaf nodes
- [#1488](https://github.com/openmls/openmls/pull/1488): Allow unknown credentials. Credentials other than the basic credential or X.509 may be used now as long as they are encoded as variable-sized vectors.
- [#1527](https://github.com/openmls/openmls/pull/1527): CredentialType::Unknown is now called CredentialType::Other.
- [#1543](https://github.com/openmls/openmls/pull/1543): PreSharedKeyId.write_to_key_store() no longer requires the cipher suite.
- [#1546](https://github.com/openmls/openmls/pull/1546): Add experimental ciphersuite based on the PQ-secure XWing hybrid KEM (currently supported only by the libcrux crypto provider).
- [#1548](https://github.com/openmls/openmls/pull/1548): CryptoConfig is now replaced by just Ciphersuite.
- [#1542](https://github.com/openmls/openmls/pull/1542): Add support for custom proposals. ProposalType::Unknown is now called ProposalType::Other. Proposal::Unknown is now called Proposal::Other.
- [#1559](https://github.com/openmls/openmls/pull/1559): Remove the `PartialEq` type constraint on the error type of both the `OpenMlsRand` and `OpenMlsKeyStore` traits. Additionally, remove the `Clone` type constraint on the error type of the `OpenMlsRand` trait.
- [#1565](https://github.com/openmls/openmls/pull/1565): Removed `OpenMlsKeyStore` and replace it with a new `StorageProvider` trait in the `openmls_traits` crate.
- [#1606](https://github.com/openmls/openmls/pull/1606): Added additional `LeafNodeParameters` argument to `MlsGroup.self_update()` and `MlsGroup.propose_self_update()` to allow for updating the leaf node with custom parameters. `MlsGroup::join_by_external_commit()` now also takes optional parameters to set the capabilities and the extensions of the LeafNode.
- [#1615](https://github.com/openmls/openmls/pull/1615): Changes the AAD handling. The AAD is no longer persisted and needs to be set before every API call that generates an `MlsMessageOut`. The functions `ProccessedMessage` to accees the AAD has been renamed to `aad()`.

### Fixed

- [#1503](https://github.com/openmls/openmls/pull/1503): Fix `CoreGroup` to check for `LastResortExtension` before deleting leaf encryption keypair from the key store in `new_from_welcome`; this allows the same `KeyPackage` (with last resort extension) to be used to join multiple groups

## 0.5.0 (2023-07-20)

This release has many breaking API changes, a few of them are listed below:

- [#902](https://github.com/openmls/openmls/pull/902): Implement External Add proposal (NewMember sender only) and replace ~~`Sender::NewMember`~~ by `Sender::NewMemberProposal` and `Sender::NewMemberCommit` for external proposals and external commits repectively
- [#903](https://github.com/openmls/openmls/pull/903): Rename MlsGroup's resumptionn_secret to resumption_secret
- [#1058](https://github.com/openmls/openmls/pull/1058): Rename resumption_secret to resumption_psk
- [#900:](https://github.com/openmls/openmls/pull/900) Expose SerializedMlsGroup until issue [#245](https://github.com/openmls/openmls/issues/245) is done
- [#1117](https://github.com/openmls/openmls/pull/1117): Remove signature key indirection
- [#1123](https://github.com/openmls/openmls/pull/1123): Rename ResumptionPsk to ResumptionPskSecret and resumption_psk to resumption_psk_secret
- [#1155](https://github.com/openmls/openmls/pull/1155): MlsGroup.members() now returns an iterator over group members, MlsGroup.merge_staged_commit() no longer returns a Result
- [#1193](https://github.com/openmls/openmls/pull/1193): `MlsGroup.propose_self_update` takes the new `LeafNode` now instead of a `KeyPackage`. `LeafNode.generate` can be used to generate a new `LeafNode` for an update proposal.

## 0.4.1 (2022-06-07)

### Added

- [#873:](https://github.com/openmls/openmls/pull/873) Signature sub-module of the ciphersuite module is now public.
- [#873:](https://github.com/openmls/openmls/pull/873) Signature keys can be imported and exported with the crypto-subtle feature.
- [#873:](https://github.com/openmls/openmls/pull/873) BasicCredentials can now be created from existing signature keys.

### Changed

- [#890:](https://github.com/openmls/openmls/pull/890) Join group by External Commit API does not expect proposal store.

## 0.4.0 (2022-02-28)

- initial release

_Please disregard any previous versions._

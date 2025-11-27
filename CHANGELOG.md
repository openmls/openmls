# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- [#1855](https://github.com/openmls/openmls/pull/1855): Added the `swap_members()` method to `MlsGroup` to replace members in a group, as well as the `WelcomeCommitMessages` and `SwapMembersError` structs.
- [#1868](https://github.com/openmls/openmls/pull/1868): Implemented AppEphemeral functionality as defined in the MLS Extensions draft and replaced the existing AppAck proposal with the AppAck object, which can now be conveyed inside an AppEphemeral proposal. These features are behind the `extensions-draft-08` feature flag.
- [#1874](https://github.com/openmls/openmls/pull/1874): In the `openmls_libcrux_crypto` provider, added AES-GCM support.
- Implemented GREASE (Generate Random Extensions And Sustain Extensibility) support as defined in [RFC 9420 Section 13.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5):
  - Added `Grease(u16)` variants to `ProposalType`, `ExtensionType`, and `CredentialType` enums
  - Added `is_grease()` methods to all GREASE-capable types including `VerifiableCiphersuite`
  - Added `Capabilities::with_grease()` and `CapabilitiesBuilder::with_grease()` convenience methods to inject random GREASE values
  - GREASE values are automatically recognized during deserialization and filtered during validation (treated the same as unknown values)
  - Added comprehensive unit and integration tests for GREASE handling
  - Added user manual documentation for GREASE support


### Fixed
- [#1868](https://github.com/openmls/openmls/pull/1868): The implementation of [valn0311](https://validation.openmls.tech/#valn0311), was updated to check support for all non-default proposals, instead of only checking support for Custom proposals.

### Fixed

- [#1871](https://github.com/openmls/openmls/pull/1871): Fixed a bug where the application export tree (part of the `extensions-draft-08` feature) was not stored properly after group creation.

## 0.7.1 (2025-09-24)

### Added

- [#1801](https://github.com/openmls/openmls/pull/1801): Added `MlsGroup::external_commit_builder`.
- [#1814](https://github.com/openmls/openmls/pull/1814): Allow disabling leaf node lifetime validation in the ratchet tree when joining a group.
  - `StagedWelcome::build_from_welcome`: Alternative to `new_from_welcome` in a builder style that allows disabling lifetime validation of the incoming ratchet tree.
  - `Lifetime::init`: Set explicit lifetimes for a key package.
- [#1801](https://github.com/openmls/openmls/pull/1801): Added `MlsGroup::external_commit_builder`.
- [#1725](https://github.com/openmls/openmls/pull/1725): Added "Safe exporter" as defined in the MLS extension draft behind the `extensions-draft-08` feature flag. Previously serialized groups will derive the exporter upon creating/processing and merging the next commit.
- [#1840](https://github.com/openmls/openmls/pull/1840): Add `has_pending_proposals` getter method to `MlsGroup`.

### Fixed

- [#1846](https://github.com/openmls/openmls/pull/1846): Fix persistence during message processing by properly persisting the secret tree after processing private messages and improve forward secrecy within epochs.

### Changed

- [#1846](https://github.com/openmls/openmls/pull/1846): Processing messages in `MlsGroup` and `PublicGroup` now returns two different error types: `ProcessMessageError` and `PublicProcessMessageError`. `ProcessMessageError` now includes a storage error variant and `PublicProcessMessageError` no longer includes the `GroupStateError` variant.
- [#1851](https://github.com/openmls/openmls/pull/1851): The GroupInfos in Welcome messages no longer contain an ExternalPub extension. This extension is generally useless for new group members, as its only purpose is to facilitate external joins.

### Deprecated

- [#1801](https://github.com/openmls/openmls/pull/1801): Deprecated `MlsGroup::join_by_external_commit` in favor of `MlsGroup::external_commit_builder`.

## 0.7.0 (2025-07-17)

### Added

- [#1661](https://github.com/openmls/openmls/pull/1661): Add `member_at` getter method to `MlsGroup`, `not_before` and `not_after` getter methods to `Lifetime` and `life_time` getter method to `KeyPackage`.
- [#1688](https://github.com/openmls/openmls/pull/1688): Add `unknown()` getter method to `Extensions`.
- [#1666](https://github.com/openmls/openmls/pull/1666): Add `members()` and `group_context()` getter methods to `StagedWelcome`.
- [#1672](https://github.com/openmls/openmls/pull/1672): Add `epoch()` getter method to `VerifiableGroupInfo`.
- [#1673](https://github.com/openmls/openmls/pull/1673): Return more specific error when attempting to decrypt own messages: `ProcessMessageError::ValidationError(ValidationError::CannotDecryptOwnMessage)`.
- [#1675](https://github.com/openmls/openmls/pull/1675): Add `CommitBuilder` that can be used to create commit messages.
- [#1682](https://github.com/openmls/openmls/pull/1682): Add stage provider backed by Sqlite.
- [#1704](https://github.com/openmls/openmls/pull/1704): Add support for SelfRemove proposals as specified in the [MLS extensions draft specification](https://datatracker.ietf.org/doc/html/draft-ietf-mls-extensions).
- [#1735](https://github.com/openmls/openmls/pull/1735): Add `self_update_with_new_signer` function to `MlsGroup`, as well as a `build_with_new_signer` build option for the `CommitBuilder`. Both can be used to create commits that rotate the creator's signature key.
- [#1731](https://github.com/openmls/openmls/pull/1731): Add helpers to recover from group state forks, hidden behind the new `fork-resolution` feature flag.
- [#1750](https://github.com/openmls/openmls/pull/1750): Support add proposals from external senders, using `ExternalProposal::new_add()`.
- [#1766](https://github.com/openmls/openmls/pull/1766): New error variant for commit creation: If a new signer is introduced via `self_update_with_new_signer` and additionally a `CredentialWithKey` is provided via `LeafNodeParameters`, an `InvalidLeafNodeParameters` error is thrown.
- [#1774](https://github.com/openmls/openmls/pull/1774): Add flag to control the return of a `GroupInfo` when building a commit using the `CommitBuilder`. Setting that flag overrides the `use_ratchet_tree_extension` flag in `MlsGroupJoinConfig`.
- [#1784](https://github.com/openmls/openmls/pull/1784): Support group context extension proposals from external senders, using `ExternalProposal::new_group_context_extensions()`.

### Fixed

- [#1657](https://github.com/openmls/openmls/pull/1657): Fix leaf node validation checks.
- [#1667](https://github.com/openmls/openmls/pull/1667): Fix remove proposal validation checks.
- [#1684](https://github.com/openmls/openmls/pull/1684): Fix external init proposal validation checks.
- [#1691](https://github.com/openmls/openmls/pull/1691): Fix the way credentials are looked up when processing messages from previous epochs.
- [#1702](https://github.com/openmls/openmls/pull/1702): Fix multiple validation checks.
- [#1703](https://github.com/openmls/openmls/pull/1703): Fix a bug where updates proposals were not properly cleared if a remove proposal is present for the same group member.
- [#1793](https://github.com/openmls/openmls/pull/1793): Fix a bug where SelfRemoves were not taken into account when computing the sender index of external committers
- [#1763](https://github.com/openmls/openmls/pull/1763): Fix which extension types are considered valid in a leaf node.
- [#1797](https://github.com/openmls/openmls/pull/1797): Fix when tree diff trimming is performed.

### Changed

- [#1661](https://github.com/openmls/openmls/pull/1661): Expose `extensions` getter method on `GroupContextExtensionProposal`.
- [#1669](https://github.com/openmls/openmls/pull/1669): The data in the enum variant `ProtocolMessage::PublicMessage` is wrapped in `Box`.
- [#1700](https://github.com/openmls/openmls/pull/1700): During commit processing, OpenMLS will now return a `StorageError` if the storage provider fails while fetching `encryption_epoch_key_pairs`. Previously, it would ignore any error returned by the storage provider and just assume that no keys could be found (which typically lead to an error later during commit processing).
- [#1762](https://github.com/openmls/openmls/pull/1762): Expose `LeafNodeSource` to allow handling output of `LeafNode::leaf_node_source()`.
- [#1767](https://github.com/openmls/openmls/pull/1767): Return a more specific error when private messages that are too old are processed. The error type has changed from `ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(MessageDecryptionError::AeadError))` to `ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(MessageDecryptoinError::SecretTree(SecretTreeError::TooDistantInThePast)))`.
- [#1786](https://github.com/openmls/openmls/pull/1786): Tighten the requirements for the providers for `MlsGroup::export_secret()` and `MlsGroup::export_group_info()`. The function now only require the `OpenMlsCrypto` provider.
- [#1793](https://github.com/openmls/openmls/pull/1793): Align the proposal types of the SelfRemove an AppAck proposals to version 06 of the MLS extensions draft.

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

## 0.6.0 (2024-07-22)

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

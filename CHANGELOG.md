# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- [#902](https://github.com/openmls/openmls/pull/902): Implement External Add proposal (NewMember sender only) and replace ~~`Sender::NewMember`~~ by `Sender::NewMemberProposal` and `Sender::NewMemberCommit` for external proposals and external commits repectively
- [#903](https://github.com/openmls/openmls/pull/903): Rename MlsGroup's resumptionn_secret to resumption_secret 
- [#1058](https://github.com/openmls/openmls/pull/1058): Rename resumption_secret to resumption_psk
- [#900:](https://github.com/openmls/openmls/pull/900) Expose SerializedMlsGroup until issue [#245](https://github.com/openmls/openmls/issues/245) is done
- [#1117](https://github.com/openmls/openmls/pull/1117): Remove signature key indirection
- [#1123](https://github.com/openmls/openmls/pull/1123): Rename ResumptionPsk to ResumptionPskSecret and resumption_psk to resumption_psk_secret
- [#1155](https://github.com/openmls/openmls/pull/1155): MlsGroup.members() now returns an iterator over group members, MlsGroup.merge_staged_commit() no longer returns a Result

## 0.4.1 (2022-06-07)

### Added
 - [#873:](https://github.com/openmls/openmls/pull/873) Signature sub-module of the ciphersuite module is now public.
 - [#873:](https://github.com/openmls/openmls/pull/873) Signature keys can be imported and exported with the crypto-subtle feature.
 - [#873:](https://github.com/openmls/openmls/pull/873) BasicCredentials can now be created from existing signature keys.

### Changed
 -  [#890:](https://github.com/openmls/openmls/pull/890) Join group by External Commit API does not expect proposal store.

## 0.4.0 (2022-02-28)

* initial release

*Please disregard any previous versions.*

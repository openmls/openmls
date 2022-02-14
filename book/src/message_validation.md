# Message Validation

## Validation steps

- Syntax validation: This should be mostly covered by the decoding
- Semantic validation: Checks to make sure a message is valid in a given context (signature verification, epoch number check, etc.)
- Group policy validation: checks about handshake type, etc.
- AS/policy validation: Checks to see whether syntactically and semantically correct messages should be adopted or dropped (Is a member allowed to add another member? Is a member allowed to remove another member?)

## Detailed list of validation steps

### Semantic validation of message framing

| ValidationStep | Description                                                 | Implemented | Tested | Test File                                            |
| -------------- | ----------------------------------------------------------- | ----------- | ------ | ---------------------------------------------------- |
| `ValSem001`    | Wire format                                                 | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem002`    | Group id                                                    | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem003`    | Epoch                                                       | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem004`    | Sender: Member: check the sender points to a non-blank leaf | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem005`    | Application messages must use ciphertext                    | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem006`    | Ciphertext: decryption needs to work                        | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem007`    | Membership tag presence                                     | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem008`    | Membership tag verification                                 | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem009`    | Confirmation tag presence                                   | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem010`    | Signature verification                                      | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |

### Semantic validation of proposals covered by a Commit

| ValidationStep | Description                                                                                 | Implemented    | Tested         | Test File                                             |
| -------------- | ------------------------------------------------------------------------------------------- | -------------- | -------------- | ----------------------------------------------------- |
| `ValSem100`    | Add Proposal: Identity in proposals must be unique among proposals                          | ✅             | ❌<sup>2</sup> | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem101`    | Add Proposal: Signature public key in proposals must be unique among proposals              | ✅             | ❌<sup>2</sup> | TBD                                                   |
| `ValSem102`    | Add Proposal: HPKE init key in proposals must be unique among proposals                     | ✅             | ❌<sup>2</sup> | TBD                                                   |
| `ValSem103`    | Add Proposal: Identity in proposals must be unique among existing group members             | ✅             | ❌<sup>2</sup> | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem104`    | Add Proposal: Signature public key in proposals must be unique among existing group members | ✅             | ❌             | TBD                                                   |
| `ValSem105`    | Add Proposal: HPKE init key in proposals must be unique among existing group members        | ✅             | ❌             | TBD                                                   |
| `ValSem106`    | Add Proposal: required capabilities                                                         | ❌<sup>1</sup> | ❌             | TBD                                                   |
| `ValSem107`    | Remove Proposal: Removed member must be unique among proposals                              | ✅             | ❌             | TBD                                                   |
| `ValSem108`    | Remove Proposal: Removed member must be an existing group member                            | ✅             | ❌             | TBD                                                   |
| `ValSem109`    | Update Proposal: Identity must be unchanged between existing member and new proposal        | ✅             | ❌             | TBD                                                   |
| `ValSem110`    | Update Proposal: HPKE init key must be unique among existing members                        | ✅             | ❌             | TBD                                                   |
| `ValSem111`    | Update Proposal: The sender of a full Commit must not include own update proposals          | ✅             | ❌             | TBD                                                   |
| `ValSem112`    | Update Proposal: The sender of a standalone update proposal must be of type member          | ✅             | ❌             | TBD                                                   |

<sup>1</sup> Partly implemented, see `TODO`s in `openmls/src/group/core_group/validation.rs`.
<sup>2</sup> Partly implemented, see `TODO`s in `openmls/src/group/core_group/test_proposal_validation.rs`.

### Commit message validation

| ValidationStep | Description                                                                            | Implemented | Tested | Test File |
| -------------- | -------------------------------------------------------------------------------------- | ----------- | ------ | --------- |
| `ValSem200`    | Commit must not cover inline self Remove proposal                                      | ✅          | ❌     | TBD       |
| `ValSem201`    | Path must be present, if Commit is empty or contains proposals other than Add, PreSharedKey or ReInit                                       | ✅          | ❌     | TBD       |
| `ValSem202`    | Path must be the right length                                                          | ✅          | ❌     | TBD       |
| `ValSem203`    | Path secrets must decrypt correctly                                                    | ✅          | ❌     | TBD       |
| `ValSem204`    | Public keys from Path must be verified and match the private keys from the direct path | ✅          | ❌     | TBD       |
| `ValSem205`    | Confirmation tag must be successfully verified                                         | ✅          | ❌     | TBD       |

### External Commit message validation

| ValidationStep | Description                                                                            | Implemented | Tested | Test File                                                    |
| -------------- | -------------------------------------------------------------------------------------- | ----------- | ------ | ------------------------------------------------------------ |
| `ValSem240`    | External Commit must cover at least one inline ExternalInit proposal                   | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |
| `ValSem241`    | External Commit must cover at most one inline ExternalInit proposal                    | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |
| `ValSem242`    | External Commit must not cover any inline Add proposals                                | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |
| `ValSem243`    | External Commit must not cover any inline Update proposals                             | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |
| `ValSem244`    | Identity of inline Remove proposal target and external committer must be the same      | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |
| `ValSem245`    | External Commit must not cover any ExternalInit proposals by reference                 | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |
| `ValSem246`    | External Commit must contain a path                                                    | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |
| `ValSem247`    | External Commit signature must be verified using the credential in the path KeyPackage | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |

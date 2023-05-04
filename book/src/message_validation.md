# Message Validation

OpenMLS implements a variety of syntactical and semantical checks, both when parsing and processing incoming commits and when creating own commits.

## Validation steps

Validation is enforced using Rust's type system. The chain of functions used to process incoming messages is described in the chapter on [Processing incoming messages](user_manual/processing.md), where each function takes a distinct type as input and produces a distinct type as output, thus ensuring that the individual steps can't be skipped. We now detail which step performs which validation checks.

### Syntax validation

Incoming messages in the shape of a byte string can only be deserialized into a `MlsMessageIn` struct. Deserialization ensures that the message is a syntactically correct MLS message, i.e., either a PublicMessage or a PrivateMessage.
Further syntax checks are applied for the latter case once the message is decrypted.

### Semantic validation

Every function in the processing chain performs several semantic validation steps. For a list of these steps, see [below](message_validation.md#detailed-list-of-validation-steps). In the following, we will give a brief overview of which function performs which category of checks.

#### Wire format policy and basic message consistency validation

`MlsMessageIn` struct instances can be passed into the `.parse_message()` function of the `MlsGroup` API, which validates that the message conforms to the group's [wire format policy](user_manual/group_config.md). The function also performs several basic semantic validation steps, such as consistency of Group id, Epoch, and Sender data between message and group (`ValSem002`-`ValSem007`). It also checks if the sender type (e.g., `Member`, `NewMember`, etc.) matches the type of the message (`ValSem112`), as well as the presence of a path in case of an External Commit (`ValSem246`).

`.parse_message()` then returns an `UnverifiedMessage` struct instance, which can in turn be used as input for `.process_unverified_message()`.

#### Message-specific semantic validation

`.process_unverified_message()` performs all other semantic validation steps. In particular, it ensures that ...

- the message is correctly authenticated by a signature (`ValSem010`), membership tag (`ValSem008`), and confirmation tag (`ValSem205`),
- proposals are valid relative to one another and the current group state, e.g., no redundant adds or removes targeting non-members (`ValSem101`-`ValSem112`),
- commits are valid relative to the group state and the proposals it covers (`ValSem200`-`ValSem205`) and
- external commits are valid according to the spec (`ValSem240`-`ValSem245`, `ValSem247` is checked as part of `ValSem010`).

After performing these steps, messages are returned as `ProcessedMessage`s that the application can either use immediately (application messages) or inspect and decide if they find them valid according to the application's policy (proposals and commits). Proposals can then be stored in the proposal queue via `.store_pending_proposal()`, while commits can be merged into the group state via `.merge_staged_commit()`.

## Detailed list of validation steps

The following is a list of the individual semantic validation steps performed by OpenMLS, including the location of the tests.

### Semantic validation of message framing

| ValidationStep | Description                                                 | Implemented | Tested | Test File                                            |
| -------------- | ----------------------------------------------------------- | ----------- | ------ | ---------------------------------------------------- |
| `ValSem002`    | Group id                                                    | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem003`    | Epoch                                                       | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem004`    | Sender: Member: check the sender points to a non-blank leaf | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem005`    | Application messages must use ciphertext                    | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem006`    | Ciphertext: decryption needs to work                        | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem007`    | Membership tag presence                                     | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem008`    | Membership tag verification                                 | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem009`    | Confirmation tag presence                                   | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem010`    | Signature verification                                      | ✅          | ✅     | `openmls/src/group/tests/test_framing_validation.rs` |
| `ValSem011`    | PrivateMessageContent padding must be all-zero              | ✅          | ✅     | `openmls/src/group/tests/test_framing.rs`            |

### Semantic validation of proposals covered by a Commit

| ValidationStep | Description                                                                                 | Implemented | Tested | Test File                                             |
| -------------- | ------------------------------------------------------------------------------------------- | ----------- | ------ | ----------------------------------------------------- |
| `ValSem101`    | Add Proposal: Signature public key in proposals must be unique among proposals & members    | ✅          | ✅     | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem102`    | Add Proposal: Init key in proposals must be unique among proposals                          | ✅          | ✅     | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem103`    | Add Proposal: Encryption key in proposals must be unique among proposals & members          | ✅          | ✅     | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem104`    | Add Proposal: Init key and encryption key must be different                                 | ✅          | ✅     | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem105`    | Add Proposal: Ciphersuite & protocol version must match the group                           | ✅          | ✅     | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem106`    | Add Proposal: required capabilities                                                         | ✅          | ✅     | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem107`    | Remove Proposal: Removed member must be unique among proposals                              | ✅          | ✅     | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem108`    | Remove Proposal: Removed member must be an existing group member                            | ✅          | ✅     | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem109`    | Update Proposal: required capabilities                                                      | ✅          | ✅     | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem110`    | Update Proposal: Encryption key must be unique among proposals & members                    | ✅          | ✅     | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem111`    | Update Proposal: The sender of a full Commit must not include own update proposals          | ✅          | ✅     | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem112`    | Update Proposal: The sender of a standalone update proposal must be of type member          | ✅          | ✅     | `openmls/src/group/tests/test_proposal_validation.rs` |

### Commit message validation

| ValidationStep | Description                                                                            | Implemented | Tested | Test File                                           |
| -------------- | -------------------------------------------------------------------------------------- | ----------- | ------ | --------------------------------------------------- |
| `ValSem200`    | Commit must not cover inline self Remove proposal                                      | ✅          | ✅     | `openmls/src/group/tests/test_commit_validation.rs` |
| `ValSem201`    | Path must be present, if at least one proposal requires a path                         | ✅          | ✅     | `openmls/src/group/tests/test_commit_validation.rs` |
| `ValSem202`    | Path must be the right length                                                          | ✅          | ✅     | `openmls/src/group/tests/test_commit_validation.rs` |
| `ValSem203`    | Path secrets must decrypt correctly                                                    | ✅          | ✅     | `openmls/src/group/tests/test_commit_validation.rs` |
| `ValSem204`    | Public keys from Path must be verified and match the private keys from the direct path | ✅          | ✅     | `openmls/src/group/tests/test_commit_validation.rs` |
| `ValSem205`    | Confirmation tag must be successfully verified                                         | ✅          | ✅     | `openmls/src/group/tests/test_commit_validation.rs` |
| `ValSem206`    | Path leaf node encryption key must be unique among proposals & members                 | ✅          | ✅     | `openmls/src/group/tests/test_commit_validation.rs` |
| `ValSem207`    | Path encryption keys must be unique among proposals & members                          | ✅          | ✅     | `openmls/src/group/tests/test_commit_validation.rs` |

### External Commit message validation

| ValidationStep | Description                                                                                       | Implemented | Tested | Test File                                                    |
| -------------- | ------------------------------------------------------------------------------------------------- | ----------- | ------ | ------------------------------------------------------------ |
| `ValSem240`    | External Commit must cover at least one inline ExternalInit proposal                              | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |
| `ValSem241`    | External Commit must cover at most one inline ExternalInit proposal                               | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |
| `ValSem242`    | External Commit must only cover inline proposal in allowlist (ExternalInit, Remove, PreSharedKey) | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |
| `ValSem243`    | Identity of inline Remove proposal target and external committer must be the same                 | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |
| `ValSem244`    | External Commit must not include any proposals by reference                                       | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |
| `ValSem245`    | External Commit must contain a path                                                               | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |
| `ValSem246`    | External Commit signature must be verified using the credential in the path KeyPackage            | ✅          | ✅     | `openmls/src/group/tests/test_external_commit_validation.rs` |

### Ratchet tree validation

| ValidationStep | Description                                                | Implemented | Tested | Test File                     |
|----------------|------------------------------------------------------------|-------------|--------|-------------------------------|
| `ValSem300`    | Exported ratchet trees must not have trailing blank nodes. | Yes         | Yes    | `openmls/src/treesync/mod.rs` |

### PSK Validation

| ValidationStep | Description                                                                                                            | Implemented | Tested | Test File                                             |
|----------------|------------------------------------------------------------------------------------------------------------------------|-------------|--------|-------------------------------------------------------|
| `ValSem400`    | The application SHOULD specify an upper limit on the number of past epochs for which the resumption_psk may be stored. | ❌           | ❌      | https://github.com/openmls/openmls/issues/1122        |
| `ValSem401`    | The nonce of a PreSharedKeyID must have length KDF.Nh.                                                                 | ✅           | ✅      | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem402`    | PSK in proposal must be of type Resumption (with usage Application) or External.                                       | ✅           | ✅      | `openmls/src/group/tests/test_proposal_validation.rs` |
| `ValSem403`    | Proposal list must not contain multiple PreSharedKey proposals that reference the same PreSharedKeyID.                 | ✅           | ❌      | https://github.com/openmls/openmls/issues/1335        |

# Forward Secrecy

OpenMLS drops key material immediately after a given
key is no longer required by the protocol to achieve forward secrecy. For some keys, this is simple, as they
are used only once, and there is no need to store them for later use. However,
for other keys, the time of deletion is a result of a trade-off between
functionality and forward secrecy. For example, it can be desirable to keep the
`SecretTree` of past epochs for a while to allow decryption of straggling
application messages sent in previous epochs.

In this chapter, we detail how we achieve forward secrecy for the different types of keys used throughout MLS.

## Ratchet Tree

The ratchet tree contains the secret key material of the client's leaf, as well
(potentially) that of nodes in its direct path. The secrets in the tree are
changed in the same way as the tree itself: via the merge of a previously
prepared diff.

### Commit Creation

Upon the creation of a commit, any fresh key material introduced by the
committer is stored in the diff. It exists alongside the key material of the
ratchet tree before the commit until the client merges the diff, upon which the
key material in the original ratchet tree is dropped.

Because the client cannot know if the commit it creates will conflict with another commit created by another client
for the same epoch, it MUST wait for the acknowledgement from the Delivery Service before merging the diff and dropping
the previous ratchet tree.

### Commit Processing

Upon receiving a commit from another group member, the client processes the
commit until they have a `StagedCommit`, which in turn contains a ratchet tree
diff. The diff contains any potential key material they decrypted from the
commit and any potential key material that was introduced to the tree as
part of an update that someone else committed for them. The key material in the original ratchet tree is dropped as soon as the `StagedCommit` (and thus the diff) is merged into the tree.

### Sending application messages

When an application message is created, the corresponding encryption key is derived from the `SecretTree` and immediately discarded after encrypting the message to guarantee the best possible Forward Secrecy. This means that the message author cannot decrypt application messages. If access to the message's content is required after creating the message, a copy of the plaintext message should be kept by the application.

### Receiving encrypted messages

When an encrypted message is received, the corresponding decryption key is derived from the `SecretTree`. By default, the key material is discarded immediately after decryption for the best possible Forward Secrecy. In some cases, the Delivery Service cannot guarantee reliable operation, and applications need to be more tolerant to accommodate this – at the expense of Forward Secrecy.

OpenMLS can address 3 scenarios:

- The Delivery Service cannot guarantee that application messages from one epoch are sent before the beginning of the next epoch. To address this, applications can configure their groups to keep the necessary key material around for past epochs by setting the `max_past_epochs` field in the `MlsGroupConfig` to the desired number of epochs.

- The Delivery Service cannot guarantee that application messages will arrive in order within the same epoch. To address this, applications can configure the `out_of_order_tolerance` parameter of the `SenderRatchetConfiguration`. The configuration can be set as the `sender_ratchet_configuration` parameter of the `MlsGroupConfig`.

- The Delivery Service cannot guarantee that application messages won't be dropped within the same epoch. To address this, applications can configure the `maximum_forward_distance` parameter of the `SenderRatchetConfiguration`. The configuration can be set as the `sender_ratchet_configuration` parameter of the `MlsGroupConfig`.

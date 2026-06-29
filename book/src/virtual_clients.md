# Virtual Clients (draft)

OpenMLS has experimental support for virtual clients, following
[draft-ietf-mls-virtual-clients](https://github.com/mlswg/mls-virtual-clients).
A virtual client lets several real clients act jointly as a single member of an
MLS group. The group sees one leaf. Behind that leaf, any of the cooperating
clients can speak for it.

> **This feature is a moving draft.** Everything described here lives behind the
> `virtual-clients-draft` cargo feature and is not part of the stable API. Wire
> formats, storage layout, and method names can change between releases with no
> migration path. Do not assume interoperability with other implementations.

## The idea

The clients that cooperate to act as one member are called *emulator clients*.
The member they present to the outside world is the *virtual client*. The
emulator clients coordinate through a separate MLS group of their own, the
*emulation group*, while the virtual client appears as a single leaf in one or
more *higher-level groups*.

The point of the construction is that the emulator clients never share raw
private keys with each other. Instead they all derive the same key material
from the emulation group's epoch secrets, so any of them can produce a commit,
an application message, or a KeyPackage on behalf of the virtual client, and any
other can reproduce the matching private state. To the higher-level group, the
result is indistinguishable from an ordinary single member.

Two mechanisms make this work without secret sharing:

- A *Virtual Client Operation Secret Tree*, derived from the emulation group's
  epoch through the Safe Exporter. It has the same shape as an MLS secret tree.
  Each emulator client's leaf carries one ratchet per operation type
  (`KeyPackage`, `LeafNode`, `Application`). Advancing a ratchet yields an
  operation secret, and from that secret each client derives the leaf encryption
  key, init key, signature key seed, and path secrets for a single operation.
- A `DerivationInfo` component embedded in every leaf node the virtual client
  produces. It carries, encrypted, the emulation epoch's `leaf_index` and the
  `generation` that was used. A sibling emulator client reads it, derives the
  same operation secret from the operation tree at that position, and so
  reconstructs the private keys for the leaf without ever receiving them.

Each emulation epoch also produces a `generation_id_secret` (so the Delivery
Service can detect when two emulator clients pick the same ratchet generation)
and a `reuse_guard_secret` (so two emulator clients never reuse a key and nonce
pair while still looking random to outside observers).

## Enabling the feature

Add the feature to your dependency on `openmls`:

```toml
[dependencies]
openmls = { version = "...", features = ["virtual-clients-draft"] }
```

Storage backends carry their own `virtual-clients-draft` feature, which the
`openmls` feature turns on for them. For tests that exercise the storage
provider trait methods directly, enable
`virtual-clients-draft-test-dependencies` on the `openmls` crate.

## Leaf requirements

Every leaf that carries virtual-client material must declare support for the
`AppDataDictionary` extension and list the VC component id in its
`AppComponents` entry. Build the capabilities and leaf-node extensions
accordingly when you create or join an emulation group or a higher-level group:

```rust,no_run,noplayground
use openmls::components::vc_derivation_info::VC_COMPONENT_ID;
use openmls::extensions::{
    AppDataDictionary, AppDataDictionaryExtension, Extension, ExtensionType, Extensions,
};
use openmls::prelude::Capabilities;
use tls_codec::Serialize as _;

let capabilities = Capabilities::builder()
    .extensions(vec![ExtensionType::AppDataDictionary])
    .build();

let supported_components: Vec<u16> = vec![VC_COMPONENT_ID];
let app_components_body = supported_components.tls_serialize_detached().unwrap();
let mut dictionary = AppDataDictionary::new();
// ComponentType::AppComponents == 1
dictionary.insert(1, app_components_body);
let leaf_extensions = Extensions::from_vec(vec![Extension::AppDataDictionary(
    AppDataDictionaryExtension::new(dictionary),
)])
.unwrap();
```

Pass `capabilities` and `leaf_extensions` to `MlsGroupCreateConfig::builder()`
through `.capabilities(...)` and `.with_leaf_node_extensions(...)`, and to the
`KeyPackage::builder()` through `.leaf_node_capabilities(...)` and
`.leaf_node_extensions(...)`.

## Registering an emulation epoch

An emulation group is an ordinary `MlsGroup`. Each emulator client maintains its
own copy. To make a given epoch usable for virtual-client operations, every
emulator client registers it. Registration sources the root secret from the
group's `safe_export_secret(VC_COMPONENT_ID)`, builds the operation secret tree,
and persists the per-epoch state, returning an `EpochId`:

```rust,no_run,noplayground
let epoch_id = emulator_group
    .register_vc_emulation_epoch(provider.crypto(), provider.storage())?;
```

Because the secret comes from the Safe Exporter, all emulator clients that are
at the same emulation epoch derive the **same** `EpochId` and the same operation
tree. The `EpochId` is the key under which all per-epoch state is stored, and it
is the value embedded in the leaves the virtual client produces. Register the
epoch on every emulator client before any of them issues an operation against
it. A missed registration is not recoverable, because the Safe Exporter state of
a past emulation epoch is not retained.

## Committing in a higher-level group

To commit on behalf of the virtual client, set `vc_emulation` on the commit
builder, passing the `EpochId`. The builder allocates the next `LeafNode`
operation generation, derives the new leaf's encryption key and the first path
secret from it, and embeds the encrypted `DerivationInfo` in the leaf:

```rust,no_run,noplayground
let bundle = main_group
    .commit_builder()
    .vc_emulation(provider.crypto(), provider.storage(), epoch_id)?
    .load_psks(provider.storage())?
    .build(provider.rand(), provider.crypto(), &vc_signer, |_| true)?
    .stage_commit(provider)?;

main_group.merge_pending_commit(provider)?;
let commit = bundle.into_commit();
```

Allocation advances the operation ratchet and persists it immediately, which is
a deliberate exception to the usual rule that nothing is written before a commit
is staged. The spec requires that a generation is never used for more than one
operation, so the generation is consumed at allocation time. If you discard the
builder, or the Delivery Service rejects the commit, the generation stays
burned. `clear_pending_commit` does not roll the ratchet back. A burned
generation is harmless, because sibling ratchets skip over it and retain the
skipped secret.

## Processing a sibling's commit

`process_message` detects the `DerivationInfo` component in a committer's leaf.
If the committer's leaf index is the receiver's own leaf, the commit came from a
sibling emulator client. The receiver loads the emulation epoch state, decrypts
the derivation info, derives the same operation secret positionally from the
operation tree (advancing or skipping the sibling's ratchet as needed),
reconstructs the path secrets, and processes the commit as if it had created it:

```rust,no_run,noplayground
let processed = receiver_group
    .process_message(provider, commit.into_protocol_message().unwrap())?;
```

A receiver that does not hold the referenced emulation epoch state, for example
a real member of the higher-level group that is not an emulator client,
processes the commit as an ordinary commit. The permissive handling is framed
around the receiver, who may not be a sibling. The sender is always a sibling.

When a commit that carries a `DerivationInfo` is merged, the client stores a
binding from `(GroupId, GroupEpoch)` to the `EpochId` from that leaf. The
binding is keyed by epoch, not just group id, because a delayed application
message from an earlier higher-level epoch must be processed with the emulation
epoch that was active then. Bindings follow the same retention window as the
message secrets store.

## Application messages

With the feature enabled, the single-shot `create_message` is replaced by a two
step send flow, because two emulator clients can race for the same ratchet
generation.

`create_unconfirmed_message` encrypts the payload, retains the key and nonce,
and returns the message together with the ratchet `generation` and a
`generation_id`:

```rust,no_run,noplayground
let unconfirmed = main_group
    .create_unconfirmed_message(provider, &vc_signer, b"hello")?;

// Attach unconfirmed.generation_id when fanning out, so the Delivery Service
// can detect a generation collision with a sibling.
send_to_delivery_service(unconfirmed.message, unconfirmed.generation_id);
```

The `generation_id` is `Some` on a group bound to an emulation epoch and `None`
otherwise. It is derived from `generation_id_secret` over the spec's
`PrivateMessageContext`. The reuse guard is computed rather than sampled: the
client resolves the emulation epoch through the `(GroupId, GroupEpoch)` binding,
picks a value congruent to its emulation leaf index modulo the emulation group
size, and encrypts it with a small-space PRP keyed from `reuse_guard_secret`.

Once the Delivery Service accepts the message, drop the retained key:

```rust,no_run,noplayground
main_group.confirm_message(provider.storage(), unconfirmed.generation)?;
```

If the Delivery Service reports a collision, the sibling won that generation.
Process the winning message through `process_message`, which has a carve-out for
messages arriving from the receiver's own leaf. Decrypting the winner consumes
the retained key for that generation, so no explicit cleanup is needed. Then
call `create_unconfirmed_message` again to re-encrypt from the ratchet head.
There is no explicit discard call. A retained unconfirmed key is, from the
receiving side, the same as a skipped-generation key. It is cleaned up by
`confirm_message`, by decrypting a sibling's message at that generation, or by
aging out under bounded retention.

On the receiving side, `process_message` inverts the reuse guard PRP and
recovers the sender's leaf index in the emulation group, so the application can
attribute the message to a specific emulator client:

```rust,no_run,noplayground
let processed = receiver_group
    .process_message(provider, message.into_protocol_message().unwrap())?;

if let Some(emulation_leaf) = processed.emulator_sender_leaf_index() {
    // The message came from this emulator client of the virtual client.
}
```

`emulator_sender_leaf_index()` returns `None` for messages that did not come
from a virtual client, or on a group with no emulation binding.

## KeyPackages and Welcomes

A virtual client publishes KeyPackages so that a sibling can later recover the
private keys and join a higher-level group on its behalf. KeyPackages are built
in batches, because one `key_package` operation generation seeds a whole batch.

Build the batch with `build_vc_batch`. It allocates one `key_package`
generation, derives a per-KeyPackage seed for each index, embeds a
`DerivationInfo` in every leaf, writes each bundle to local storage, and returns
the `generation` plus one `(KeyPackageBundle, KeyPackageInfo)` per KeyPackage:

```rust,no_run,noplayground
let batch = KeyPackage::builder()
    .leaf_node_capabilities(capabilities)
    .leaf_node_extensions(leaf_extensions)?
    .build_vc_batch(
        ciphersuite,
        provider,
        &vc_signer,
        vc_credential,
        epoch_id.clone(),
        count, // number of KeyPackages, must be > 0
    )?;
```

The operation tree is advanced in memory and persisted only after every
KeyPackage is built, so a build failure consumes no generation. A `count` of `0`
returns `EmptyBatch` before any state is touched.

Assemble the upload the virtual client hands to its sibling from the batch
generation and its `KeyPackageInfo`s. OpenMLS fills the emulation `leaf_index`
from the stored epoch state:

```rust,no_run,noplayground
use openmls::components::vc_derivation_info::assemble_vc_key_package_upload;

let infos = batch
    .key_packages
    .iter()
    .map(|(_bundle, info)| info.clone())
    .collect();

let upload = assemble_vc_key_package_upload(
    provider.storage(),
    epoch_id,
    batch.generation,
    infos,
)?;
```

How the upload reaches the sibling emulator clients is up to the application. It
must reach them before the KeyPackages are offered to anyone else. On receipt, a
sibling calls `process_vc_key_package_upload`, which derives the init and leaf
encryption private keys for each listed reference and stores them keyed by
`KeyPackageRef`:

```rust,no_run,noplayground
use openmls::components::vc_derivation_info::process_vc_key_package_upload;

process_vc_key_package_upload(provider, &upload)?;
```

After that, Welcome processing runs through the ordinary `ProcessedWelcome` and
`StagedWelcome` entry points unchanged. The lookup by `KeyPackageRef` finds
either a locally generated `KeyPackageBundle` or the derived virtual-client key
material. Eager derivation costs no forward secrecy: the derived private keys
take the place of any retained operation secret and have to be kept until the
KeyPackage is no longer live anyway.

## What is not implemented yet

The implementation tracks the draft but does not yet cover everything in it:

- Handshake messages framed as PrivateMessages in higher-level groups do not
  carry a generation ID or computed reuse guard. Only application messages do.
- Onboarding a new emulator client by state transfer (the draft's
  `NewEmulatorClientState`, Variant A) is not implemented. Onboarding through an
  external commit (Variant B) works, because it is an application-orchestrated
  sequence of operations the code already supports.
- VC Update proposals are not implemented. Only commits and external commits
  emit virtual-client leaves.
- The `VirtualClientAction` coordination channel over SafeAAD (the draft's
  `external_join` and `key_package_upload` actions) is not implemented. The
  transport of the KeyPackage upload is left entirely to the application.
- There is no convenience layer for marking a group as an emulation group on its
  config and deriving epoch secrets automatically. Registration is the manual
  `register_vc_emulation_epoch` call shown above.
- Per-epoch state for dead emulation epochs is not garbage collected
  automatically.

Refer to the [virtual clients draft](https://github.com/mlswg/mls-virtual-clients)
for the authoritative protocol description.

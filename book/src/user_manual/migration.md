# Migrating from a previous version

OpenMLS supports migrating between storage versions through a serialization bridge:
a group, together with all the group-associated data it owns, is exported with the
*previous* version, serialized to a self-describing format (such as JSON), and
imported into the *current* version, which writes it back out in the new storage format.

This requires the `migration-export` feature on the previous version's `openmls`
crate and the `migration-import` feature on the current one.

## When to use this

The main use case is a version upgrade whose storage format changed, in particular,
migrating data serialized using `0.7.4` or `0.8.1` into `0.8.2`, when a
**self-describing** format (such as JSON) rather than a **non-self-describing**
one (such as `postcard`) should be used. Non-self-describing formats
are no longer supported, and cannot tolerate changes to a type's fields: adding,
removing, or renaming a field silently shifts the layout and corrupts existing
data. Bridging the old state through a self-describing format, matching fields by
name (and, where needed, `#[serde(alias)]` / `#[serde(default)]`), is what makes
the version jump safe.

The same helper also covers **enabling a feature flag** that adds or changes a
type's serialized representation (for example turning on `extensions-draft`): the
old data is re-bridged and the newly feature-gated fields are populated with their
defaults.

> **The migration target must use a self-describing format** (such as JSON), even
> when the source did not: a current-version group cannot currently be stored in or loaded
> from a non-self-describing format like postcard. Migrating *in place while
> staying on a non-self-describing format* is therefore not supported — a
> self-describing format should be used for the current-version store.

## Prerequisites

<!-- TODO: document the concrete dependency declarations for the previous-version
bridge crates + `migration_export` feature -->.

- Both the previous-version and the current-version OpenMLS crates in your
  dependency tree (e.g. `openmls_0_8_1` and `openmls`), the previous version with
  its `migration-export` feature and the current one with `migration-import`.
- A storage provider for each version: one implementing the *previous* version's
  storage traits (holding the existing data), and one implementing the *current*
  version's storage traits (receiving the migrated data). A single backing store
  can serve both roles if it implements both trait versions.

## Performing the migration

For each group, export it with the previous version's API, bridge the bundle
through `serde`, and store it with the current version:

```rust,no_run,noplayground
{{#include ../../../compat_tests/tests/test_migration.rs:migration}}
```

Then run this once per group. Afterwards the group can be loaded normally with
the current-version `MlsGroup::load`.

Perform the migration (together with any cleanup of the old data, see below)
within a single storage transaction, so that an interruption cannot leave a group
partially migrated. If the migration is aborted or the process crashes part-way
through, the transaction rolls back and the group can be migrated again from its
original state.

Group state that contains queued (uncommitted) proposals or a pending, not yet
merged commit is migrated as well — both are preserved.

## Cleaning up the old data

Whether the old data needs to be removed depends on how you migrate:

- **Into a fresh or separate store:** simply discard the old store once every
  group has been migrated; there is nothing else to clean up.
- **In-place, when the storage keys change:** moving between a non-self-describing
  and a self-describing format generally changes how storage keys are encoded, so
  the new entries are written under *new* keys and the old entries remain behind.
  Remove them by loading each group with the previous version's API and calling
  its `MlsGroup::delete` on the old storage provider.
- **In-place, when the storage keys are unchanged** (e.g. toggling a feature flag,
  or a same-format update): the import overwrites the existing entries, so no
  separate cleanup is needed — and deleting would remove the freshly migrated
  data.

## What is not migrated

The migration bundle carries the group and all group-associated data OpenMLS owns
— group state, queued proposals, a pending commit, and the group's encryption key
pairs. Application-managed material that OpenMLS does *not* own — signature key
pairs, PSKs, and published key packages — is not group-scoped and is not part of
the bundle. If you keep it in the same store, migrate it separately with the same
read → bridge → write pattern over the ids your application tracks.

### Migrating application-managed material

All three cases below use only existing public APIs. Each takes a value (or its
id) from the previous version and produces the current-version equivalent in the
new store.

**Signature key pairs** bridge directly through serde:

```rust,no_run,noplayground
{{#include ../../../compat_tests/tests/test_migration.rs:migrate_signature_key_pair}}
```

**Published key packages** are read from the old store by the hash reference your
application tracks, bridged, and written to the new store:

```rust,no_run,noplayground
{{#include ../../../compat_tests/tests/test_migration.rs:migrate_key_package}}
```

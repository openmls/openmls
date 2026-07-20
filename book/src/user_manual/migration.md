# Migrating from a previous version

OpenMLS supports migrating between storage versions through a serialization bridge:
a group, together with all the group-associated data it owns, is exported with the
previous version of the library, serialized into `serde_json`, and
then imported into the *current* version of the library, which writes it back out in the new storage format.

This migration approach requires the `migration-export` feature on the previous version's `openmls`
crate and the `migration-import` feature on the current one.

## When to use this

The main migration use case is upgrading between `openmls` versions with incompatible
storage formats.
This approach can be used to migrate data serialized using `0.7.0`, `0.7.4` or `0.8.1` 
into the format used by `0.9.0`, which requires a self-describing format. 
As of this version, non-self-describing formats are no longer supported; adding,
removing, or renaming a field silently shifts the layout and corrupts existing
data.

> **The migration target must use a self-describing format** (such as JSON), even
> when the source did not: a current-version group cannot currently be stored in or loaded
> from a non-self-describing format like postcard. Migrating *in place while
> staying on a non-self-describing format* is therefore not supported — a
> self-describing format should be used for the current-version store.

## Prerequisites

<!-- TODO: document the concrete dependency declarations for the previous-version
bridge crates + `migration_export` feature -->.

- Both the previous-version and the current-version OpenMLS crates should be in the
  dependency tree (e.g. `openmls_0_8_1` and `openmls`), the previous version with
  its `migration-export` feature, and the current one with `migration-import` enabled.
- A storage provider for each version: one implementing the *previous* version's
  storage traits (holding the existing data), and one implementing the *current*
  version's storage traits (receiving the migrated data).

## Requirements

The following requirements must be satisfied:

- **Quiescence.** The migration must run while the MLS state is at rest: no
  message is mid-processing, and nothing else — no other thread or process —
  touches the store until the migration completes. Group state that is
  legitimately pending at rest is fine: queued (uncommitted) proposals and a
  pending, not yet merged commit are both migrated and preserved.
- **Atomicity.** Perform the migration (together with any cleanup of the old
  data, see below) within a single storage transaction, so that an interruption
  cannot leave a group partially migrated. The transaction comes from the
  *backing store* (e.g. SQLite) — the OpenMLS storage traits have no transaction
  API. Alternatives: per-group transactions with a per-group
  “migrated” marker (allowing an interrupted migration to resume), or —
  recommended — migrating into a **fresh store**, verifying, then
  atomically swapping it in and discarding the old one.
- **Interruption tolerance.** Import is a *replace*, not an append, so it is
  idempotent: re-running the migration after a crash is safe as long as the old
  data is still intact.

**Prefer a fresh store over migrating in place.** A transaction only protects
against interruption, not against a migration defect, and an in-place
migration that overwrites the same keys destroys the source data as it writes:
once the transaction commits there is nothing left to verify against and
nothing to roll back to. In-place with changed keys keeps the old entries
longer, but its cleanup is item-wise deletion of key material in a live store,
where anything missed lingers silently. Migrating into a fresh store keeps the
source intact for verification and rollback, tolerates interruption even
without a transactional store, and makes cleanup a simple discard. If the
store itself cannot be swapped (e.g. it shares a database with other
application data), migrate into a fresh table set or namespace within it and
swap that instead of overwriting.

## Performing the migration

For each group, export it with the previous version's API, bridge the bundle
through `serde`, and store it with the current version:

```rust,no_run,noplayground
{{#include ../../../compat_tests/tests/test_migration.rs:migration}}
```

Then run this once per group. Afterwards the group can be loaded normally with
the current-version `MlsGroup::load`.

Run this within a single storage transaction and observe the invariants in
[Requirements](#requirements) above; queued proposals and a pending commit are
migrated along with the rest of the group state.

## What is not migrated

The migration bundle carries the group and all group-associated data OpenMLS owns
— group state, queued proposals, a pending commit, and the group's encryption key
pairs. Application-managed material that OpenMLS does *not* own — signature key
pairs, PSKs, and published key packages — is not group-scoped and is not part of
the bundle. If you keep it in the same store, migrate it separately with the same
read → bridge → write pattern over the ids your application tracks.

### Migrating data that is managed by the application

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

## Recommendations

### Verifying the migration

Before relying on the migrated store (and before any cleanup), load each group
with the current-version `MlsGroup::load` and sanity-check what the application
expects — at minimum the epoch and the member list. If any group fails to export,
bridge, or load, fail closed: abort the migration, keep the old data, and report
the error, rather than continuing with a partially migrated store.

Store a **schema-version marker** alongside the data so the migration runs
exactly once and the application always knows which format the store holds.

## Cleaning up the old data

Whether the old data needs to be removed depends on how you migrate:

- **Into a fresh or separate store:** simply discard the old store once every
  group has been migrated; there is nothing else to clean up.
- **In-place, when the storage keys change:** moving between a non-self-describing
  and a self-describing format generally changes how storage keys are encoded, so
  the new entries are written under *new* keys and the old entries remain behind.
  Remove them by loading each group with the previous version’s API and calling
  its `MlsGroup::delete` on the old storage provider.
- **In-place, when the storage keys are unchanged** (e.g. toggling a feature flag,
  or a same-format update): the import overwrites the existing entries, so no
  separate cleanup is needed — and deleting would remove the freshly migrated
  data.

**Rolling back to retained old data is only safe before first use.** Once a
migrated group sends or processes anything, the old store holds stale ratchet
state: reverting to it forks the group and risks key reuse. If you keep the old
store as a rollback path, that path expires the moment the group is used.

## Running the migration in an application

Requirements and brief best practices for shipping this in a deployed
application, particularly one with local storage on end-user devices (e.g. a
mobile app):

- **Run at startup, before any MLS traffic.** Application startup is the natural
  quiescence point: gate all message processing and outbound operations on the
  migration having completed (checked via the schema-version marker). A separate
  process buys nothing — the requirement is exclusive access to the store, not
  process isolation.
- **Watch for other processes touching the store.** For example, an iOS
  Notification Service Extension that decrypts MLS messages runs in a different
  process and can wake on a push mid-migration; hold a cross-process lock or gate
  it on the schema-version marker.
- **Expect interruption.** Mobile operating systems terminate apps freely, so
  the migration can be cut short at any point — the transactional, idempotent
  design above makes this safe. Run the migration off the main thread, and prefer the
  per-group-marker shape if group counts are large enough to make resumability
  matter.
- **Check disk space.** Migrating into a fresh store temporarily roughly doubles
  the storage footprint.
- **Plan the release lifecycle.** One “migration release” of the application
  ships both OpenMLS versions; keep the migration path for a defined support
  window (an enforced minimum client version, telemetry on remaining un-migrated
  installs, or a stated time period). The release that finally removes it must
  keep the schema-version marker check and ship a fallback — resetting the local
  MLS state and rejoining groups — because users can jump arbitrary version gaps
  when updating.
- **Binary size is usually a non-issue.** Only code reachable from
  `export_for_migration` is linked from the previous version — storage reads and
  serde impls, no crypto backend, no protocol machinery — and the linker strips
  the rest. Measure (e.g. with `cargo bloat`) before optimizing, and do **not**
  hand-prune or `#[cfg]`strip the old crate: its fidelity to the released
  serialization code is exactly what makes the migration correct.

### Key material hygiene

- Never log or upload the bundle. The serialized `GroupMigrationBundle` contains private encryption keys in plaintext JSON. Error reports and
  diagnostics must not include the bundle, value diffs, or deserialization error messages that embed the offending content — and the bundle should stay
  in memory, never written to a temp file for debugging.

- Create the fresh store with the same protections as the old. Same at-rest encryption (e.g. SQLCipher key), and on desktop, restrictive file
  permissions set before data is written, not fixed up after.

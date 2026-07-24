# Compatibility tests for `openmls`

This crate tests compatibility with previous `openmls` versions:

- **Group migration** from a previous version (`0.7.4` or `0.8.1`) to the current
  one: the group is exported with the previous version into a `GroupMigrationBundle`,
  bridged through `serde_json`, and imported with `GroupMigrationBundle::store` in
  the current storage format. Tested with and without `extensions-draft` and
  `virtual-clients-draft`, and across a feature-flag toggle (source *without* a
  draft feature, target *with* it). See [`MIGRATION_DESIGN.md`](./MIGRATION_DESIGN.md).
- **Storage-format compatibility** (storage tag stability) for `openmls=0.7.1`,
  `openmls=0.8.1`, and `openmls=0.8.1` with the `extensions-draft` feature.

## Usage

Run the full matrix with [`test.sh`](./test.sh), or individual combinations:

```
# Group migration (previous version -> current)
cargo test -F storage_migration_0_8
cargo test -F storage_migration_0_8,extensions-draft
cargo test -F storage_migration_0_8,extensions-draft,virtual-clients-draft
cargo test -F storage_migration_0_7
cargo test -F storage_migration_0_7,extensions-draft
cargo test -F storage_migration_0_7,extensions-draft,virtual-clients-draft

# Migration across a feature-flag toggle (source without extensions-draft, target with)
cargo test -F storage_migration_0_8,extensions-draft-current
cargo test -F storage_migration_0_7,extensions-draft-current

# Storage-format compatibility (storage tag stability)
cargo test -F compat_0_7_1
cargo test -F compat_0_8_1
cargo test -F compat_0_8_1,extensions-draft
```

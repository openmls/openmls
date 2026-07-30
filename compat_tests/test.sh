#!/usr/bin/env bash
# Fail on the first failing command (and on unset vars / failed pipes) so a
# broken feature combination actually fails CI instead of being swallowed.
set -euo pipefail

# Run from this crate's directory so feature flags resolve against this package
# regardless of the caller's working directory.
cd "$(dirname "$0")"

# Group migration (previous version -> current), with and without extensions-draft.
#
# NOTE: the `virtual-clients-draft` combos are commented out because the migration
# tests cannot build with them: enabling `openmls/virtual-clients-draft` gates
# `MlsGroup::self_update` / `add_members` behind `test-utils` (which these tests do
# not enable), so the operability tests fail to compile. As a result the vc-draft
# storage-provider code (including `registered_vc_emulation_epoch`) is not covered
# here; re-enable these lines once the tests no longer need those gated APIs.
cargo test -F storage_migration_0_8
cargo test -F storage_migration_0_8,extensions-draft
# cargo test -F storage_migration_0_8,extensions-draft,virtual-clients-draft
cargo test -F storage_migration_0_7
cargo test -F storage_migration_0_7,extensions-draft
# cargo test -F storage_migration_0_7,extensions-draft,virtual-clients-draft

# Migration across a feature-flag toggle: source WITHOUT extensions-draft, target
# WITH it (`extensions-draft-current` only). Exercises the new fields defaulting on
# import (see test_migration_enabling_extensions_draft).
cargo test -F storage_migration_0_8,extensions-draft-current
cargo test -F storage_migration_0_7,extensions-draft-current

# Storage-format compatibility (storage tag stability) for each supported
# previous version, including the 0.8.1 + extensions-draft combination.
cargo test -F compat_0_7_1
cargo test -F compat_0_8_1
cargo test -F compat_0_8_1,extensions-draft

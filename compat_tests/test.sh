#!/usr/bin/env bash
set -euo pipefail

# Change the working directory to the directory containing this script
# NOTE: this ensures that the `git restore Cargo.lock` command below
# will only affect the Cargo.lock in this directory.
cd "$(dirname "$0")"

# This script restores Cargo.lock to the original version on exit.
# Don't run if there are uncommitted Cargo.lock changes,
# since they would be discarded by that restore.
git diff --quiet Cargo.lock || {
    echo "error: Cargo.lock has local changes; commit or stash them first" >&2
    exit 1
}
trap 'git restore Cargo.lock' EXIT

# Run storage tag stability tests for openmls=0.8.1
cargo test -F compat_0_8_1 --test test_storage_tag_stability
cargo test -F compat_0_8_1_extensions --test test_storage_tag_stability

# Run the tests once per 0.7.x patch version of `openmls`.
# Only one of these versions can be resolved at a time,
# so use `cargo update --precise` to pin each one.
for version in 0.7.0 0.7.1 0.7.2 0.7.3 0.7.4; do
    cargo update --package openmls@0.7 --precise "$version"

    # storage tag stability tests
    cargo test -F compat_0_7 --test test_storage_tag_stability

    # storage migration tests
    cargo test -F storage_migration --test test_storage_migration
    cargo test -F storage_migration,extensions-draft --test test_storage_migration --test storage_migration_book_code
    cargo test -F storage_migration,extensions-draft,virtual-clients-draft --test test_storage_migration --test storage_migration_book_code
done

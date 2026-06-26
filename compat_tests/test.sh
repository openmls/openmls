#!/usr/bin/env bash

cargo test -F compat_0_7_0 --test test_storage_tag_stability
cargo test -F compat_0_8_1 --test test_storage_tag_stability
cargo test -F compat_0_8_1_extensions --test test_storage_tag_stability

cargo test -F storage_migration --test test_storage_migration
cargo test -F storage_migration,extensions-draft-08 --test test_storage_migration --test storage_migration_book_code
cargo test -F storage_migration,extensions-draft-08,virtual-clients-draft --test test_storage_migration --test storage_migration_book_code

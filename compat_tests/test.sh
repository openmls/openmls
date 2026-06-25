#!/usr/bin/env bash

cargo test -F compat_0_7_0 --test test_storage_tag_stability
cargo test -F compat_0_8_1 --test test_storage_tag_stability
cargo test -F compat_0_8_1_extensions --test test_storage_tag_stability

cargo test -F optional_field_stability --test test_optional_field_stability
cargo test -F optional_field_stability,extensions-draft-08 --test test_optional_field_stability
cargo test -F optional_field_stability,extensions-draft-08,virtual-clients-draft --test test_optional_field_stability

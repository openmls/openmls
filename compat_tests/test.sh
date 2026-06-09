#!/usr/bin/env bash

cargo test -F compat_0_7_1
cargo test -F compat_0_8_1
cargo test -F compat_0_8_1_extensions

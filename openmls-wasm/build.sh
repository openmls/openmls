#!/usr/bin/env bash

pushd $(dirname $0) >/dev/null
trap popd EXIT

set -e
set -x

mkdir -p pkg
wasm-pack build --target web
cp static/index.html pkg/index.html

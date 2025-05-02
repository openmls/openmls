#!/usr/bin/env bash

pushd $(dirname $0) >/dev/null
trap "popd >/dev/null" EXIT

function die() {
	echo error: $@
	exit 1
}

set -e

./build.sh

raw_size=$(tar c pkg | wc -c)
gzip_size=$(tar cj pkg | wc -c)

raw_thresh=1700000
gzip_thresh=500000

if [ $raw_size -gt $raw_thresh ]; then
	die "raw size is too large: $raw_size > $raw_thresh"
else
	echo "raw size $raw_size is below threshold $raw_thresh"
fi

if [ $gzip_size -gt $gzip_thresh ]; then
	die "gzip'd size is too largs: $gzip_size > $gzip_thresh"
else
	echo "gzip'd size $gzip_size is below threshold $gzip_thresh"
fi

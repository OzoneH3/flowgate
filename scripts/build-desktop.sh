#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
. ./scripts/go-env.sh
go build -o .workspace/flowgate ./cmd/flowgate
go build -o .workspace/flowgate-demo-receiver ./fixtures/native
cmake -S desktop -B .workspace/desktop -DCMAKE_BUILD_TYPE=Debug
cmake --build .workspace/desktop -j2

#!/usr/bin/env bash
#
# One-step test runner for the Dart binding. Builds libitb3.so via
# build.sh, points ITB_LIBITB3_PATH at the freshly-built shared
# library, then invokes `dart test`. Forwards any positional
# arguments through to dart test (e.g. a --name filter).
#
# Usage:
#   ./run_tests.sh                          # full suite
#   ./run_tests.sh --name 'round trip'      # filtered

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB3_PATH="$DIST_DIR/libitb3.so"

exec dart test "$@"

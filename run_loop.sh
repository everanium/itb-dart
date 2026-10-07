#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Dart binding:
# runs the utility with every argument passed through. The binding is
# pure Dart over dart:ffi, so there is nothing to compile here;
# build.sh owns libitb3.so, the resolved package config the entry point
# needs, and the analyzer pass over the sources.
#
# The library is found by the package's own lookup order, which walks
# up from the working directory to the repo dist directory, so the
# launcher sets no environment of its own.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

exec dart run loop/main.dart "$@"

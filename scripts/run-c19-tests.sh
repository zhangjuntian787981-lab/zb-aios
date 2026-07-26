#!/bin/sh
set -eu

node --test \
  tests/c19-observability.test.mjs \
  tests/c19-observability-artifacts.test.mjs \
  tests/c19-observability-postgres-contract.test.mjs \
  tests/c19-upstream-emitter-integration.test.mjs

sh scripts/run-c19-postgres-tests.sh

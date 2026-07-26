#!/bin/sh
set -eu

node --test \
  tests/c16-c06-authorizer.test.mjs \
  tests/c16-c06-integration.test.mjs \
  tests/c16-contract.test.mjs \
  tests/c16-credential-adapter.test.mjs \
  tests/c16-outbox-worker.test.mjs \
  tests/c16-tool-gateway.test.mjs

sh scripts/run-c16-postgres-tests.sh

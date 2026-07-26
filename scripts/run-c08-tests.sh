#!/bin/sh
set -eu

node --test \
  tests/aios-state-api.test.mjs \
  tests/aios-state-c06-integration.test.mjs \
  tests/aios-state-core.test.mjs \
  tests/aios-state-postgres-contract.test.mjs \
  tests/c08-c0-mock-tool-receipts.test.mjs \
  tests/c08-outbox-worker.test.mjs \
  tests/c08-synthetic-reference-catalog.test.mjs

sh scripts/run-c08-postgres-tests.sh
sh scripts/run-c08-roles-postgres-tests.sh

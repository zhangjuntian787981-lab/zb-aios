#!/bin/sh
set -eu

node --test \
  tests/tenant-data-boundary.test.mjs \
  tests/tenant-data-catalog.test.mjs \
  tests/tenant-data-postgres-contract.test.mjs \
  tests/file-tenant-object-adapter.test.mjs

sh scripts/run-c07-postgres-tests.sh
sh scripts/run-c07-roles-postgres-tests.sh
sh scripts/run-c07-restore-postgres-tests.sh

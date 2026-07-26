#!/bin/sh
set -eu

node --test \
  tests/skill-registry.test.mjs \
  tests/c13-synthetic-skill-catalog.test.mjs \
  tests/skill-registry-c06-integration.test.mjs \
  tests/skill-registry-contract.test.mjs
sh scripts/run-c13-postgres-tests.sh
sh scripts/run-c13-roles-postgres-tests.sh

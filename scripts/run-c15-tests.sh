#!/bin/sh
set -eu

node --test \
  tests/c15-c06-authorizer.test.mjs \
  tests/c15-c06-integration.test.mjs \
  tests/c15-c18-audit-publisher.test.mjs \
  tests/c15-contract.test.mjs \
  tests/c15-human-decision-workflow.test.mjs

sh scripts/run-c15-postgres-tests.sh

#!/bin/sh
set -eu

node --test \
  tests/c02-contract.test.mjs \
  tests/c02-c06-authorizer.test.mjs \
  tests/c02-c06-integration.test.mjs \
  tests/c02-governance-shell.test.mjs \
  tests/c02-tenant-governance-bff.test.mjs

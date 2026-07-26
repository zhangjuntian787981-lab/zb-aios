#!/bin/sh
set -eu

node --test \
  tests/c01-contract.test.mjs \
  tests/c01-c06-authorizer.test.mjs \
  tests/c01-employee-portal-bff.test.mjs \
  tests/c01-portal-shell.test.mjs

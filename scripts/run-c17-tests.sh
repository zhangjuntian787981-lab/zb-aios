#!/bin/sh
set -eu

node --test \
  tests/c17-contract.test.mjs \
  tests/c17-connector-sdk.test.mjs \
  tests/c17-mock-lab.test.mjs \
  tests/c17-source-boundary.test.mjs

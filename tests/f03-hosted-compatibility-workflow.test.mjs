import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowUrl = new URL(
  "../.github/workflows/f03-contract-compatibility-gate.yml",
  import.meta.url,
);

const workflow = await readFile(workflowUrl, "utf8");

test("F03 hosted compatibility gate uses a read-only pinned pull-request boundary", () => {
  assert.match(workflow, /^on:\n  pull_request:\s*$/m);
  assert.doesNotMatch(workflow, /pull_request_target/);
  assert.match(workflow, /^permissions:\n  contents: read\s*$/m);
  assert.match(workflow, /runs-on: ubuntu-24\.04/);
  assert.match(
    workflow,
    /uses: actions\/checkout@11d5960a326750d5838078e36cf38b85af677262/,
  );
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /fetch-depth: 0/);
  assert.match(
    workflow,
    /uses: actions\/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020/,
  );
  assert.match(workflow, /node-version: "24"/);
  assert.doesNotMatch(workflow, /(?:^|\s)cache:/m);
  assert.doesNotMatch(
    workflow,
    /uses:\s*[^@\s]+@(?![a-f0-9]{40}(?:\s|$))\S+/,
  );
});

test("F03 hosted gate compares every frozen contract against the exact PR base", () => {
  assert.match(
    workflow,
    /BASE_SHA: \$\{\{ github\.event\.pull_request\.base\.sha \}\}/,
  );
  assert.match(workflow, /test "\$\{#BASE_SHA\}" -eq 40/);
  assert.match(workflow, /\*\[\^0-9a-f\]\*/);
  assert.match(workflow, /git show "\$\{BASE_SHA\}:\$\{contract_path\}"/);
  assert.match(
    workflow,
    /node scripts\/f03-contract-lab\.mjs breaking/,
  );

  for (const moduleName of [
    "audit",
    "connector",
    "core",
    "model",
    "portal",
    "tool",
  ]) {
    assert.match(workflow, new RegExp(`\\b${moduleName}\\b`));
  }
});

test("F03 hosted gate runs the frozen eight-category mutation and consumer-provider tests", () => {
  assert.match(
    workflow,
    /npm ci --ignore-scripts --no-audit --no-fund/,
  );
  assert.match(
    workflow,
    /node --test tests\/f03-contract-lab\.test\.mjs tests\/f03-consumer-provider\.test\.mjs/,
  );
  assert.doesNotMatch(workflow, /continue-on-error:\s*true/);
  assert.doesNotMatch(workflow, /\|\|\s*true/);
});

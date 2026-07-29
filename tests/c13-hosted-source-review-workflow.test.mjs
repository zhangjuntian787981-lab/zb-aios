import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflow = await readFile(
  new URL(
    "../.github/workflows/c13-source-review-gate.yml",
    import.meta.url,
  ),
  "utf8",
);

test("C13 hosted source-review gate is read-only and pinned", () => {
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

test("C13 hosted source-review gate runs only the frozen synthetic review boundary", () => {
  assert.match(
    workflow,
    /npm ci --ignore-scripts --no-audit --no-fund/,
  );
  assert.match(
    workflow,
    /node --test tests\/c13-hosted-source-review-workflow\.test\.mjs tests\/c13-skill-registry-evidence\.test\.mjs tests\/c13-synthetic-skill-catalog\.test\.mjs tests\/skill-registry-contract\.test\.mjs tests\/p1-b11-protected-review-candidate\.test\.mjs/,
  );
  assert.doesNotMatch(workflow, /continue-on-error:\s*true/);
  assert.doesNotMatch(workflow, /\|\|\s*true/);
  assert.doesNotMatch(workflow, /secrets\./);
});

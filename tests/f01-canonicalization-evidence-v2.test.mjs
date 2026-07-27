import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const evidence = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p0/f01/f01-canonicalization-evidence.v2.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const cases = JSON.parse(
  execFileSync(
    "git",
    [
      "show",
      `${evidence.verified_source_commit}:implementation/p0/f01/canonicalization-cases.v1.json`,
    ],
    { cwd: repositoryRoot, encoding: "utf8" },
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("F01 v2 freezes every case byte receipt and three stable process receipts", () => {
  assert.equal(evidence.parent_work_package_id, "F01");
  assert.deepEqual(evidence.acceptance_item_ids, ["F01-AC03", "F01-AC04"]);
  assert.equal(evidence.case_receipts.length, 3);
  assert.equal(evidence.independent_process_receipts.length, 3);

  for (const receipt of evidence.case_receipts) {
    const fixture = cases.cases.find(({ id }) => id === receipt.case_id);
    assert.ok(fixture, receipt.case_id);
    assert.equal(receipt.observed_utf8_hex, fixture.expectedUtf8Hex);
    assert.equal(receipt.observed_sha256, fixture.expectedSha256);
    assert.equal(receipt.equivalent_input_count, fixture.equivalentInputs.length);
    assert.equal(receipt.status, "PASS");
  }

  const processBytes = new Set(
    evidence.independent_process_receipts.map(
      ({ canonical_utf8_hex }) => canonical_utf8_hex,
    ),
  );
  const processHashes = new Set(
    evidence.independent_process_receipts.map(
      ({ canonical_bytes_sha256 }) => canonical_bytes_sha256,
    ),
  );
  assert.deepEqual(
    [...processBytes],
    [cases.cases[1].expectedUtf8Hex],
  );
  assert.deepEqual(
    [...processHashes],
    [cases.cases[1].expectedSha256],
  );
  assert.deepEqual(
    evidence.independent_process_receipts.map(({ ordinal }) => ordinal),
    [1, 2, 3],
  );

  for (const artifact of evidence.source_artifacts) {
    const contents = execFileSync(
      "git",
      ["show", `${evidence.verified_source_commit}:${artifact.path}`],
      { cwd: repositoryRoot },
    );
    assert.equal(sha256(contents), artifact.sha256, artifact.path);
  }
  assert.deepEqual(evidence.governance_boundary, {
    d1_written: false,
    historical_work_package_status_changed: false,
    historical_gate_decision_changed: false,
    manifest_changed: false,
    enterprise_data_used: false,
  });
});

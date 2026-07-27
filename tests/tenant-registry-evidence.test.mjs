import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const rootUrl = new URL("../", import.meta.url);
const repositoryRoot = fileURLToPath(rootUrl);
const evidenceFreezeCommit =
  "c29ec39f3cad8e123660bb2764a69efc7286ec1d";
const historicalEvidenceUrl = new URL(
  "../implementation/p1/c03/c03-implementation-evidence.v1.json",
  import.meta.url,
);
const evidenceUrl = new URL(
  "../implementation/p1/c03/c03-verification-evidence.v2.json",
  import.meta.url,
);

test("C03 verified evidence is intact and preserves its unverified history", async () => {
  const historicalContent = await readFile(historicalEvidenceUrl);
  const historicalSha256 = `sha256:${createHash("sha256")
    .update(historicalContent)
    .digest("hex")}`;
  assert.equal(
    historicalSha256,
    "sha256:879561dc2dc2b9e4ce6d6ac69c306ae22bec4eb94a8891303906f2791baab6f5",
  );

  const evidence = JSON.parse(await readFile(evidenceUrl, "utf8"));

  assert.equal(evidence.work_package_id, "C03");
  assert.equal(evidence.implementation_status, "IMPLEMENTED");
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verified_source_commit, "207986b6d58dd07897a6b681d190e81c20139c9f");
  execFileSync(
    "git",
    [
      "merge-base",
      "--is-ancestor",
      evidence.verified_source_commit,
      evidenceFreezeCommit,
    ],
    { cwd: repositoryRoot },
  );
  assert.equal(
    evidence.supersedes_evidence_sha256,
    historicalSha256,
  );
  assert.equal(
    evidence.verification_results.real_postgresql_runtime,
    "8 PASS, 0 FAIL",
  );

  for (const artifact of evidence.artifacts) {
    const content = execFileSync(
      "git",
      ["show", `${evidenceFreezeCommit}:${artifact.path}`],
      { cwd: repositoryRoot },
    );
    const actual = `sha256:${createHash("sha256")
      .update(content)
      .digest("hex")}`;
    assert.equal(actual, artifact.sha256, artifact.path);
  }
});

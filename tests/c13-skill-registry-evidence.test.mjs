import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const evidenceUrl = new URL(
  "../implementation/p1/c13/c13-verification-evidence.v1.json",
  import.meta.url,
);

test("C13 P1 synthetic verification evidence is intact", async () => {
  const evidence = JSON.parse(await readFile(evidenceUrl, "utf8"));

  assert.equal(evidence.work_package_id, "C13");
  assert.equal(evidence.implementation_status, "IMPLEMENTED");
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(
    evidence.verified_source_commit,
    "5a52c959c70ba448f3155b927e52aa545907d6d9",
  );
  assert.equal(
    evidence.approved_g0_submission_sha256,
    "sha256:77d8707a602a83729b557c028bd6cf87c5a0e5d921145b9dc3a5a1e79bf32a07",
  );
  assert.equal(
    evidence.verification_results.verified_source_test_suite,
    "568 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.full_test_suite_with_evidence,
    "569 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.c13_targeted_node_tests,
    "30 PASS, 0 FAIL",
  );
  assert.equal(evidence.verification_results.deterministic_f04_gate, "PASS");
  assert.equal(evidence.independent_review.reviewers, 1);
  assert.equal(evidence.independent_review.p0_findings, 0);
  assert.equal(evidence.independent_review.p1_findings, 0);
  assert.equal(evidence.independent_review.p2_findings, 0);
  assert.equal(evidence.artifacts.length, 32);
  assert.equal(evidence.dependency_evidence.length, 9);
  assert.equal(
    new Set(evidence.artifacts.map(({ path }) => path)).size,
    evidence.artifacts.length,
  );
  assert.equal(
    evidence.artifacts.some(({ path }) => path === evidence.evidence_ref),
    false,
  );

  for (const artifact of [
    ...evidence.artifacts,
    ...evidence.dependency_evidence,
  ]) {
    const content = execFileSync(
      "/usr/bin/git",
      [
        "show",
        `${evidence.verified_source_commit}:${artifact.path}`,
      ],
      {
        cwd: root,
        env: {
          GIT_CONFIG_GLOBAL: "/dev/null",
          GIT_CONFIG_NOSYSTEM: "1",
          LANG: "C",
          LC_ALL: "C",
        },
      },
    );
    const actual = `sha256:${createHash("sha256")
      .update(content)
      .digest("hex")}`;
    assert.equal(actual, artifact.sha256, artifact.path);
  }

  const catalog = JSON.parse(
    await readFile(
      new URL(
        "../implementation/p1/c13/synthetic-skill-catalog.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.equal(catalog.tenants.length, 3);
  assert.equal(
    catalog.tenants.flatMap(({ releases }) => releases)
      .every(({ evaluation }) => evaluation.status === "BLOCKED"),
    true,
  );
});

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { sha256ProjectValue } from "../lib/project-control.mjs";

const REPOSITORY_ROOT = new URL("..", import.meta.url);
const audit = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c13/github/p1-b11-github-capability-audit.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function withoutSelfHash(value) {
  const copy = structuredClone(value);
  delete copy.auditSha256;
  return copy;
}

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function assertExactKeys(value, expected) {
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort());
}

test("P1-B11 capability audit is a closed blocked snapshot, not enforcement evidence", async () => {
  assertExactKeys(audit, [
    "schemaVersion",
    "auditId",
    "recordType",
    "workPackageId",
    "acceptanceCriterionId",
    "status",
    "observedAt",
    "repository",
    "probes",
    "codeownersAssessment",
    "collaboratorAssessment",
    "hostedCheckAssessment",
    "blockers",
    "governanceBoundary",
    "auditSha256",
  ]);
  assert.equal(audit.status, "BLOCKED_EXTERNAL_PREREQUISITES");
  assert.deepEqual(audit.blockers, [
    "PRIVATE_REPOSITORY_RULES_CAPABILITY_UNAVAILABLE",
    "CODEOWNERS_OWNER_INVALID",
    "INDEPENDENT_REVIEWER_MISSING",
  ]);
  assert.equal(audit.governanceBoundary.p1B11Closed, false);
  assert.equal(audit.governanceBoundary.rulesetApplied, false);
  assert.equal(audit.governanceBoundary.independentReviewProved, false);
  assert.equal(audit.governanceBoundary.d1Written, false);
  assert.equal(
    await sha256ProjectValue(withoutSelfHash(audit)),
    audit.auditSha256,
  );
});

test("P1-B11 capability audit binds the exact pre-remediation CODEOWNERS bytes", () => {
  const bytes = execFileSync(
    "/usr/bin/git",
    [
      "show",
      `${audit.repository.observedCommit}:${audit.codeownersAssessment.path}`,
    ],
    {
      cwd: REPOSITORY_ROOT,
      env: {
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
        LANG: "C",
        LC_ALL: "C",
      },
    },
  );
  assert.equal(
    sha256Bytes(bytes),
    audit.codeownersAssessment.sha256,
  );
  assert.equal(audit.codeownersAssessment.ruleCount, 7);
  assert.equal(audit.codeownersAssessment.errorCount, 7);
  assert.deepEqual(audit.codeownersAssessment.errorKinds, [
    "Unknown owner",
  ]);
  assert.equal(audit.codeownersAssessment.zeroErrors, false);
});

test("P1-B11 capability audit records plan and reviewer blockers without secrets", () => {
  assert.deepEqual(
    audit.probes.map(({ probeId, httpStatus, resultCode }) => ({
      probeId,
      httpStatus,
      resultCode,
    })),
    [
      {
        probeId: "RULESETS",
        httpStatus: 403,
        resultCode: "PRIVATE_REPOSITORY_RULES_CAPABILITY_UNAVAILABLE",
      },
      {
        probeId: "EFFECTIVE_BRANCH_RULES",
        httpStatus: 403,
        resultCode: "PRIVATE_REPOSITORY_RULES_CAPABILITY_UNAVAILABLE",
      },
      {
        probeId: "CLASSIC_BRANCH_PROTECTION",
        httpStatus: 403,
        resultCode: "PRIVATE_REPOSITORY_RULES_CAPABILITY_UNAVAILABLE",
      },
      {
        probeId: "CODEOWNERS_ERRORS",
        httpStatus: 200,
        resultCode: "SEVEN_UNKNOWN_OWNERS",
      },
      {
        probeId: "COLLABORATORS",
        httpStatus: 200,
        resultCode: "ONE_IMPLEMENTER_ONLY",
      },
    ],
  );
  assert.equal(audit.collaboratorAssessment.totalCount, 1);
  assert.equal(
    audit.collaboratorAssessment.independentWriteCapableCount,
    0,
  );
  assert.equal(
    audit.collaboratorAssessment.independentReviewerPresent,
    false,
  );

  const serialized = JSON.stringify(audit).toLowerCase();
  for (const forbidden of [
    "authorization",
    "cookie",
    "token",
    "password",
    "secret",
    "email",
    "request headers",
  ]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
});

test("P1-B11 capability audit distinguishes observed and pending hosted checks", () => {
  assert.deepEqual(audit.hostedCheckAssessment, {
    integrationId: 15368,
    observed: [
      "protected-surface-gate",
      "contract-compatibility-gate",
    ],
    pendingHostedObservation: ["c13-source-review-gate"],
  });
});

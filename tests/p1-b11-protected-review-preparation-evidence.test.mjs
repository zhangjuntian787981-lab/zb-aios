import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { sha256ProjectValue } from "../lib/project-control.mjs";

const ROOT = new URL("..", import.meta.url);
const EVIDENCE_PATH =
  "implementation/p1/c13/p1-b11-protected-review-preparation-evidence.v1.json";
const SOURCE_COMMIT = "9e14804015e022ffae90696b04fdb37edd31e992";
const SOURCE_PARENT = "5d12201e984937a905ab8bae90a86a4b1763d899";
const SOURCE_TREE = "cfe2b281543bc354fe4cdda259d2acd6bf870927";
const SOURCE_PATCH_SHA256 =
  "sha256:382c30b8677785581f1eef6b298b82f9c6e9a4eba8b70c7410fcb7271cd216f7";
const EXPECTED_LIMITATIONS = [
  "The successful hosted checks prove execution of the frozen synthetic source-review boundary, not enforcement of a branch Ruleset.",
  "Zero CODEOWNERS parse errors prove that the branch policy parses; they do not prove that a second real human reviewer approved the change.",
  "The current private-repository plan returns HTTP 403 for Rulesets and classic branch protection.",
  "Only one write-capable human is present, so independent Code Owner review remains INCONCLUSIVE.",
  "No protected negative control has proved that an unapproved or failing change is denied at merge time; this evidence does not prove merge denial.",
  "Making the repository public is not authorized as a substitute for the missing private-repository capability.",
];
const GIT_ENV = {
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_ATTR_NOSYSTEM: "1",
  LANG: "C",
  LC_ALL: "C",
};

const evidence = JSON.parse(
  await readFile(new URL(`../${EVIDENCE_PATH}`, import.meta.url), "utf8"),
);

function sha256Bytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function gitBytes(commit, path) {
  return execFileSync("/usr/bin/git", ["show", `${commit}:${path}`], {
    cwd: ROOT,
    env: GIT_ENV,
  });
}

function gitValue(format, commit) {
  return execFileSync("/usr/bin/git", ["show", "-s", `--format=${format}`, commit], {
    cwd: ROOT,
    encoding: "utf8",
    env: GIT_ENV,
  }).trim();
}

function withoutSelfHash(value) {
  const copy = structuredClone(value);
  delete copy.evidenceSha256;
  return copy;
}

function assertExactKeys(value, expected) {
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort());
}

function assertNoSensitiveMaterial(value) {
  const forbiddenKey =
    /^(?:actorId|authorization|cookie|email|requestHeaders|secret|token)$/i;
  const forbiddenContent =
    /(?:[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|\b(?:Cookie|Set-Cookie)\s*:|\bAuthorization\s*:\s*(?:Basic|Bearer)\b|\bBasic\s+[A-Za-z0-9+/=]{8,}|\bBearer\s+[A-Za-z0-9._-]{8,}|gh[opsu]_[A-Za-z0-9]{8,}|\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b|[?&](?:access_token|api_key|apikey|client_secret|password)=|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY)/i;
  const visit = (current) => {
    if (Array.isArray(current)) {
      current.forEach(visit);
      return;
    }
    if (current && typeof current === "object") {
      for (const [key, nested] of Object.entries(current)) {
        assert.doesNotMatch(key, forbiddenKey);
        visit(nested);
      }
      return;
    }
    if (typeof current === "string") {
      assert.doesNotMatch(current, forbiddenContent);
    }
  };
  visit(value);
}

async function validateEvidence(value) {
  assertExactKeys(value, [
    "schemaVersion",
    "evidenceId",
    "recordType",
    "groupId",
    "workPackageId",
    "acceptanceCriterionId",
    "classification",
    "status",
    "recordedAt",
    "sourceFreeze",
    "pullRequest",
    "hostedChecks",
    "codeownersReadback",
    "rulesetCandidate",
    "capabilityBoundary",
    "criterionAssessment",
    "governanceBoundary",
    "limitations",
    "evidenceSha256",
  ]);
  assertExactKeys(value.sourceFreeze, [
    "commit",
    "parent",
    "tree",
    "patchSha256",
    "branch",
    "artifacts",
  ]);
  assertExactKeys(value.pullRequest, [
    "number",
    "url",
    "state",
    "draft",
    "merged",
    "baseBranch",
    "baseSha",
    "headBranch",
    "headSha",
    "mergeStateStatus",
    "reviewDecision",
    "createdAt",
  ]);
  assertExactKeys(value.hostedChecks, [
    "integrationId",
    "requiredCandidateChecks",
    "c13SourceReview",
    "contractCompatibility",
    "protectedSurface",
  ]);
  assertExactKeys(value.hostedChecks.c13SourceReview, [
    "runId",
    "runNumber",
    "workflowId",
    "runUrl",
    "event",
    "headBranch",
    "headSha",
    "status",
    "conclusion",
    "createdAt",
    "updatedAt",
    "jobId",
    "jobUrl",
    "startedAt",
    "completedAt",
    "runner",
    "log",
    "gateResult",
  ]);
  assertExactKeys(value.hostedChecks.c13SourceReview.runner, [
    "runnerVersion",
    "provisionerVersion",
    "image",
    "imageVersion",
    "nodeVersion",
    "npmVersion",
    "includedSoftwareUrl",
    "imageReleaseUrl",
  ]);
  assertExactKeys(value.hostedChecks.c13SourceReview.log, [
    "byteLength",
    "sha256",
  ]);
  assertExactKeys(value.hostedChecks.c13SourceReview.gateResult, [
    "testCount",
    "passedCount",
    "failedCount",
  ]);
  for (const check of [
    value.hostedChecks.contractCompatibility,
    value.hostedChecks.protectedSurface,
  ]) {
    assertExactKeys(check, [
      "runId",
      "runUrl",
      "headSha",
      "status",
      "conclusion",
      "createdAt",
      "updatedAt",
      "jobId",
    ]);
  }
  assertExactKeys(value.codeownersReadback, [
    "ref",
    "observedAt",
    "httpStatus",
    "errorCount",
    "errors",
  ]);
  assertExactKeys(value.rulesetCandidate, [
    "path",
    "fileSha256",
    "status",
    "target",
    "desiredEnforcement",
    "bypassActors",
    "remoteEnforcementProved",
  ]);
  assertExactKeys(value.capabilityBoundary, [
    "auditPath",
    "auditFileSha256",
    "auditSha256",
    "repositoryVisibility",
    "privateRepositoryRulesCapability",
    "rulesetProbeHttpStatus",
    "classicProtectionProbeHttpStatus",
    "writeCapableHumanCount",
    "independentHumanReviewer",
    "automaticPublicVisibilityChangeAuthorized",
  ]);
  assertExactKeys(value.criterionAssessment, [
    "codeownersSyntax",
    "hostedCheckExecution",
    "rulesetEnforcement",
    "independentCodeOwnerReview",
    "unapprovedMergeDenied",
    "overall",
  ]);
  assertExactKeys(value.governanceBoundary, [
    "d1EventCreated",
    "workPackageStateChanged",
    "gateChanged",
    "p1B11Closed",
    "profileApproved",
    "o02Authorized",
    "o03Authorized",
    "isProgressTracker",
  ]);
  assertNoSensitiveMaterial(value);
  assert.equal(value.schemaVersion, "p1-b11-protected-review-preparation-evidence.v1");
  assert.equal(value.groupId, "P1-B11");
  assert.equal(value.workPackageId, "C13");
  assert.equal(value.acceptanceCriterionId, "C13-AC02");
  assert.equal(value.classification, "CANDIDATE_PREPARATION");
  assert.equal(value.status, "PREPARED_NOT_ENFORCED");
  assert.equal(value.sourceFreeze.commit, SOURCE_COMMIT);
  assert.equal(value.sourceFreeze.parent, SOURCE_PARENT);
  assert.equal(value.sourceFreeze.tree, SOURCE_TREE);
  assert.equal(value.sourceFreeze.patchSha256, SOURCE_PATCH_SHA256);
  assert.equal(value.pullRequest.number, 6);
  assert.equal(
    value.pullRequest.url,
    "https://github.com/zhangjuntian787981-lab/zb-aios/pull/6",
  );
  assert.equal(value.pullRequest.draft, true);
  assert.equal(value.pullRequest.merged, false);
  assert.equal(value.pullRequest.headSha, SOURCE_COMMIT);
  assert.equal(value.hostedChecks.c13SourceReview.status, "completed");
  assert.equal(value.hostedChecks.c13SourceReview.conclusion, "success");
  assert.equal(
    value.hostedChecks.c13SourceReview.runUrl,
    "https://github.com/zhangjuntian787981-lab/zb-aios/actions/runs/30498992738",
  );
  assert.equal(
    value.hostedChecks.c13SourceReview.jobUrl,
    "https://github.com/zhangjuntian787981-lab/zb-aios/actions/runs/30498992738/job/90734205670",
  );
  assert.equal(
    value.hostedChecks.c13SourceReview.runner.includedSoftwareUrl,
    "https://github.com/actions/runner-images/blob/ubuntu24/20260726.254/images/ubuntu/Ubuntu2404-Readme.md",
  );
  assert.equal(
    value.hostedChecks.c13SourceReview.runner.imageReleaseUrl,
    "https://github.com/actions/runner-images/releases/tag/ubuntu24%2F20260726.254",
  );
  assert.equal(
    value.hostedChecks.contractCompatibility.runUrl,
    "https://github.com/zhangjuntian787981-lab/zb-aios/actions/runs/30498992695",
  );
  assert.equal(
    value.hostedChecks.protectedSurface.runUrl,
    "https://github.com/zhangjuntian787981-lab/zb-aios/actions/runs/30498992706",
  );
  assert.equal(value.hostedChecks.c13SourceReview.gateResult.testCount, 20);
  assert.equal(value.hostedChecks.c13SourceReview.gateResult.passedCount, 20);
  assert.equal(value.hostedChecks.c13SourceReview.gateResult.failedCount, 0);
  assert.equal(value.codeownersReadback.errorCount, 0);
  assert.deepEqual(value.codeownersReadback.errors, []);
  assert.equal(value.rulesetCandidate.status, "CANDIDATE_NOT_APPLIED");
  assert.equal(value.rulesetCandidate.remoteEnforcementProved, false);
  assert.deepEqual(value.rulesetCandidate.bypassActors, []);
  assert.equal(
    value.capabilityBoundary.privateRepositoryRulesCapability,
    "BLOCKED_BY_GITHUB_PLAN",
  );
  assert.equal(value.capabilityBoundary.independentHumanReviewer, "MISSING");
  assert.equal(value.criterionAssessment.codeownersSyntax, "PASS");
  assert.equal(value.criterionAssessment.hostedCheckExecution, "PASS");
  assert.equal(
    value.criterionAssessment.rulesetEnforcement,
    "BLOCKED_BY_GITHUB_PLAN",
  );
  assert.equal(value.criterionAssessment.independentCodeOwnerReview, "INCONCLUSIVE");
  assert.equal(value.criterionAssessment.unapprovedMergeDenied, "NOT_RUN_BLOCKED");
  assert.equal(value.criterionAssessment.overall, "INCONCLUSIVE");
  assert.equal(value.governanceBoundary.d1EventCreated, false);
  assert.equal(value.governanceBoundary.workPackageStateChanged, false);
  assert.equal(value.governanceBoundary.p1B11Closed, false);
  assert.equal(value.governanceBoundary.profileApproved, false);
  assert.equal(value.governanceBoundary.o02Authorized, false);
  assert.equal(value.governanceBoundary.o03Authorized, false);
  assert.deepEqual(value.limitations, EXPECTED_LIMITATIONS);
  assert.equal(
    value.evidenceSha256,
    await sha256ProjectValue(withoutSelfHash(value)),
  );
}

test("P1-B11 preparation evidence binds the exact source commit and artifacts", async () => {
  await validateEvidence(evidence);
  execFileSync("/usr/bin/git", ["cat-file", "-e", `${SOURCE_COMMIT}^{commit}`], {
    cwd: ROOT,
    env: GIT_ENV,
  });
  execFileSync(
    "/usr/bin/git",
    ["merge-base", "--is-ancestor", SOURCE_COMMIT, "HEAD"],
    { cwd: ROOT, env: GIT_ENV },
  );
  assert.equal(gitValue("%P", SOURCE_COMMIT), SOURCE_PARENT);
  assert.equal(gitValue("%T", SOURCE_COMMIT), SOURCE_TREE);
  assert.equal(
    sha256Bytes(
      execFileSync(
        "/usr/bin/git",
        [
          "diff",
          "--binary",
          "--no-ext-diff",
          "--no-textconv",
          SOURCE_PARENT,
          SOURCE_COMMIT,
        ],
        { cwd: ROOT, env: GIT_ENV },
      ),
    ),
    SOURCE_PATCH_SHA256,
  );
  for (const artifact of evidence.sourceFreeze.artifacts) {
    assertExactKeys(artifact, ["path", "sha256"]);
    assert.equal(sha256Bytes(gitBytes(SOURCE_COMMIT, artifact.path)), artifact.sha256);
  }
});

test("hosted evidence is exact but cannot masquerade as protected independent review", () => {
  assert.deepEqual(evidence.hostedChecks.requiredCandidateChecks, [
    "protected-surface-gate",
    "contract-compatibility-gate",
    "c13-source-review-gate",
  ]);
  assert.equal(
    evidence.hostedChecks.c13SourceReview.log.sha256,
    "sha256:eb15d6ab82ce4195a223bedfc763275eab30dfbdf56b278116b52aa195b465af",
  );
  assert.equal(evidence.hostedChecks.c13SourceReview.log.byteLength, 19568);
  assert.equal(evidence.pullRequest.reviewDecision, "NONE");
  assert.equal(evidence.capabilityBoundary.writeCapableHumanCount, 1);
  assert.match(evidence.limitations.join("\n"), /second real human reviewer/i);
  assert.match(evidence.limitations.join("\n"), /does not prove merge denial/i);
});

test("ruleset, reviewer, merge-denial, or completion overclaims fail closed", async () => {
  for (const mutate of [
    (copy) => {
      copy.status = "CLOSED";
    },
    (copy) => {
      copy.rulesetCandidate.status = "APPLIED";
    },
    (copy) => {
      copy.rulesetCandidate.remoteEnforcementProved = true;
    },
    (copy) => {
      copy.capabilityBoundary.independentHumanReviewer = "PRESENT";
    },
    (copy) => {
      copy.criterionAssessment.overall = "PASS";
    },
    (copy) => {
      copy.governanceBoundary.p1B11Closed = true;
    },
  ]) {
    const copy = structuredClone(evidence);
    mutate(copy);
    copy.evidenceSha256 = await sha256ProjectValue(withoutSelfHash(copy));
    await assert.rejects(() => validateEvidence(copy));
  }
});

test("self-hash and frozen source bytes fail closed on tampering", async () => {
  const selfHash = structuredClone(evidence);
  selfHash.evidenceSha256 = `sha256:${"f".repeat(64)}`;
  await assert.rejects(() => validateEvidence(selfHash));

  const source = structuredClone(evidence);
  source.sourceFreeze.artifacts[0].sha256 = `sha256:${"f".repeat(64)}`;
  source.evidenceSha256 = await sha256ProjectValue(withoutSelfHash(source));
  await assert.rejects(async () => {
    await validateEvidence(source);
    for (const artifact of source.sourceFreeze.artifacts) {
      assert.equal(
        sha256Bytes(gitBytes(SOURCE_COMMIT, artifact.path)),
        artifact.sha256,
      );
    }
  });
});

test("unknown nested fields and sensitive material fail closed", async () => {
  const unknown = structuredClone(evidence);
  unknown.pullRequest.token = "not-a-real-token";
  unknown.evidenceSha256 = await sha256ProjectValue(withoutSelfHash(unknown));
  await assert.rejects(() => validateEvidence(unknown));

  for (const content of [
    "person@example.com",
    "Cookie: session=synthetic",
    "Authorization: Basic c3ludGhldGlj",
    "eyJhbGciOiJIUzI1NiJ9.c3ludGhldGlj.c2lnbmF0dXJl",
    "https://github.com/example?access_token=synthetic",
    "https://github.com/example?api_key=synthetic",
  ]) {
    const sensitive = structuredClone(evidence);
    sensitive.limitations[0] = content;
    sensitive.evidenceSha256 =
      await sha256ProjectValue(withoutSelfHash(sensitive));
    await assert.rejects(() => validateEvidence(sensitive));
  }
});

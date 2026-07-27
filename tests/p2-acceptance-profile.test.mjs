import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = new URL("../", import.meta.url);
const profile = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p2/acceptance/p2-acceptance-profile.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const receiptSchema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p2/acceptance/p2-acceptance-receipt.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

function canonical(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(",")}}`;
}

test("P2 profile declares all 91 matrix criteria without becoming progress authority", async () => {
  assert.equal(profile.recordType, "P2_ACCEPTANCE_PROFILE");
  assert.equal(profile.profileFreeze, "FROZEN_CONFIGURATION");
  assert.equal(profile.scopeKind, "SYNTHETIC");
  assert.equal(profile.enterpriseDataAllowed, false);
  assert.equal(profile.isProgressTracker, false);
  assert.equal(profile.authorityBoundary.recordsWorkPackageStatus, false);
  assert.equal(
    profile.authorityBoundary.recordsGateSubmissionOrDecision,
    false,
  );

  const matrix = await readFile(
    new URL(
      "../docs/plans/通用多企业AI员工平台_v5.2最小验收项与开源参考矩阵_v1.0.md",
      import.meta.url,
    ),
    "utf8",
  );
  const p2 = matrix.slice(
    matrix.indexOf("## 5. P2"),
    matrix.indexOf("## 6. P3"),
  );
  const matrixIds = [
    ...p2.matchAll(
      /^\| (O\d{2}-(?:AC|PX|Q)\d+[A-Z]?) \|/gmu,
    ),
  ].map((match) => match[1]);
  const profileIds = profile.criteria.map(({ criterionId }) => criterionId);

  assert.equal(matrixIds.length, 91);
  assert.deepEqual(profileIds, matrixIds);
  assert.equal(new Set(profileIds).size, 91);
  assert.equal(
    profile.criteria.every(
      ({
        criterionId,
        ownerRole,
        applicability,
        thresholdRef,
        receiptSchemaRef,
        receiptKind,
      }) =>
        ownerRole.length > 0 &&
        applicability === "REQUIRED" &&
        thresholdRef === `matrix://${criterionId}` &&
        receiptSchemaRef ===
          "implementation/p2/acceptance/p2-acceptance-receipt.v1.schema.json" &&
        receiptKind.length > 0,
    ),
    true,
  );
});

test("P2 profile freezes cross-stage semantics, thresholds and receipt schema", () => {
  assert.deepEqual(
    profile.crossStageCriteria.map(
      ({ criterionId, applicability }) => ({
        criterionId,
        applicability,
      }),
    ),
    [
      {
        criterionId: "C08-AC06",
        applicability: "REQUIRED_IN_P2_C0_SYNTHETIC",
      },
      {
        criterionId: "C15-AC02",
        applicability: "REQUIRED_IN_P2",
      },
      {
        criterionId: "C17-AC02",
        applicability: "REQUIRED_IN_P2",
      },
      {
        criterionId: "C17-AC08",
        applicability: "REQUIRED_IN_P2",
      },
      {
        criterionId: "C17-AC09",
        applicability:
          "CONDITIONAL_IF_RELEASE_EXPOSES_WEBHOOK_OTHERWISE_SIGNED_NA",
      },
    ],
  );
  assert.equal(
    profile.referenceThresholds.dynamicCredentialLeaseTtlSecondsMax,
    900,
  );
  assert.equal(
    profile.referenceThresholds.mutableStateRpoSecondsMax,
    900,
  );
  assert.equal(
    profile.referenceThresholds.fullStackRtoSecondsMax,
    14400,
  );
  assert.equal(
    profile.referenceThresholds.steadyLoadAvailabilityPercentMin,
    99.9,
  );
  assert.equal(
    profile.referenceThresholds.criticalOrHighRiskFalseSuccessCountMax,
    0,
  );
  assert.equal(profile.receiptPolicy.exactToolVersionsRequired, true);
  assert.equal(profile.receiptPolicy.rawEvidenceMustBeHashBound, true);

  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  assert.doesNotThrow(() => ajv.compile(receiptSchema));
});

test("P2 profile is hash-bound but explicitly blocks O02 and O03 start", async () => {
  for (const baseline of Object.values(profile.baselineRefs)) {
    const content = await readFile(new URL(baseline.path, root));
    assert.equal(sha256(content), baseline.sha256, baseline.path);
  }
  const fixture = await readFile(
    new URL(
      "../implementation/p0/f02/fixture-inventory.v1.json",
      import.meta.url,
    ),
  );
  assert.equal(
    sha256(fixture),
    profile.releaseCandidateScope.syntheticFixtureInventorySha256,
  );
  const digestInput = {
    packageLockSha256:
      profile.releaseCandidateScope.packageLockSha256,
    sourceCommit: profile.releaseCandidateScope.sourceCommit,
    sourceTree: profile.releaseCandidateScope.sourceTree,
    syntheticFixtureInventorySha256:
      profile.releaseCandidateScope.syntheticFixtureInventorySha256,
  };
  assert.equal(
    sha256(canonical(digestInput)),
    profile.releaseCandidateScope.scopeDigest,
  );
  assert.equal(profile.implementationToolLocks.length, 13);
  assert.equal(
    profile.implementationToolLocks.every(
      ({ selection }) => selection === "UNSELECTED_BLOCKS_EVIDENCE",
    ),
    true,
  );
  assert.deepEqual(profile.executionBoundary, {
    startO02Authorized: false,
    startO03Authorized: false,
    acceptanceReceiptCollectionAuthorized: false,
    reasons: profile.executionBoundary.reasons,
  });
  assert.equal(profile.executionBoundary.reasons.length, 6);
});

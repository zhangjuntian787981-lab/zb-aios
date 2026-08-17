import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  createP2AcceptanceReceiptValidator,
  p2AcceptanceDigests,
} from "../lib/p2-acceptance-receipt-validator.mjs";

const schema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p2/acceptance/p2-acceptance-receipt.v2.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

const ajv = new Ajv2020({
  strict: true,
  allErrors: true,
  validateFormats: true,
});
addFormats(ajv);
const validate = ajv.compile(schema);

const hash = (character) => `sha256:${character.repeat(64)}`;
const hashBytes = (value) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

function validPassReceipt() {
  return {
    schemaVersion: "p2-acceptance-receipt.v2",
    receiptId: "p2r_valid_pass_01",
    criterionId: "O06-Q01",
    receiptKind: "QUALITY_GATE_ACCEPTANCE",
    scopeKind: "SYNTHETIC",
    enterpriseDataUsed: false,
    acceptanceProfileSha256: hash("a"),
    finalReleaseDigest: hash("b"),
    applicabilityAssertion: {
      status: "APPLICABLE",
      predicateRef: null,
      evidenceIds: [],
    },
    owner: {
      principalRef: "principal:quality-owner",
      role: "QUALITY_RELEASE_OWNER",
      assignmentEvidenceId: "p2e_owner_assignment",
    },
    reviewer: {
      principalRef: "principal:independent-reviewer",
      role: "INDEPENDENT_REVIEWER",
      independentOfImplementation: true,
      independenceStatement: "未参与实现、测试执行或证据生成。",
      independenceEvidenceIds: ["p2e_reviewer_assignment"],
    },
    startedAt: "2026-07-28T01:00:00.000Z",
    finishedAt: "2026-07-28T01:05:00.000Z",
    metricResults: [
      {
        metricId: "quality_success_percent",
        numerator: 10,
        denominator: 10,
        value: 100,
        result: "PASS",
        evidenceIds: ["p2e_metric_result"],
      },
    ],
    rawEvidence: [
      {
        evidenceId: "p2e_metric_result",
        path: "artifacts/p2/quality-result.json",
        sha256: hash("c"),
        mediaType: "application/json",
        freezeCommit: "1".repeat(40),
        executionBaselineDigest: hash("d"),
      },
    ],
    findings: [],
    exclusions: [],
    zeroToleranceFindingCount: 0,
    decision: "PASS",
  };
}

test("v2 Receipt Schema compiles in strict Ajv 2020-12 mode", () => {
  assert.equal(validate(validPassReceipt()), true, ajv.errorsText(validate.errors));
});

test("v2 Receipt Schema rejects structurally false PASS decisions", () => {
  const metricFail = validPassReceipt();
  metricFail.metricResults[0].result = "FAIL";
  assert.equal(validate(metricFail), false);

  const zeroTolerance = validPassReceipt();
  zeroTolerance.zeroToleranceFindingCount = 1;
  assert.equal(validate(zeroTolerance), false);

  const nonIndependent = validPassReceipt();
  nonIndependent.reviewer.independentOfImplementation = false;
  assert.equal(validate(nonIndependent), false);
});

test("P2 digest chain has no Profile, evidence, release or Receipt cycle", () => {
  const executionBaseline = {
    schemaVersion: "p2-execution-baseline.v1",
    sourceCommit: "1".repeat(40),
    acceptanceProfile: {
      path: "implementation/p2/acceptance/p2-acceptance-profile.v2.candidate.json",
      sha256: hash("a"),
    },
    receiptSchema: {
      path: "implementation/p2/acceptance/p2-acceptance-receipt.v2.schema.json",
      version: "p2-acceptance-receipt.v2",
      sha256: hash("b"),
    },
    semanticValidator: {
      path: "lib/p2-acceptance-receipt-validator.mjs",
      version: "p2-acceptance-validator.v2",
      sha256: hash("c"),
    },
    fixtures: [
      {
        name: "synthetic-fixture-inventory",
        path: "implementation/p0/f02/fixture-inventory.v1.json",
        sha256: hash("d"),
      },
    ],
    toolLocks: [
      {
        name: "ajv",
        version: "8.20.0",
        digest: hash("e"),
      },
    ],
  };
  const executionBaselineDigest =
    p2AcceptanceDigests.executionBaseline(executionBaseline);
  const changedBaselineDigest = p2AcceptanceDigests.executionBaseline({
    ...executionBaseline,
    sourceCommit: "2".repeat(40),
  });
  assert.match(executionBaselineDigest, /^sha256:[a-f0-9]{64}$/);
  assert.notEqual(changedBaselineDigest, executionBaselineDigest);
  assert.throws(
    () =>
      p2AcceptanceDigests.executionBaseline({
        ...executionBaseline,
        finalReleaseDigest: hash("f"),
      }),
    /forbidden/i,
  );

  const evidenceIndexBytes = Buffer.from(
    JSON.stringify({
      schemaVersion: "p2-evidence-index.v1",
      executionBaselineDigest,
      entries: [],
    }),
  );
  const evidenceIndexDigest =
    p2AcceptanceDigests.evidenceIndex(evidenceIndexBytes);
  const artifactManifestDigest = p2AcceptanceDigests.artifactManifest({
    schemaVersion: "p2-artifact-manifest.v1",
    artifacts: [
      {
        kind: "SCHEMA",
        path: executionBaseline.receiptSchema.path,
        sha256: executionBaseline.receiptSchema.sha256,
        freezeCommit: executionBaseline.sourceCommit,
      },
    ],
  });
  const finalReleaseDigest = p2AcceptanceDigests.finalRelease({
    executionBaselineDigest,
    evidenceIndexDigest,
    artifactManifestDigest,
  });
  assert.match(finalReleaseDigest, /^sha256:[a-f0-9]{64}$/);
  assert.throws(
    () =>
      p2AcceptanceDigests.artifactManifest({
        schemaVersion: "p2-artifact-manifest.v1",
        artifacts: [
          {
            kind: "RECEIPT",
            path: "artifacts/p2/receipt.json",
            sha256: hash("f"),
            freezeCommit: "1".repeat(40),
          },
        ],
      }),
    /Receipt/i,
  );

  const finalProfileBaseline = {
    ...executionBaseline,
    acceptanceProfile: {
      path: "implementation/p2/acceptance/p2-acceptance-profile.v2.json",
      sha256: hash("f"),
    },
  };
  const finalProfileDigest =
    p2AcceptanceDigests.executionBaseline(finalProfileBaseline);
  assert.match(finalProfileDigest, /^sha256:[a-f0-9]{64}$/);
  assert.notEqual(finalProfileDigest, executionBaselineDigest);
  assert.equal(
    Object.hasOwn(finalProfileBaseline, "executionBaselineRecipe"),
    false,
  );
});

function semanticFixture({
  ownerAssignment = {
    principalRef: "principal:quality-owner",
    role: "QUALITY_RELEASE_OWNER",
    assignmentEvidenceId: "p2e_owner_assignment",
    validFrom: "2026-07-27T00:00:00.000Z",
    validUntil: null,
  },
  reviewerResolution = {
    independent: true,
    conflicts: [],
  },
  gitBlobOverride = undefined,
  criterionOverrides = {},
  applicabilityPredicate = undefined,
  executionBaselineOverride = undefined,
  artifactManifestOverride = undefined,
  profileApprovalAvailable = true,
  resolvedIndexDocumentOverride = undefined,
  metricEvidenceContent = Buffer.from('{"passed":10,"attempts":10}\n'),
  artifactSubjectContent = Buffer.from(
    "export const qualityResult = true;\n",
  ),
  artifactSubjectPath = "lib/quality-check.mjs",
  artifactSubjectKind = "SOURCE",
  additionalIndexedEvidence = [],
} = {}) {
  const criterion = {
    criterionId: "O06-Q01",
    receiptKind: "QUALITY_GATE_ACCEPTANCE",
    ownerRole: "QUALITY_RELEASE_OWNER",
    applicability: "REQUIRED",
    independentReviewRequired: true,
    metricPolicy: [
      {
        metricId: "quality_success_percent",
        calculation: "RATIO_PERCENT",
        operator: "GTE",
        threshold: 100,
        expectedAttemptCount: 10,
      },
    ],
    ...criterionOverrides,
  };
  const profile = {
    schemaVersion: "p2-acceptance-profile.v2",
    scopeKind: "SYNTHETIC",
    criteria: [criterion],
  };
  const profileBytes = Buffer.from(`${JSON.stringify(profile, null, 2)}\n`);
  const profileSha256 = hashBytes(profileBytes);
  const executionBaseline = {
    schemaVersion: "p2-execution-baseline.v1",
    sourceCommit: "1".repeat(40),
    acceptanceProfile: {
      path: "implementation/p2/acceptance/p2-acceptance-profile.v2.candidate.json",
      sha256: profileSha256,
    },
    receiptSchema: {
      path: "implementation/p2/acceptance/p2-acceptance-receipt.v2.schema.json",
      version: "p2-acceptance-receipt.v2",
      sha256: hash("b"),
    },
    semanticValidator: {
      path: "lib/p2-acceptance-receipt-validator.mjs",
      version: "p2-acceptance-validator.v2",
      sha256: hash("c"),
    },
    fixtures: [
      {
        name: "synthetic-fixture-inventory",
        path: "implementation/p0/f02/fixture-inventory.v1.json",
        sha256: hash("d"),
      },
    ],
    toolLocks: [
      {
        name: "ajv",
        version: "8.20.0",
        digest: hash("e"),
      },
    ],
  };
  const executionBaselineDigest =
    p2AcceptanceDigests.executionBaseline(executionBaseline);
  const receiptEvidenceContents = new Map([
    ["p2e_metric_result", metricEvidenceContent],
    ["p2e_owner_assignment", Buffer.from('{"owner":"quality-owner"}\n')],
    ["p2e_reviewer_assignment", Buffer.from('{"reviewer":"reviewer-2"}\n')],
  ]);
  const rawEvidence = [...receiptEvidenceContents.entries()].map(
    ([evidenceId, content], index) => ({
      evidenceId,
      path: `artifacts/p2/${evidenceId}.json`,
      sha256: hashBytes(content),
      mediaType: "application/json",
      freezeCommit: String(index + 1).repeat(40),
      executionBaselineDigest,
    }),
  );
  const indexedOnlyEntries = additionalIndexedEvidence.map(
    ({ evidenceId, content, path }, index) => ({
      evidenceId,
      path: path ?? `artifacts/p2/${evidenceId}.json`,
      sha256: hashBytes(content),
      mediaType: "application/json",
      freezeCommit: String(index + 5).repeat(40),
      executionBaselineDigest,
      criterionId: criterion.criterionId,
      acceptanceProfileSha256: profileSha256,
    }),
  );
  const evidenceContents = new Map([
    ...receiptEvidenceContents,
    ...additionalIndexedEvidence.map(({ evidenceId, content }) => [
      evidenceId,
      content,
    ]),
  ]);
  const evidenceIndex = {
    schemaVersion: "p2-evidence-index.v1",
    executionBaselineDigest,
    entries: [
      ...rawEvidence.map((entry, index) => ({
        ...entry,
        criterionId: criterion.criterionId,
        acceptanceProfileSha256: profileSha256,
        ...(index === 0 && applicabilityPredicate !== undefined
          ? { applicabilityPredicate }
          : {}),
      })),
      ...indexedOnlyEntries,
    ],
  };
  const evidenceIndexBytes = Buffer.from(
    `${JSON.stringify(evidenceIndex, null, 2)}\n`,
  );
  const evidenceIndexDigest =
    p2AcceptanceDigests.evidenceIndex(evidenceIndexBytes);
  const artifactManifest = {
    schemaVersion: "p2-artifact-manifest.v1",
    artifacts: [
      {
        kind: artifactSubjectKind,
        path: artifactSubjectPath,
        sha256: hashBytes(artifactSubjectContent),
        freezeCommit: "4".repeat(40),
      },
    ],
  };
  const artifactContents = new Map([
    [artifactSubjectPath, artifactSubjectContent],
  ]);
  const artifactManifestDigest =
    p2AcceptanceDigests.artifactManifest(artifactManifest);
  const finalReleaseDigest = p2AcceptanceDigests.finalRelease({
    executionBaselineDigest,
    evidenceIndexDigest,
    artifactManifestDigest,
  });
  const release = {
    schemaVersion: "p2-final-release.v1",
    executionBaselineDigest,
    evidenceIndexDigest,
    artifactManifestDigest,
    finalReleaseDigest,
  };
  const receipt = validPassReceipt();
  receipt.criterionId = criterion.criterionId;
  receipt.receiptKind = criterion.receiptKind;
  receipt.owner.role = criterion.ownerRole;
  receipt.acceptanceProfileSha256 = profileSha256;
  receipt.finalReleaseDigest = finalReleaseDigest;
  receipt.rawEvidence = rawEvidence;

  const validator = createP2AcceptanceReceiptValidator({
    validateStructure: (candidate) => ({
      valid: validate(candidate),
      errors: structuredClone(validate.errors ?? []),
    }),
    resolveApprovedProfile: async () =>
      profileApprovalAvailable
        ? {
            profile,
            profileBytes,
            approval: {
              profile_sha256: profileSha256,
              execution_baseline_digest: executionBaselineDigest,
            },
          }
        : null,
    resolveFinalRelease: async () => release,
    resolveExecutionBaseline: async () =>
      executionBaselineOverride ?? executionBaseline,
    resolveEvidenceIndex: async () => ({
      document: resolvedIndexDocumentOverride ?? evidenceIndex,
      bytes: evidenceIndexBytes,
    }),
    resolveArtifactManifest: async () =>
      artifactManifestOverride ?? artifactManifest,
    resolveOwnerAssignment: async () => ownerAssignment,
    resolveReviewerConflicts: async () => reviewerResolution,
    readGitBlob: async ({ evidenceId, path }) =>
      gitBlobOverride === undefined
        ? evidenceContents.get(evidenceId) ??
          artifactContents.get(path) ??
          null
        : gitBlobOverride,
    now: () => "2026-07-28T02:00:00.000Z",
  });

  return {
    artifactManifest,
    evidenceIndex,
    executionBaseline,
    receipt,
    validator,
  };
}

test("semantic validator accepts a fully bound PASS and rejects a self-reported false PASS", async () => {
  const { receipt, validator } = semanticFixture();
  const accepted = await validator.validate(receipt);
  assert.equal(accepted.receiptValid, true);
  assert.equal(accepted.derivedDecision, "PASS");
  assert.equal(accepted.completionEligible, true);

  const falsePass = structuredClone(receipt);
  falsePass.metricResults[0].numerator = 9;
  falsePass.metricResults[0].value = 90;
  const rejected = await validator.validate(falsePass);
  assert.equal(rejected.receiptValid, false);
  assert.equal(
    rejected.errors.some(({ code }) => code === "METRIC_RESULT_MISMATCH"),
    true,
  );
});

test("semantic validator reproduces the execution baseline and artifact manifest digests", async () => {
  const original = semanticFixture();
  {
    const { receipt, validator } = semanticFixture({
      executionBaselineOverride: {
        ...original.executionBaseline,
        sourceCommit: "2".repeat(40),
      },
    });
    const result = await validator.validate(receipt);
    assert.equal(result.receiptValid, false);
    assert.equal(
      result.errors.some(
        ({ code }) => code === "EXECUTION_BASELINE_DIGEST_MISMATCH",
      ),
      true,
    );
  }
  {
    const { receipt, validator } = semanticFixture({
      artifactManifestOverride: {
        ...original.artifactManifest,
        artifacts: [
          {
            kind: "SOURCE",
            path: "lib/quality-check.mjs",
            sha256: hash("f"),
            freezeCommit: "4".repeat(40),
          },
        ],
      },
    });
    const result = await validator.validate(receipt);
    assert.equal(result.receiptValid, false);
    assert.equal(
      result.errors.some(
        ({ code }) => code === "ARTIFACT_MANIFEST_DIGEST_MISMATCH",
      ),
      true,
    );
  }
});

test("semantic validator trusts only the digest-verified evidence index bytes", async () => {
  const original = semanticFixture();
  const forgedDocument = structuredClone(original.evidenceIndex);
  forgedDocument.entries[0].path = "artifacts/p2/forged-result.json";
  const { receipt, validator } = semanticFixture({
    resolvedIndexDocumentOverride: forgedDocument,
  });
  receipt.rawEvidence[0].path = "artifacts/p2/forged-result.json";

  const result = await validator.validate(receipt);
  assert.equal(result.receiptValid, false);
  assert.equal(
    result.errors.some(({ code }) => code === "EVIDENCE_NOT_IN_INDEX"),
    true,
  );
});

test("Receipt content cannot be relabelled as evidence or another release artifact", async () => {
  const disguisedReceipt = Buffer.from(
    '{"schemaVersion":"p2-acceptance-receipt.v2","receiptId":"p2r_disguised_01"}\n',
  );
  for (const fixtureOptions of [
    { metricEvidenceContent: disguisedReceipt },
    {
      additionalIndexedEvidence: [
        {
          evidenceId: "p2e_unreferenced_receipt",
          content: disguisedReceipt,
        },
      ],
    },
    {
      artifactSubjectContent: disguisedReceipt,
      artifactSubjectKind: "SOURCE",
      artifactSubjectPath: "artifacts/p2/disguised-result.json",
    },
  ]) {
    const { receipt, validator } = semanticFixture(fixtureOptions);
    const result = await validator.validate(receipt);
    assert.equal(result.receiptValid, false);
    assert.equal(
      result.errors.some(
        ({ code }) => code === "RECEIPT_INCLUDED_IN_RELEASE",
      ),
      true,
    );
  }

  for (const schemaVersion of [
    "p2-evidence-index.v1",
    "p2-final-release.v1",
  ]) {
    const forbiddenDocument = Buffer.from(
      `${JSON.stringify({ schemaVersion })}\n`,
    );
    for (const fixtureOptions of [
      { metricEvidenceContent: forbiddenDocument },
      {
        artifactSubjectContent: forbiddenDocument,
        artifactSubjectKind: "SOURCE",
        artifactSubjectPath: `artifacts/p2/${schemaVersion}.json`,
      },
    ]) {
      const { receipt, validator } = semanticFixture(fixtureOptions);
      const result = await validator.validate(receipt);
      assert.equal(result.receiptValid, false);
      assert.equal(
        result.errors.some(
          ({ code }) => code === "RELEASE_CONTROL_DOCUMENT_INCLUDED",
        ),
        true,
      );
    }
  }
});

test("semantic validator rejects time, Profile, Release, Owner, reviewer and Git integrity mismatches", async () => {
  {
    const { receipt, validator } = semanticFixture();
    receipt.finishedAt = "2026-07-28T00:59:59.000Z";
    const result = await validator.validate(receipt);
    assert.equal(result.receiptValid, false);
    assert.equal(
      result.errors.some(({ code }) => code === "INVALID_TIME_ORDER"),
      true,
    );
  }
  {
    const { receipt, validator } = semanticFixture();
    receipt.acceptanceProfileSha256 = hash("f");
    const result = await validator.validate(receipt);
    assert.equal(
      result.errors.some(({ code }) => code === "PROFILE_HASH_MISMATCH"),
      true,
    );
  }
  {
    const { receipt, validator } = semanticFixture();
    receipt.finalReleaseDigest = hash("f");
    const result = await validator.validate(receipt);
    assert.equal(
      result.errors.some(
        ({ code }) => code === "FINAL_RELEASE_DIGEST_MISMATCH",
      ),
      true,
    );
  }
  {
    const { receipt, validator } = semanticFixture();
    receipt.owner.role = "quality_release_owner";
    const result = await validator.validate(receipt);
    assert.equal(result.receiptValid, false);
    assert.equal(
      result.errors.some(({ code }) => code === "RECEIPT_SCHEMA_INVALID"),
      true,
    );
  }
  {
    const { receipt, validator } = semanticFixture();
    receipt.owner.role = "SECURITY_RELEASE_OWNER";
    const result = await validator.validate(receipt);
    assert.equal(result.receiptValid, false);
    assert.equal(
      result.errors.some(({ code }) => code === "OWNER_ROLE_MISMATCH"),
      true,
    );
  }
  {
    const { receipt, validator } = semanticFixture({
      profileApprovalAvailable: false,
    });
    const result = await validator.validate(receipt);
    assert.equal(result.receiptValid, false);
    assert.equal(
      result.errors.some(({ code }) => code === "PROFILE_NOT_ACTIVATED"),
      true,
    );
  }
  {
    const { receipt, validator } = semanticFixture({
      reviewerResolution: {
        independent: false,
        conflicts: ["IMPLEMENTER"],
      },
    });
    const result = await validator.validate(receipt);
    assert.equal(
      result.errors.some(
        ({ code }) => code === "REVIEWER_CONFLICT_OF_INTEREST",
      ),
      true,
    );
  }
  {
    const { receipt, validator } = semanticFixture({
      gitBlobOverride: null,
    });
    const result = await validator.validate(receipt);
    assert.equal(
      result.errors.some(
        ({ code }) => code === "EVIDENCE_NOT_IN_GIT_FREEZE",
      ),
      true,
    );
  }
});

test("semantic validator rejects hidden zero-tolerance findings and incomplete attempt denominators", async () => {
  {
    const { receipt, validator } = semanticFixture();
    receipt.findings.push({
      findingId: "p2f_critical_01",
      severity: "CRITICAL",
      zeroTolerance: true,
      summary: "发现跨 Tenant 泄漏。",
      evidenceIds: ["p2e_metric_result"],
    });
    const result = await validator.validate(receipt);
    assert.equal(result.receiptValid, false);
    assert.equal(
      result.errors.some(
        ({ code }) => code === "ZERO_TOLERANCE_COUNT_MISMATCH",
      ),
      true,
    );
  }
  {
    const { receipt, validator } = semanticFixture();
    receipt.metricResults[0].numerator = 9;
    receipt.metricResults[0].denominator = 9;
    receipt.metricResults[0].value = 100;
    const result = await validator.validate(receipt);
    assert.equal(
      result.errors.some(
        ({ code }) => code === "ATTEMPT_DENOMINATOR_INCOMPLETE",
      ),
      true,
    );
  }
});

test("a single-implementer Receipt remains truthfully INCONCLUSIVE", async () => {
  const { receipt, validator } = semanticFixture();
  receipt.reviewer = null;
  receipt.decision = "INCONCLUSIVE";
  const result = await validator.validate(receipt);
  assert.equal(result.receiptValid, true);
  assert.equal(result.derivedDecision, "INCONCLUSIVE");
  assert.equal(result.observedOutcome, "PASS");
  assert.equal(result.completionEligible, false);
  assert.equal(
    result.blockers.some(
      ({ code }) => code === "INDEPENDENT_REVIEW_UNAVAILABLE",
    ),
    true,
  );
});

test("the Product Owner cannot substitute their approval for independent review", async () => {
  const { receipt, validator } = semanticFixture({
    reviewerResolution: {
      independent: false,
      conflicts: ["PRODUCT_OWNER_IS_IMPLEMENTER"],
    },
  });
  receipt.reviewer.principalRef = "principal:product-owner";
  const result = await validator.validate(receipt);
  assert.equal(result.receiptValid, false);
  assert.equal(result.completionEligible, false);
  assert.equal(
    result.errors.some(
      ({ code }) => code === "REVIEWER_CONFLICT_OF_INTEREST",
    ),
    true,
  );
});

function conditionalNotApplicableFixture(applicabilityPredicate) {
  const fixture = semanticFixture({
    ownerAssignment: {
      principalRef: "principal:quality-owner",
      role: "SUPPLY_CHAIN_OWNER",
      assignmentEvidenceId: "p2e_owner_assignment",
      validFrom: "2026-07-27T00:00:00.000Z",
      validUntil: null,
    },
    criterionOverrides: {
      criterionId: "C17-AC09",
      receiptKind: "CROSS_STAGE_ACCEPTANCE",
      ownerRole: "SUPPLY_CHAIN_OWNER",
      applicability:
        "CONDITIONAL_IF_RELEASE_EXPOSES_WEBHOOK_OTHERWISE_SIGNED_NA",
      applicabilityRule: {
        predicateRef: "release.capabilities.webhookExposed",
        notApplicableWhen: false,
      },
      metricPolicy: [],
    },
    applicabilityPredicate,
  });
  fixture.receipt.applicabilityAssertion = {
    status: "NOT_APPLICABLE",
    predicateRef: "release.capabilities.webhookExposed",
    evidenceIds: ["p2e_metric_result"],
  };
  fixture.receipt.metricResults = [];
  fixture.receipt.decision = "NOT_APPLICABLE";
  return fixture;
}

test("NOT_APPLICABLE is limited to a frozen false conditional predicate", async () => {
  {
    const { receipt, validator } = semanticFixture();
    receipt.applicabilityAssertion = {
      status: "NOT_APPLICABLE",
      predicateRef: "release.capabilities.webhookExposed",
      evidenceIds: ["p2e_metric_result"],
    };
    receipt.metricResults = [];
    receipt.decision = "NOT_APPLICABLE";
    const result = await validator.validate(receipt);
    assert.equal(
      result.errors.some(
        ({ code }) => code === "NOT_APPLICABLE_FOR_REQUIRED_CRITERION",
      ),
      true,
    );
  }
  {
    const { receipt, validator } = conditionalNotApplicableFixture(undefined);
    receipt.decision = "INCONCLUSIVE";
    const result = await validator.validate(receipt);
    assert.equal(result.receiptValid, true);
    assert.equal(result.derivedDecision, "INCONCLUSIVE");
    assert.equal(
      result.blockers.some(
        ({ code }) => code === "APPLICABILITY_FACT_UNKNOWN",
      ),
      true,
    );
  }
  {
    const { receipt, validator } = conditionalNotApplicableFixture({
      predicateRef: "release.capabilities.webhookExposed",
      value: true,
    });
    const result = await validator.validate(receipt);
    assert.equal(result.receiptValid, false);
    assert.equal(
      result.errors.some(
        ({ code }) => code === "NOT_APPLICABLE_PREDICATE_MISMATCH",
      ),
      true,
    );
  }
  {
    const { receipt, validator } = conditionalNotApplicableFixture({
      predicateRef: "release.capabilities.webhookExposed",
      value: false,
    });
    const result = await validator.validate(receipt);
    assert.equal(result.receiptValid, true);
    assert.equal(result.derivedDecision, "NOT_APPLICABLE");
  }
  {
    const { receipt, validator } = conditionalNotApplicableFixture({
      predicateRef: "release.capabilities.webhookExposed",
      value: false,
    });
    receipt.reviewer = null;
    receipt.decision = "INCONCLUSIVE";
    const result = await validator.validate(receipt);
    assert.equal(result.receiptValid, true);
    assert.equal(result.derivedDecision, "INCONCLUSIVE");
    assert.equal(result.completionEligible, false);
  }
});

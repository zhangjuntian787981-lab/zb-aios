import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  referenceReviewDigests,
  validateReferenceReviewReceipt,
} from "../lib/reference-review-receipt-validator.mjs";

const schema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/schemas/reference-review-receipt.v1.schema.json",
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
const validateSchema = ajv.compile(schema);

const digest = (character) => `sha256:${character.repeat(64)}`;

async function validReceipt(decision = "ADOPT") {
  const receipt = {
    schemaVersion: "reference-review-receipt.v1",
    receiptId: `rrr_o02_openbao_${decision.toLowerCase()}`,
    workPackageId: "O02",
    reviewMode: "PROSPECTIVE",
    reviewBoundary: "DEPENDENCY_ADOPTION",
    applicableReferenceSetDigest: digest("a"),
    referenceCatalogSha256: digest("b"),
    referencePolicySha256: digest("c"),
    profileSha256: digest("d"),
    referenceId: "R26.OPENBAO",
    referenceKind: "OPEN_SOURCE_PROJECT",
    referenceName: "OpenBao",
    officialSources: [
      {
        sourceId: "src_openbao_docs",
        uri: "https://openbao.org/docs/",
        authority: "OpenBao",
        sourceKind: "OFFICIAL_DOCUMENTATION",
        observedAt: "2026-07-29T01:00:00.000Z",
        contentEvidenceRef:
          "implementation/p2/reference-reviews/fixtures/openbao-docs.txt",
        contentSha256: digest("e"),
      },
      {
        sourceId: "src_openbao_license",
        uri: "https://github.com/openbao/openbao/blob/v2.4.4/LICENSE",
        authority: "OpenBao",
        sourceKind: "OFFICIAL_LICENSE_TEXT",
        observedAt: "2026-07-29T01:00:00.000Z",
        contentEvidenceRef:
          "implementation/p2/reference-reviews/fixtures/openbao-license.txt",
        contentSha256: digest("f"),
      },
    ],
    reviewedMaterials: [
      {
        materialId: "mat_openbao_release",
        sourceId: "src_openbao_docs",
        materialKind: "RELEASE",
        documentationVersion: "2.4",
        sourceCommit: "1".repeat(40),
        release: "v2.4.4",
        imageDigest: digest("1"),
        artifactDigest: digest("2"),
      },
    ],
    reviewedSections: [
      {
        sourceId: "src_openbao_docs",
        locator: "docs/secrets/",
        topic: "dynamic secret leases and revocation",
        notesRef:
          "implementation/p2/reference-reviews/fixtures/openbao-notes.txt",
        notesDigest: digest("3"),
      },
    ],
    reviewedAt: "2026-07-29T01:10:00.000Z",
    capabilityGap: {
      summary: "O02 requires short-lived dynamic credentials.",
      currentMeasure: "No production secrets runtime is selected.",
      targetMeasure: "Leases and forced revocation meet the P2 Profile.",
      evidenceRef: "implementation/p2/reference-reviews/fixtures/gap.json",
      evidenceHash: digest("4"),
    },
    currentImplementation: {
      status: "CANDIDATE",
      summary: "The Product Core exposes only a secrets-system interface.",
      evidenceRefs: [
        "implementation/p2/reference-reviews/fixtures/current.json",
      ],
      evidenceHashes: [digest("5")],
    },
    alternativesCompared: [
      {
        alternativeId: "alt_current_interface",
        name: "Current interface only",
        kind: "CURRENT_IMPLEMENTATION",
        versionOrStandard: "source baseline",
        advantages: ["No new runtime dependency."],
        risks: ["Cannot issue production dynamic credentials."],
        disposition: "FALLBACK",
      },
      {
        alternativeId: "alt_openbao",
        name: "OpenBao",
        kind: "OPEN_SOURCE_PROJECT",
        versionOrStandard: "v2.4.4",
        advantages: ["Supports leases and revocation."],
        risks: ["Adds an operational control plane."],
        disposition: "SELECTED",
      },
    ],
    licenseAndRedistributionAssessment: {
      licenseId: "MPL-2.0",
      licenseSourceId: "src_openbao_license",
      reviewedVersion: "v2.4.4",
      usageMode: "NETWORK_SERVICE",
      distributionMode: "not redistributed in the synthetic PoC",
      obligations: ["Preserve applicable license notices."],
      brandRestrictions: [],
      commercialRestrictions: [],
      conclusion: "ACCEPTABLE",
      rationale: "The reviewed network-service use is compatible with the PoC.",
    },
    securityAndDataFlowAssessment: {
      dataClasses: ["SYNTHETIC_SECRET"],
      ingress: ["synthetic lease request"],
      egress: ["short-lived synthetic credential"],
      storage: ["encrypted service state"],
      networkAccess: ["allowlisted service endpoint"],
      privileges: ["dedicated unprivileged workload identity"],
      secretHandling: ["never enter source, logs, or response evidence"],
      trustBoundaries: ["Product Core to secrets service"],
      knownRisks: ["lease revocation delay"],
      conclusion: "ACCEPTABLE",
      rationale: "The PoC is synthetic and isolates the service boundary.",
    },
    maintenanceAndExitAssessment: {
      operationalOwnerRole: "SECRETS_SYSTEM_OWNER",
      upstreamHealth: "Release and security advisory monitoring required.",
      upgradeCadence: "Quarterly review and urgent security updates.",
      onCallResponsibility: "P2 platform operations owner.",
      backupAndRecoveryResponsibility: "P2 state recovery owner.",
      costResponsibility: "Product operations budget.",
      exitPlanStatus: "DEFINED",
      exitPlan: "Disable issuance, revoke leases, export only approved metadata.",
      migrationTarget: "A compatible secrets-system adapter.",
      stopMaintenanceTrigger: "Unsupported release or unacceptable license change.",
    },
    decision,
    decisionReason: "The decision follows the reviewed gap and comparison.",
    alternativePath: null,
    reReviewTrigger: null,
    notApplicableReason: null,
    pocRequired: true,
    pocResult: {
      status: "PASS",
      summary: "Synthetic lease and revocation checks passed.",
      evidenceRefs: [
        "implementation/p2/reference-reviews/fixtures/openbao-poc.json",
      ],
      evidenceHashes: [digest("6")],
    },
    adrRef: "docs/adr/0006-reference-review-before-work-start.md",
    ownerRole: "SECRETS_SYSTEM_OWNER",
    evidenceRefs: [
      "implementation/p2/reference-reviews/fixtures/openbao-review.json",
    ],
    evidenceHashes: [digest("7")],
    sourceCommit: "8".repeat(40),
    supersedesReceiptId: null,
    governanceEffect: "NONE",
    isProgressTracker: false,
    selfAuthorizing: false,
    productionAdoptionClaim: false,
    receiptSha256: digest("0"),
  };
  if (decision === "REJECT") {
    receipt.alternativesCompared[0].disposition = "SELECTED";
    receipt.alternativesCompared[1].disposition = "NOT_SELECTED";
    receipt.alternativePath = "Retain the current interface and do not lock OpenBao.";
    receipt.pocRequired = false;
    receipt.pocResult = {
      status: "NOT_REQUIRED",
      summary: "The candidate was rejected before PoC.",
      evidenceRefs: [],
      evidenceHashes: [],
    };
    receipt.adrRef = null;
  }
  if (decision === "DEFER") {
    receipt.alternativesCompared[0].disposition = "SELECTED";
    receipt.alternativesCompared[1].disposition = "NOT_SELECTED";
    receipt.reReviewTrigger = {
      triggerKind: "CAPABILITY_GAP_REACHED",
      condition: "Re-review before a secrets runtime enters the dependency lock.",
      beforeBoundary: "DEPENDENCY_ADOPTION",
    };
    receipt.pocRequired = false;
    receipt.pocResult = {
      status: "NOT_REQUIRED",
      summary: "PoC is deferred with the adoption decision.",
      evidenceRefs: [],
      evidenceHashes: [],
    };
    receipt.adrRef = null;
  }
  if (decision === "NOT_APPLICABLE") {
    receipt.alternativesCompared[0].disposition = "SELECTED";
    receipt.alternativesCompared[1].disposition = "NOT_SELECTED";
    receipt.notApplicableReason =
      "This synthetic work-package variant never handles runtime credentials.";
    receipt.pocRequired = false;
    receipt.pocResult = {
      status: "NOT_REQUIRED",
      summary: "No PoC is needed for an inapplicable candidate.",
      evidenceRefs: [],
      evidenceHashes: [],
    };
    receipt.adrRef = null;
  }
  receipt.receiptSha256 = await referenceReviewDigests.receipt(receipt);
  return receipt;
}

test("a complete ADOPT Reference Review Receipt passes structure and semantics", async () => {
  const receipt = await validReceipt();

  assert.equal(
    validateSchema(receipt),
    true,
    ajv.errorsText(validateSchema.errors),
  );
  assert.deepEqual(await validateReferenceReviewReceipt(receipt), {
    ok: true,
    status: "VALID",
    reasonCodes: [],
  });
});

for (const decision of [
  "REJECT",
  "DEFER",
  "NOT_APPLICABLE",
]) {
  test(`a complete ${decision} Reference Review Receipt passes`, async () => {
    const receipt = await validReceipt(decision);

    assert.equal(
      validateSchema(receipt),
      true,
      ajv.errorsText(validateSchema.errors),
    );
    assert.deepEqual(await validateReferenceReviewReceipt(receipt), {
      ok: true,
      status: "VALID",
      reasonCodes: [],
    });
  });
}

async function mutateReceipt(mutator) {
  const receipt = await validReceipt();
  mutator(receipt);
  receipt.receiptSha256 = await referenceReviewDigests.receipt(receipt);
  return receipt;
}

test("missing official source, exact version or reviewed sections is rejected", async () => {
  const missingSource = await mutateReceipt((receipt) => {
    receipt.officialSources = [];
  });
  const missingVersion = await mutateReceipt((receipt) => {
    receipt.reviewedMaterials[0] = {
      ...receipt.reviewedMaterials[0],
      documentationVersion: null,
      sourceCommit: null,
      release: null,
      imageDigest: null,
      artifactDigest: null,
    };
  });
  const missingSections = await mutateReceipt((receipt) => {
    receipt.reviewedSections = [];
  });

  assert.match(
    (await validateReferenceReviewReceipt(missingSource)).reasonCodes.join(),
    /REFERENCE_OFFICIAL_SOURCE_NOT_PROVED/,
  );
  assert.match(
    (await validateReferenceReviewReceipt(missingVersion)).reasonCodes.join(),
    /REFERENCE_VERSION_NOT_PINNED/,
  );
  assert.match(
    (await validateReferenceReviewReceipt(missingSections)).reasonCodes.join(),
    /REFERENCE_REVIEWED_SECTIONS_MISSING/,
  );
});

test("ADOPT requires license, security, maintenance, exit, ADR and required PoC", async () => {
  const cases = [
    [
      "REFERENCE_ADOPT_LICENSE_INCOMPLETE",
      (receipt) => {
        receipt.licenseAndRedistributionAssessment.conclusion = "UNRESOLVED";
      },
    ],
    [
      "REFERENCE_ADOPT_SECURITY_DATA_FLOW_INCOMPLETE",
      (receipt) => {
        receipt.securityAndDataFlowAssessment.conclusion = "UNRESOLVED";
      },
    ],
    [
      "REFERENCE_ADOPT_MAINTENANCE_EXIT_INCOMPLETE",
      (receipt) => {
        receipt.maintenanceAndExitAssessment.exitPlanStatus = "UNRESOLVED";
      },
    ],
    [
      "REFERENCE_ADOPT_ADR_MISSING",
      (receipt) => {
        receipt.adrRef = null;
      },
    ],
    [
      "REFERENCE_ADOPT_POC_NOT_PASSED",
      (receipt) => {
        receipt.pocResult.status = "FAIL";
      },
    ],
  ];

  for (const [reasonCode, mutator] of cases) {
    const result = await validateReferenceReviewReceipt(
      await mutateReceipt(mutator),
    );
    assert.equal(result.ok, false, reasonCode);
    assert.ok(result.reasonCodes.includes(reasonCode), result.reasonCodes);
  }
});

test("REJECT, DEFER and NOT_APPLICABLE require their decision-specific rationale", async () => {
  const reject = await validReceipt("REJECT");
  reject.alternativePath = null;
  reject.receiptSha256 = await referenceReviewDigests.receipt(reject);
  const defer = await validReceipt("DEFER");
  defer.reReviewTrigger = null;
  defer.receiptSha256 = await referenceReviewDigests.receipt(defer);
  const notApplicable = await validReceipt("NOT_APPLICABLE");
  notApplicable.notApplicableReason = null;
  notApplicable.receiptSha256 =
    await referenceReviewDigests.receipt(notApplicable);

  assert.ok(
    (await validateReferenceReviewReceipt(reject)).reasonCodes.includes(
      "REFERENCE_REJECT_PATH_MISSING",
    ),
  );
  assert.ok(
    (await validateReferenceReviewReceipt(defer)).reasonCodes.includes(
      "REFERENCE_DEFER_TRIGGER_MISSING",
    ),
  );
  assert.ok(
    (
      await validateReferenceReviewReceipt(notApplicable)
    ).reasonCodes.includes("REFERENCE_NOT_APPLICABLE_REASON_MISSING"),
  );
});

test("Receipt hash tampering and production-adoption claims are rejected", async () => {
  const tampered = await validReceipt();
  tampered.decisionReason = "Changed after hashing.";
  const productionClaim = await mutateReceipt((receipt) => {
    receipt.productionAdoptionClaim = true;
  });

  assert.ok(
    (await validateReferenceReviewReceipt(tampered)).reasonCodes.includes(
      "REFERENCE_RECEIPT_HASH_MISMATCH",
    ),
  );
  assert.ok(
    (
      await validateReferenceReviewReceipt(productionClaim)
    ).reasonCodes.includes("REFERENCE_PRODUCTION_ADOPTION_CLAIM_FORBIDDEN"),
  );
});

test("the Receipt schema is closed and cannot carry governance approval", async () => {
  const receipt = await validReceipt();
  receipt.ready = true;
  receipt.receiptSha256 = await referenceReviewDigests.receipt(receipt);

  assert.equal(validateSchema(receipt), false);
  assert.match(ajv.errorsText(validateSchema.errors), /additional properties/);
  assert.ok(
    (await validateReferenceReviewReceipt(receipt)).reasonCodes.includes(
      "REFERENCE_RECEIPT_SCHEMA_CLOSED",
    ),
  );
});

test("the runtime Receipt validator enforces the nested closed Schema", async () => {
  const receipt = await validReceipt();
  receipt.schemaVersion = "attacker-controlled.v999";
  receipt.reviewMode = "ATTACKER_MODE";
  receipt.ownerRole = "";
  receipt.currentImplementation.ready = true;
  receipt.receiptSha256 = await referenceReviewDigests.receipt(receipt);

  const result = await validateReferenceReviewReceipt(receipt);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes("REFERENCE_RECEIPT_SCHEMA_INVALID"),
    result.reasonCodes,
  );
});

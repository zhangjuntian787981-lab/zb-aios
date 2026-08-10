import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  INDEPENDENT_REVIEW_ARTIFACT_SCHEMAS,
  validateActiveIndependentReviewPolicy,
  validateTargetedRemediationModelReviewEvidence,
} from "../lib/independent-review-artifact-validation.mjs";

const root = new URL("../", import.meta.url);
const paths = Object.freeze({
  activePolicy:
    "implementation/governance/independent-review/independent-review-policy.v2.json",
  activePolicySchema:
    "implementation/governance/schemas/independent-review-policy.v2.active.schema.json",
  activationAdr:
    "docs/adr/0022-independent-model-review-policy-v2-activation.md",
  evidence:
    "implementation/governance/independent-review/evidence/terra-targeted-remediation-ec8315c/targeted-remediation-model-review-evidence.v1.json",
  evidenceSchema:
    "implementation/governance/schemas/targeted-remediation-model-review-evidence.v1.schema.json",
});

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(",")}}`;
}

const sha256Bytes = (value) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;
const selfHash = (value, field) => {
  const copy = structuredClone(value);
  delete copy[field];
  return sha256Bytes(Buffer.from(canonicalize(copy), "utf8"));
};
const digest = (character) => `sha256:${character.repeat(64)}`;
const commit = (character) => character.repeat(40);
const readBytes = (path) => readFile(new URL(path, root));

const [activePolicyBytes, activePolicySchemaBytes, activationAdrBytes] =
  await Promise.all([
    readBytes(paths.activePolicy),
    readBytes(paths.activePolicySchema),
    readBytes(paths.activationAdr),
  ]);
const activePolicy = JSON.parse(activePolicyBytes);
const activePolicySchema = JSON.parse(activePolicySchemaBytes);

async function validateActivePolicy(instance) {
  return validateActiveIndependentReviewPolicy({
    policy: instance,
    schemaBytes: activePolicySchemaBytes,
  });
}

export async function assertActivePolicyContract() {
  assert.equal(
    sha256Bytes(activePolicyBytes),
    "sha256:1bc70e243ccf1d3dc0d202a300469f0e169b40632712f12d0910573e03ccff8d",
  );
  assert.equal(
    sha256Bytes(activePolicySchemaBytes),
    INDEPENDENT_REVIEW_ARTIFACT_SCHEMAS.activePolicy.sha256,
  );
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validateSchema = ajv.compile(activePolicySchema);
  assert.equal(validateSchema(activePolicy), true, ajv.errorsText(validateSchema.errors));
  assert.equal(activePolicy.policyId, "independent-review-policy-v2");
  assert.equal(activePolicy.policyVersion, "2.0.0");
  assert.equal(activePolicy.lifecycle, "ACTIVE");
  assert.equal(activePolicy.assuranceLevel, "MODEL_ONLY_PREPRODUCTION");
  assert.deepEqual(activePolicy.applicablePhases, ["P0", "P1", "P2"]);
  assert.equal(activePolicy.humanIndependentReviewRequired, false);
  assert.equal(activePolicy.humanIndependentReviewSatisfied, false);
  assert.equal(activePolicy.independentModelReviewRequired, true);
  assert.equal(activePolicy.p3HumanReviewRequired, true);
  assert.equal(activePolicy.policySha256, selfHash(activePolicy, "policySha256"));
  assert.deepEqual(await validateActivePolicy(activePolicy), {
    ok: true,
    status: "VALID",
    reasonCodes: [],
  });
  assert.equal(
    (
      await validateActiveIndependentReviewPolicy({
        policy: activePolicy,
        schemaBytes: Buffer.from('{"type":"object"}', "utf8"),
      })
    ).ok,
    false,
  );
}

export async function assertActivePolicyHistory(candidatePolicy) {
  assert.deepEqual(activePolicy.historicalTreatment, candidatePolicy.historicalTreatment);
  assert.deepEqual(activePolicy.activationBoundary, {
    effectiveFrom: "POLICY_ACTIVATION_GIT_COMMIT",
    prospectiveOnly: true,
    historicalEventsReclassified: false,
    d1StateChangedByActivation: false,
    p1B11StatusChangedByActivation: false,
  });
  const adr = activationAdrBytes.toString("utf8");
  assert.equal(
    sha256Bytes(activationAdrBytes),
    "sha256:640bda808f5fc3dc013dd5abca915ad25d90f1b06b14cd301815d65ba67ff1b1",
  );
  assert.match(adr, /Status: Accepted/u);
  assert.match(adr, /prospective/u);
  assert.match(adr, /INCONCLUSIVE_INDEPENDENT_HUMAN_REVIEWER_MISSING/u);
  assert.match(adr, /does not change P1-B11/u);
}

export async function assertActivePolicyMutationsFail() {
  for (const mutate of [
    (candidate) => (candidate.humanIndependentReviewRequired = true),
    (candidate) => (candidate.humanIndependentReviewSatisfied = true),
    (candidate) => (candidate.independentModelReviewRequired = false),
    (candidate) => (candidate.p3HumanReviewRequired = false),
    (candidate) => (candidate.requiredCheck.githubHumanApproveCreated = true),
    (candidate) => (candidate.activationBoundary.prospectiveOnly = false),
    (candidate) => (candidate.activationBoundary.historicalEventsReclassified = true),
  ]) {
    const candidate = structuredClone(activePolicy);
    mutate(candidate);
    candidate.policySha256 = selfHash(candidate, "policySha256");
    assert.equal((await validateActivePolicy(candidate)).ok, false);
  }
}

export async function assertActivePolicyP3MutationsFail() {
  for (const mutate of [
    (candidate) => candidate.p3HumanReviewBoundary.phases.pop(),
    (candidate) => candidate.p3HumanReviewBoundary.dataBoundaries.pop(),
    (candidate) => candidate.p3HumanReviewBoundary.highRiskScopes.push("SECRETS"),
    (candidate) =>
      (candidate.p3HumanReviewBoundary.modelReviewSubstitutionAllowed = true),
    (candidate) => candidate.allowedReviewScopes.pop(),
  ]) {
    const candidate = structuredClone(activePolicy);
    mutate(candidate);
    candidate.policySha256 = selfHash(candidate, "policySha256");
    assert.equal((await validateActivePolicy(candidate)).ok, false);
  }
}

export async function assertTargetedRemediationEvidenceAndHistory() {
  const preservedPaths = [
    "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
    "implementation/governance/schemas/independent-review-policy.v2.schema.json",
    "docs/adr/0011-independent-model-review-policy-v2-candidate.md",
    "implementation/governance/independent-review/evidence/terra-advisory-p0p1-7acf4c6/review-result.json",
    "implementation/governance/v5.3-supplemental-evidence-index.v2.json",
    "implementation/p2/acceptance/p2-acceptance-profile.v2.candidate.json",
    "implementation/governance/work-package-manifest.v1.json",
    "app/api/progress/route.ts",
  ];
  const [publicAttestationBytes, evidenceBytes, evidenceSchemaBytes, ...preserved] =
    await Promise.all([
      readBytes("implementation/governance/public-source-export-attestation.v1.json"),
      readBytes(paths.evidence),
      readBytes(paths.evidenceSchema),
      ...preservedPaths.map(readBytes),
    ]);
  assert.equal(
    sha256Bytes(publicAttestationBytes),
    "sha256:f96e8de2d9f3e3aa4fe0b9ef87391729d4d3cdfdf390ac6a78604d8f74bc652f",
  );
  assert.equal(
    JSON.parse(publicAttestationBytes).githubFreeP1B11.status,
    "INCONCLUSIVE_INDEPENDENT_REVIEWER_MISSING",
  );
  assert.deepEqual(JSON.parse(publicAttestationBytes).privateSource.protectedWorkingFiles, [
    {
      path: "README.md",
      sha256: "sha256:d047161065434d34a9d48429af95557b796eb0e156fe5125ec2c23d0cefec40d",
      includedInPublicRoot: false,
    },
    {
      path: "docs/plans/通用多企业AI员工平台_v5.1新增内容与开源参考对照表_v1.0.md",
      sha256: "sha256:01706419c90f144beb0191469eeefd2af5373dce0b2487034abff4b96ac9b205",
      includedInPublicRoot: false,
    },
    {
      path: "docs/plans/通用多企业AI员工平台_完备工程级方案_v5.2.md",
      sha256: "sha256:4561e29937b0f6315c882e74959cbc990bf84413732e8c91e542600b259f2fa8",
      includedInPublicRoot: false,
    },
  ]);
  assert.deepEqual(preserved.map(sha256Bytes), [
    "sha256:88a399e0d380fad1199ca2d9ef6fd20da29913c289df85c98c20b02dd8fc3d78",
    "sha256:bb7a8e48e8aa2c9fc019f8250bab94a5cbc8575e97939e77e13fc1313fd76626",
    "sha256:cbc3ac35caebf7d7013af46cf6939212d889d1870e4b7b003bdbb11186025737",
    "sha256:e820030bcd9935f3c2e336568ef0f71becefa6a50ffdd608a7a8404fe3263d78",
    "sha256:6327632b416687987e49fa207f1c4562647cb1298f276490822c85850ea8c05a",
    "sha256:90a9741d6ae39012458f073523da0c7b4dc8e4eef53ea759b32d6640e6aaef32",
    "sha256:e1dd21cab94ae4febbeef2ad4a14b72999270e49940fc2a50a7a3aea073cdc4d",
    "sha256:67f7d4363f8eaa98c0d268fa62a48dbc6c91464ed55cf0cd011a62b5d5debcdd",
  ]);

  assert.equal(
    sha256Bytes(evidenceBytes),
    "sha256:710c3295b3863a3ad48bd21821e19156a1b318b83c1014629652bd7b1ddc2789",
  );
  assert.equal(
    sha256Bytes(evidenceSchemaBytes),
    INDEPENDENT_REVIEW_ARTIFACT_SCHEMAS.targetedRemediationEvidence.sha256,
  );
  const evidence = JSON.parse(evidenceBytes);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validateSchema = ajv.compile(JSON.parse(evidenceSchemaBytes));
  assert.equal(validateSchema(evidence), true, ajv.errorsText(validateSchema.errors));
  assert.equal(evidence.evidenceSha256, selfHash(evidence, "evidenceSha256"));
  assert.deepEqual(
    await validateTargetedRemediationModelReviewEvidence({
      evidence,
      schemaBytes: evidenceSchemaBytes,
    }),
    { ok: true, status: "VALID", reasonCodes: [] },
  );
  assert.equal(evidence.formalReceiptIssued, false);
  assert.equal(evidence.governanceEffect, "NONE");
  assert.ok(
    Object.values(evidence.captureStatus).every(
      (value) => value === "NOT_CAPTURED_AT_SOURCE",
    ),
  );

  const mutations = [
    (value) => (value.reviewRounds[0].sourceCommit = commit("0")),
    (value) => (value.reviewRounds[1].sourceTree = commit("1")),
    (value) => (value.reviewRounds[0].findings[0].findingId = "wrong_finding"),
    (value) => (value.reviewRounds[0].decision = "CLEAR"),
    (value) => (value.reviewRounds[1].decision = "BLOCKED"),
    (value) => (value.reviewRounds[1].claimBoundary = "FULL_REPOSITORY"),
    (value) => (value.captureStatus.reviewerSessionId = "invented-session"),
    (value) => (value.formalReceiptIssued = true),
    (value) => (value.receiptSchemaVersion = "independent-model-review-receipt.v10"),
    (value) => (value.finalAssessment.humanIndependentReviewSatisfied = true),
    (value) => (value.finalAssessment.p1B11StatusChanged = true),
    (value) => value.remediationCommits.pop(),
  ];
  for (const mutate of mutations) {
    const candidate = structuredClone(evidence);
    mutate(candidate);
    candidate.evidenceSha256 = selfHash(candidate, "evidenceSha256");
    assert.equal(
      (
        await validateTargetedRemediationModelReviewEvidence({
          evidence: candidate,
          schemaBytes: evidenceSchemaBytes,
        })
      ).ok,
      false,
    );
  }
  const hashTamper = structuredClone(evidence);
  hashTamper.evidenceSha256 = digest("f");
  assert.equal(
    (
      await validateTargetedRemediationModelReviewEvidence({
        evidence: hashTamper,
        schemaBytes: evidenceSchemaBytes,
      })
    ).ok,
    false,
  );
  assert.equal(
    (
      await validateTargetedRemediationModelReviewEvidence({
        evidence,
        schemaBytes: Buffer.from('{"type":"object"}', "utf8"),
      })
    ).ok,
    false,
  );
}

const candidatePolicy = JSON.parse(
  await readBytes(
    "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  ),
);
await assertActivePolicyContract();
await assertActivePolicyHistory(candidatePolicy);
await assertActivePolicyMutationsFail();
await assertActivePolicyP3MutationsFail();
await assertTargetedRemediationEvidenceAndHistory();

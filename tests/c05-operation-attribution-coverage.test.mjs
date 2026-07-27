import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function text(relativePath) {
  return readFile(new URL(relativePath, import.meta.url), "utf8");
}

async function json(relativePath) {
  return JSON.parse(await text(relativePath));
}

const coverage = await json(
  "../implementation/p1/c05/operation-action-identity-coverage.v1.json",
);
const c08Source = await text("../lib/aios-state-core.mjs");
const c15Source = await text("../lib/human-decision-workflow.mjs");
const c15Authorizer = await text("../lib/c15-c06-authorizer.mjs");
const c18Source = await text("../lib/c18-audit-evidence.mjs");
const c15Api = await json(
  "../implementation/p1/c15/human-decision.openapi.v1.json",
);
const c18Api = await json(
  "../implementation/p1/c18/audit.openapi.v1.json",
);

const C08_HUMAN_OPERATIONS = Object.freeze([
  "C08_CREATE_CASE",
  "C08_OPEN_THREAD",
  "C08_RECORD_ARTIFACT_VERSION",
  "C08_START_RUN",
  "C08_PREPARE_TOOL_CALL",
  "C08_FINISH_RUN",
  "C08_INSPECT_RUN",
  "C08_RECONSTRUCT_RUN",
]);
const C15_OPERATIONS = Object.freeze([
  "C15_PREPARE_DRAFT",
  "C15_APPROVE_SYNTHETIC_TEST_DECISION",
  "C15_WITHDRAW_SYNTHETIC_TEST_DECISION",
  "C15_EXECUTE_SYNTHETIC_PREVIEW",
]);
const C18_HUMAN_OPERATIONS = Object.freeze(["appendAuditEvidence"]);
const POLICY_EXEMPT = Object.freeze([
  "C08_RECORD_TOOL_CALL_RESULT",
  "C08_SNAPSHOT",
  "queryAuditEvidence",
  "exportAuditEvidence",
  "restoreAuditEvidence",
]);

function openApiOperationIds(document) {
  return Object.values(document.paths).flatMap((pathItem) =>
    Object.values(pathItem)
      .map((operation) => operation.operationId)
      .filter(Boolean),
  );
}

test("C05-AC05 operation attribution denominator closes with zero unexplained operations", () => {
  assert.equal(coverage.workPackageId, "C05");
  assert.equal(coverage.acceptanceCriterionId, "C05-AC05");
  assert.equal(coverage.evidenceGroupId, "P1-B06");
  assert.equal(coverage.scope, "P1_SYNTHETIC_ONLY");
  assert.equal(
    coverage.requiredActionIdentityFields.includes(
      "humanSubject.principalId",
    ),
    true,
  );
  assert.equal(
    coverage.requiredActionIdentityFields.includes(
      "workloadActor.principalId",
    ),
    true,
  );
  assert.equal(
    coverage.requiredActionIdentityFields.includes(
      "delegationChain[].delegationId",
    ),
    true,
  );

  const covered = coverage.coveredOperations.map(
    ({ operationId }) => operationId,
  );
  assert.deepEqual(
    covered,
    [
      ...C08_HUMAN_OPERATIONS,
      ...C15_OPERATIONS,
      ...C18_HUMAN_OPERATIONS,
    ],
  );
  assert.deepEqual(
    coverage.policyExemptOperations.map(
      ({ operationId }) => operationId,
    ),
    POLICY_EXEMPT,
  );
  assert.equal(new Set([...covered, ...POLICY_EXEMPT]).size, 18);
  assert.deepEqual(coverage.coverageSummary, {
    inventoryOperations: 18,
    coveredHumanDelegatedOperations: 13,
    policyExemptOperations: 5,
    unexplainedOperations: 0,
  });
});

test("coverage entries resolve to implemented C08, C15 and C18 operation seams", () => {
  const implementedC08Commands = [
    ...new Set(
      [...c08Source.matchAll(/command\.kind\s*===\s*"([A-Z_]+)"/g)].map(
        (match) => `C08_${match[1]}`,
      ),
    ),
  ];
  assert.deepEqual(
    implementedC08Commands,
    [
      ...C08_HUMAN_OPERATIONS.slice(0, 6),
      "C08_RECORD_TOOL_CALL_RESULT",
    ],
  );
  for (const operationId of C08_HUMAN_OPERATIONS) {
    const command = operationId.replace(/^C08_/, "");
    assert.match(c08Source, new RegExp(`"${command}"`), operationId);
  }
  for (const operationId of C15_OPERATIONS) {
    assert.match(c15Authorizer, new RegExp(operationId), operationId);
    assert.equal(
      openApiOperationIds(c15Api).includes(operationId),
      true,
      operationId,
    );
  }
  assert.deepEqual(openApiOperationIds(c15Api), C15_OPERATIONS);
  assert.deepEqual(
    openApiOperationIds(c18Api),
    [
      "appendAuditEvidence",
      "queryAuditEvidence",
      "exportAuditEvidence",
      "restoreAuditEvidence",
    ],
  );
  assert.match(
    c08Source,
    /stablePrincipalRegistry\.resolveActionIdentity/,
  );
  assert.match(
    c15Source,
    /stablePrincipalRegistry\.resolveActionIdentity/,
  );
  assert.match(
    c18Source,
    /stablePrincipalRegistry\.resolveActionIdentity/,
  );
  assert.match(c18Source, /identity:\s*finalIdentity/);
});

test("every covered Human operation declares two-phase C05 resolution and a frozen verification test", () => {
  for (const entry of coverage.coveredOperations) {
    assert.equal(entry.actionIdentityResolution, "C05_FIRST_AND_FINAL");
    assert.match(entry.binding, /^(?:C08|C15|C18)_/);
    assert.match(entry.verificationTest, /^tests\/.+\.test\.mjs$/);
  }
  for (const entry of coverage.policyExemptOperations) {
    assert.equal(entry.reason.length > 0, true);
    assert.match(entry.authorityPath, /^(?:C08|C18)_/);
  }
  assert.equal(coverage.dataScope, "SYNTHETIC_ONLY");
  assert.equal(coverage.enterpriseSystems, "NOT_CONNECTED");
});

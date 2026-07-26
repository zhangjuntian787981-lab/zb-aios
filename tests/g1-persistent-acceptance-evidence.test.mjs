import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const root = new URL("../", import.meta.url);
const execFileAsync = promisify(execFile);
const repoPath = fileURLToPath(root);
const sourceCommit =
  "b0bdb6b60d46f5702b8d0d680d0de93aba611e17";
const approvedG0SubmissionSha256 =
  "sha256:77d8707a602a83729b557c028bd6cf87c5a0e5d921145b9dc3a5a1e79bf32a07";
const deploymentSha256 =
  "sha256:0ad6c07cea92ea050232b34af2bf1362e7599ae5f694a5c6d23968e18c066162";
const runtimeEvidencePath =
  "implementation/gates/g1/g1-persistent-runtime-evidence.v1.json";
const isolationEvidencePath =
  "implementation/gates/g1/g1-persistent-isolation-evidence.v1.json";
const acceptancePackagePath =
  "implementation/gates/g1/g1-acceptance-package.v1.json";

async function read(path) {
  return readFile(new URL(path, root));
}

async function json(path) {
  return JSON.parse(await read(path));
}

async function sha256(path) {
  return `sha256:${createHash("sha256")
    .update(await read(path))
    .digest("hex")}`;
}

async function assertRefs(refs) {
  assert.equal(new Set(refs.map(({ path }) => path)).size, refs.length);
  for (const ref of refs) {
    assert.equal(await sha256(ref.path), ref.sha256, ref.path);
  }
}

async function assertSourceRefs(refs) {
  await assertRefs(refs);
  for (const ref of refs) {
    const { stdout } = await execFileAsync(
      "git",
      ["-C", repoPath, "show", `${sourceCommit}:${ref.path}`],
      { encoding: null, maxBuffer: 10 * 1024 * 1024 },
    );
    assert.equal(
      `sha256:${createHash("sha256").update(stdout).digest("hex")}`,
      ref.sha256,
      `${sourceCommit}:${ref.path}`,
    );
  }
}

test("G1 persistent runtime evidence binds a real two-process replay", async () => {
  const evidence = await json(runtimeEvidencePath);

  assert.equal(evidence.schemaVersion, "g1-persistent-runtime-evidence.v1");
  assert.equal(evidence.recordType, "G1_CONDITION_EVIDENCE");
  assert.equal(evidence.gateId, "G1");
  assert.equal(evidence.phase, "P1_SYNTHETIC_ONLY");
  assert.deepEqual(evidence.conditionIds, ["G1-2", "G1-4"]);
  assert.equal(evidence.verificationStatus, "VERIFIED");
  assert.equal(evidence.verifiedSourceCommit, sourceCommit);
  assert.equal(
    evidence.approvedG0SubmissionSha256,
    approvedG0SubmissionSha256,
  );
  assert.equal(evidence.deployment.sha256, deploymentSha256);
  assert.deepEqual(evidence.deployment, {
    sha256: deploymentSha256,
    tenantCount: 3,
    usersPerTenant: 3,
    rolesPerTenant: 3,
    stablePrincipalCount: 9,
    firstProcessSessionCount: 9,
    secondProcessSessionCount: 9,
    secondProcessUsesFreshSessions: true,
  });
  assert.deepEqual(evidence.replay, {
    processCount: 2,
    workflow:
      "LOGIN_TO_AGENT_TO_RAG_OR_TOOL_TO_SYNTHETIC_TEST_DECISION_TO_AUDIT_AND_USAGE",
    tenantRunCountPerProcess: 3,
    firstProcessNewModelExecutionCount: 6,
    secondProcessNewModelExecutionCount: 0,
    authorizationDecisionCountPerProcess: 114,
    stableBusinessTableCount: 17,
    stableBusinessRowsChangedOnReplay: 0,
    replayedModules: ["C08", "C12", "C16", "C18", "C19"],
  });
  assert.deepEqual(evidence.externalEffects, {
    enterpriseConnectorCount: 0,
    networkRequestCount: 0,
    externalEffectCount: 0,
    humanDecisionProductionReusable: false,
  });
  assert.deepEqual(evidence.verificationBoundary, {
    productionVerified: false,
    enterpriseIntegrationVerified: false,
    oaErpBiConnected: false,
    arbitraryCodeExecutionEnabled: false,
  });
  assert.equal(evidence.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(evidence.enterpriseIntegrationStatus, "P3_REQUIRED");
  await assertSourceRefs(evidence.sourceRefs);
});

test("G1 isolation evidence is independently source-backed", async () => {
  const evidence = await json(isolationEvidencePath);

  assert.equal(evidence.schemaVersion, "g1-persistent-isolation-evidence.v1");
  assert.equal(evidence.recordType, "G1_CONDITION_EVIDENCE");
  assert.equal(evidence.gateId, "G1");
  assert.equal(evidence.conditionId, "G1-3");
  assert.equal(evidence.verificationStatus, "VERIFIED");
  assert.equal(evidence.verifiedSourceCommit, sourceCommit);
  assert.equal(
    evidence.approvedG0SubmissionSha256,
    approvedG0SubmissionSha256,
  );
  assert.equal(
    evidence.orchestrationContractGateStatus,
    "NOT_SATISFIED_WITHOUT_INDEPENDENT_PROVENANCE",
  );
  assert.equal(
    evidence.independentSourceBackedIntegrationStatus,
    "SATISFIED",
  );
  assert.deepEqual(evidence.orchestrationContractRemainingGaps, [
    "INDEPENDENT_BACKEND_PROVENANCE_REQUIRED",
  ]);
  assert.equal(evidence.deploymentSha256, deploymentSha256);
  assert.deepEqual(evidence.matrix, {
    caseCount: 288,
    allowCount: 72,
    denyCount: 216,
    wrongTenantCount: 72,
    wrongUserCount: 72,
    wrongRoleCount: 72,
    wrongUserAndWrongRoleUseDistinctCallers: true,
    negativeBackendTouchCount: 0,
    observedLeakCount: 0,
    wrongAttributionCount: 0,
    actualOpenFgaCheckCount: 288,
  });
  assert.deepEqual(
    evidence.surfaces.map(({ surface, backendKind }) => ({
      surface,
      backendKind,
    })),
    [
      { surface: "SQL", backendKind: "POSTGRESQL_C07_SOURCE" },
      { surface: "VECTOR", backendKind: "POSTGRESQL_C07_SOURCE" },
      { surface: "FILE", backendKind: "C10_FILE_QUARANTINE" },
      { surface: "OBJECT", backendKind: "C07_FILE_OBJECT_ROOT" },
      { surface: "SEARCH", backendKind: "POSTGRESQL_C07_SOURCE" },
      { surface: "CACHE", backendKind: "POSTGRESQL_C07_SOURCE" },
      { surface: "TOOL", backendKind: "C16_POSTGRESQL_GATEWAY_C0" },
      {
        surface: "RESTORE_REPLICA",
        backendKind: "POSTGRESQL_C07_RESTORE_REPLICA",
      },
    ],
  );
  assert.deepEqual(evidence.restore, {
    actualPgDumpRestore: true,
    sourceAndRestoreAreDistinctDatabases: true,
    readOnly: true,
    sourceReplicaHashMatchCount: 9,
    sourceReplicaHashMismatchCount: 0,
    directWriteDenied: true,
  });
  assert.deepEqual(evidence.externalEffects, {
    networkRequestCount: 0,
    enterpriseEndpointCount: 0,
    enterpriseCredentialCount: 0,
    externalEffectCount: 0,
  });
  assert.equal(evidence.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(
    evidence.deploymentBinding.runtimeEvidenceSha256,
    await sha256(runtimeEvidencePath),
  );
  await assertSourceRefs(evidence.sourceRefs);
});

test("G1 acceptance package is complete but still awaits the Product Owner", async () => {
  const [runtime, isolation, acceptance, moduleIndex, executionBoundary] =
    await Promise.all([
      json(runtimeEvidencePath),
      json(isolationEvidencePath),
      json(acceptancePackagePath),
      json("implementation/gates/g1/p1-module-evidence-index.v1.json"),
      json(
        "implementation/gates/g1/g1-execution-boundary-evidence.v1.json",
      ),
    ]);

  assert.equal(acceptance.schemaVersion, "g1-acceptance-package.v1");
  assert.equal(acceptance.recordType, "GATE_ACCEPTANCE_PACKAGE");
  assert.equal(acceptance.gateId, "G1");
  assert.equal(acceptance.phaseFrom, "P1");
  assert.equal(acceptance.phaseTo, "P2");
  assert.equal(acceptance.verifiedSourceCommit, sourceCommit);
  assert.equal(
    acceptance.approvedG0SubmissionSha256,
    approvedG0SubmissionSha256,
  );
  assert.equal(acceptance.packageStatus, "READY_FOR_PRODUCT_OWNER_APPROVAL");
  assert.equal(acceptance.gateDecisionStatus, "PENDING");
  assert.equal(acceptance.p2EntryStatus, "BLOCKED_UNTIL_G1_APPROVAL");
  assert.equal(acceptance.p2EntryAuthorized, false);
  assert.equal(acceptance.productOwner, "EXTERNAL_PRODUCT_OWNER");
  assert.equal(acceptance.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(acceptance.enterpriseIntegrationStatus, "P3_REQUIRED");

  assert.equal(moduleIndex.modules.length, 19);
  assert.equal(
    new Set(moduleIndex.modules.map(({ workPackageId }) => workPackageId))
      .size,
    19,
  );
  await assertRefs(
    moduleIndex.modules.map(({ evidencePath, evidenceSha256 }) => ({
      path: evidencePath,
      sha256: evidenceSha256,
    })),
  );

  assert.deepEqual(
    acceptance.conditions.map(({ conditionId, status }) => ({
      conditionId,
      status,
    })),
    [
      { conditionId: "G1-1", status: "SATISFIED" },
      { conditionId: "G1-2", status: "SATISFIED" },
      { conditionId: "G1-3", status: "SATISFIED" },
      { conditionId: "G1-4", status: "SATISFIED" },
      { conditionId: "G1-5", status: "SATISFIED" },
      {
        conditionId: "G1-6",
        status: "PENDING_PRODUCT_OWNER_APPROVAL",
      },
    ],
  );
  assert.equal(runtime.deployment.sha256, isolation.deploymentSha256);
  assert.equal(executionBoundary.prohibitedPrimitiveMatches, 0);
  assert.deepEqual(executionBoundary.skillExecution, {
    scriptExecution: "DISABLED",
    executionMode: "INSTRUCTIONS_ONLY",
    sandboxRuntime: "ABSENT_UNTIL_P2",
  });
  assert.deepEqual(executionBoundary.connectorBoundary, {
    connectorStage: "C0_DISABLED",
    networkAccess: "DISABLED",
    mode: "READ_ONLY",
    adapter: "REGISTERED_SYNTHETIC_MOCK_ONLY",
    externalEffectCount: 0,
  });
  assert.deepEqual(acceptance.blockingTechnicalGaps, []);
  assert.deepEqual(acceptance.pendingHumanActions, [
    "PRODUCT_OWNER_MUST_APPROVE_THE_EXACT_GATE_SUBMISSION_SHA256",
  ]);
  await assertRefs(acceptance.evidenceRefs);
  const serialized = JSON.stringify(acceptance);
  for (const forbidden of [
    "\"packageHash\"",
    "\"decisionId\"",
    "\"approvedAt\"",
    "\"gateDecisionStatus\":\"APPROVED\"",
  ]) {
    assert.equal(serialized.includes(forbidden), false);
  }
});

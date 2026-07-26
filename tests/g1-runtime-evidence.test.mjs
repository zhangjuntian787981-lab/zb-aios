import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  G1_SYNTHETIC_TENANT_IDS,
  createG1SyntheticRuntime,
} from "../lib/g1-synthetic-runtime.mjs";

const root = new URL("../", import.meta.url);
const evidencePath =
  "implementation/gates/g1/g1-runtime-deployment-evidence.v1.json";

async function read(path) {
  return readFile(new URL(path, root));
}

function sha256(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

test("G1 runtime evidence is source-bound and reproducible for all three Synthetic Tenants", async () => {
  const evidence = JSON.parse(await read(evidencePath));

  assert.equal(evidence.schemaVersion, "g1-runtime-deployment-evidence.v1");
  assert.equal(
    evidence.recordType,
    "G1_SYNTHETIC_RUNTIME_DEPLOYMENT_EVIDENCE",
  );
  assert.equal(evidence.gateId, "G1");
  assert.equal(evidence.phase, "P1");
  assert.equal(evidence.evidenceStatus, "PASS");
  assert.deepEqual(evidence.verificationBoundary, {
    scope: "P1_SYNTHETIC_ONLY",
    productionVerified: false,
    enterpriseConnectorsEnabled: false,
    networkRequestCount: 0,
    externalEffectCount: 0,
    humanDecisionProductionReusable: false,
  });
  assert.equal(evidence.testRun.testCount, 13);
  assert.equal(evidence.testRun.passCount, 13);
  assert.equal(evidence.testRun.failCount, 0);

  for (const source of evidence.sources) {
    assert.equal(sha256(await read(source.path)), source.sha256, source.path);
  }

  const runtime = await createG1SyntheticRuntime();
  const deployment = await runtime.deploy();
  assert.deepEqual(
    deployment.tenants.map(({ tenantId }) => tenantId),
    G1_SYNTHETIC_TENANT_IDS,
  );
  assert.equal(
    deployment.tenants.flatMap(({ users }) => users).length,
    evidence.deployment.realC04SessionCount,
  );
  assert.equal(
    deployment.tenants
      .flatMap(({ users }) => users)
      .some((user) => Object.hasOwn(user, "sessionToken")),
    false,
  );

  for (const expected of evidence.tenantChainEvidence) {
    const result = await runtime.runTenant(expected.tenantId);
    assert.equal(result.modules.C08.runId, expected.c08RunId);
    assert.equal(
      result.modules.C08.reconstructionHash,
      expected.c08ReconstructionSha256,
    );
    assert.equal(result.modules.C12.taskId, expected.c12TaskId);
    assert.equal(
      result.modules.C12.stateSha256,
      expected.c12StateSha256,
    );
    assert.equal(
      result.modules.C16.receiptSha256,
      expected.c16ReceiptSha256,
    );
    assert.equal(
      result.modules.C18.eventHash,
      expected.c18EventSha256,
    );
    assert.equal(result.modules.C19.traceId, expected.c19TraceId);
    assert.equal(
      result.modules.C19.totalSignals,
      expected.c19SignalCount,
    );
    assert.equal(
      result.modules.C19.modelSettlementState,
      expected.c19ModelSettlementState,
    );
    assert.equal(
      result.modules.C19.toolSettlementState,
      expected.c19ToolSettlementState,
    );
    assert.equal(result.modules.C16.externalEffectCount, 0);
  }

  const firstTenant = evidence.tenantChainEvidence[0];
  const firstExecutionCount =
    (await runtime.runTenant(firstTenant.tenantId))
      .modules.C16.adapterNewExecutionCount;
  const replay =
    await runtime.runTenant(firstTenant.tenantId);
  assert.equal(replay.modules.C08.replayed, true);
  assert.equal(replay.modules.C12.replayed, true);
  assert.equal(replay.modules.C18.replayed, true);
  assert.equal(replay.modules.C19.replayed, true);
  assert.equal(replay.modules.C08.runId, firstTenant.c08RunId);
  assert.equal(
    replay.modules.C16.adapterNewExecutionCount,
    firstExecutionCount,
  );
  assert.equal(replay.modules.C16.externalEffectCount, 0);
});

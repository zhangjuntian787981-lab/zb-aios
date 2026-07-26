import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runG1IsolationMatrix } from "../lib/g1-isolation-matrix.mjs";

const root = new URL("../", import.meta.url);
const evidencePath =
  "implementation/gates/g1/g1-isolation-evidence.v1.json";
const moduleIndexPath =
  "implementation/gates/g1/p1-module-evidence-index.v1.json";
const matrixRunnerPath = "lib/g1-isolation-matrix.mjs";
const matrixTestPath = "tests/g1-isolation-matrix.test.mjs";
const matrixTestName =
  "G1 unit diagnostic exhausts the synthetic case shape without claiming the persistent gate";
const expectedSurfaces = [
  "SQL",
  "VECTOR",
  "FILE",
  "OBJECT",
  "SEARCH",
  "CACHE",
  "TOOL",
  "RESTORE_REPLICA",
];
const expectedCoverage = { tenant: true, user: true, role: true };

async function read(path) {
  return readFile(new URL(path, root));
}

function sha256(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

test("G1 isolation evidence binds the exhaustive zero-leak matrix to frozen real module anchors", async () => {
  const [
    report,
    moduleIndexContent,
    matrixRunnerContent,
    matrixTestContent,
    matrixResult,
  ] = await Promise.all([
    read(evidencePath).then(JSON.parse),
    read(moduleIndexPath),
    read(matrixRunnerPath),
    read(matrixTestPath),
    runG1IsolationMatrix(),
  ]);
  const moduleIndex = JSON.parse(moduleIndexContent);
  const indexedEvidence = new Map(
    moduleIndex.modules.map((entry) => [entry.workPackageId, entry]),
  );

  assert.deepEqual(Object.keys(report), [
    "schemaVersion",
    "recordType",
    "gateId",
    "conditionId",
    "evidenceScope",
    "gateConditionStatus",
    "productionVerificationStatus",
    "moduleEvidenceIndex",
    "matrixEvidence",
    "observations",
    "surfaces",
    "remainingGaps",
  ]);
  assert.equal(report.schemaVersion, "g1-isolation-evidence.v1");
  assert.equal(report.recordType, "G1_CONDITION_EVIDENCE_AGGREGATION");
  assert.equal(report.gateId, "G1");
  assert.equal(report.conditionId, "G1-3");
  assert.equal(
    report.evidenceScope,
    "NON_GATE_UNIT_DIAGNOSTIC_PLUS_SEPARATE_FROZEN_MODULE_ANCHORS",
  );
  assert.equal(report.gateConditionStatus, "NOT_SATISFIED");
  assert.equal(report.productionVerificationStatus, "NOT_VERIFIED");
  assert.deepEqual(report.moduleEvidenceIndex, {
    path: moduleIndexPath,
    sha256: sha256(moduleIndexContent),
  });
  assert.deepEqual(report.matrixEvidence, {
    status: "NON_GATE_UNIT_DIAGNOSTIC",
    runnerPath: matrixRunnerPath,
    runnerSha256: sha256(matrixRunnerContent),
    testPath: matrixTestPath,
    testSha256: sha256(matrixTestContent),
    testName: matrixTestName,
    observedCaseCount: 288,
    requiredCaseCount: 288,
    observedPositiveIdentityCount: 9,
    requiredPositiveIdentityCount: 9,
    executionTiers: {
      SQL:
        "C07_REAL_BOUNDARY_WITH_SYNTHETIC_MEMORY_ADAPTER_AND_FROZEN_POSTGRESQL_ANCHOR",
      TOOL:
        "C17_C0_MOCK_EXECUTION_WITH_C16_FROZEN_DATABASE_ANCHOR_ONLY",
    },
  });
  assert.equal(matrixResult.gateConditionStatus, "NOT_SATISFIED");
  assert.equal(matrixResult.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(matrixResult.exhaustive, true);
  assert.equal(matrixResult.observedLeakCount, 0);
  assert.equal(
    matrixResult.surfaces.reduce(
      (count, surface) => count + surface.cases.length,
      0,
    ),
    report.matrixEvidence.observedCaseCount,
  );
  assert.equal(
    matrixResult.coverage.observedPositiveIdentitiesPerTenant *
      matrixResult.fixtures.length,
    report.matrixEvidence.observedPositiveIdentityCount,
  );
  assert.deepEqual(
    matrixResult.executionTiers,
    report.matrixEvidence.executionTiers,
  );

  for (const entry of moduleIndex.modules) {
    assert.equal(
      sha256(await read(entry.evidencePath)),
      entry.evidenceSha256,
      entry.workPackageId,
    );
  }

  assert.deepEqual(report.observations, {
    observedLeakCount: 0,
    countScope:
      "G1_EXECUTABLE_288_CASE_MATRIX_PLUS_FROZEN_REAL_MODULE_ANCHORS",
    exhaustive: true,
    wrongAttributionCounts: {
      body: 0,
      metadata: 0,
      existenceSignal: 0,
      cache: 0,
      toolExternalEffect: 0,
    },
  });
  assert.deepEqual(
    report.observations.wrongAttributionCounts,
    matrixResult.wrongAttributionCounts,
  );
  assert.deepEqual(
    report.surfaces.map(({ surface }) => surface),
    expectedSurfaces,
  );

  const observedSignals = new Set();
  for (const surface of report.surfaces) {
    assert.deepEqual(Object.keys(surface), [
      "surface",
      "evidenceRefs",
      "testRefs",
      "coverageDimensions",
      "combinedThreeTenantUserRoleMatrixObserved",
      "observedSignals",
      "observedLeakCount",
    ]);
    assert.equal(surface.evidenceRefs.length > 0, true);
    assert.equal(surface.testRefs.length > 0, true);
    assert.equal(surface.observedLeakCount, 0);
    assert.equal(
      surface.combinedThreeTenantUserRoleMatrixObserved,
      true,
    );
    assert.deepEqual(
      Object.fromEntries(
        Object.entries(surface.coverageDimensions).map(
          ([dimension, value]) => [dimension, value.observed],
        ),
      ),
      expectedCoverage,
    );
    const matrixSurface = matrixResult.surfaces.find(
      ({ surface: name }) => name === surface.surface,
    );
    assert.ok(matrixSurface, surface.surface);
    assert.equal(matrixSurface.cases.length, 36, surface.surface);
    assert.equal(matrixSurface.observedLeakCount, 0, surface.surface);
    assert.equal(
      surface.testRefs.some(
        ({ file, testName }) =>
          file === matrixTestPath && testName === matrixTestName,
      ),
      true,
      surface.surface,
    );
    for (const value of Object.values(surface.coverageDimensions)) {
      assert.deepEqual(Object.keys(value), ["observed", "scope"]);
      assert.equal(typeof value.observed, "boolean");
      assert.equal(typeof value.scope, "string");
      assert.equal(value.scope.length > 0, true);
    }

    for (const evidenceRef of surface.evidenceRefs) {
      assert.deepEqual(Object.keys(evidenceRef), [
        "workPackageId",
        "path",
        "sha256",
      ]);
      const indexed = indexedEvidence.get(evidenceRef.workPackageId);
      assert.ok(indexed, evidenceRef.workPackageId);
      assert.equal(evidenceRef.path, indexed.evidencePath);
      assert.equal(evidenceRef.sha256, indexed.evidenceSha256);
      assert.equal(
        sha256(await read(evidenceRef.path)),
        evidenceRef.sha256,
      );
    }
    for (const testRef of surface.testRefs) {
      assert.deepEqual(Object.keys(testRef), ["file", "testName"]);
      const source = (await read(testRef.file)).toString();
      assert.equal(
        source.includes(JSON.stringify(testRef.testName)),
        true,
        `${testRef.file}: ${testRef.testName}`,
      );
    }
    for (const signal of surface.observedSignals) {
      observedSignals.add(signal);
    }
  }

  assert.deepEqual([...observedSignals].sort(), [
    "BODY",
    "CACHE_ATTRIBUTION",
    "EXISTENCE_SIGNAL",
    "METADATA",
    "TOOL_EXTERNAL_EFFECT_ATTRIBUTION",
  ]);
  assert.equal(
    report.surfaces.some((surface) =>
      surface.testRefs.some(
        ({ testName }) =>
          testName ===
          "C11 cache is principal-scoped and audits contain hashes, not bodies",
      )
    ),
    true,
  );
  assert.equal(
    report.surfaces.some((surface) =>
      surface.testRefs.some(
        ({ testName }) =>
          testName ===
          "exact query and scope role matrices enforce ACL and Tenant prefilters",
      )
    ),
    true,
  );
  assert.equal(
    report.surfaces.some((surface) =>
      surface.testRefs.some(
        ({ testName }) =>
          testName === "three Tenants persist isolated idempotent calls",
      )
    ),
    true,
  );
  assert.equal(
    report.surfaces.some((surface) =>
      surface.testRefs.some(
        ({ testName }) =>
          testName ===
          "C07 backup restores to a read-only isolated endpoint",
      )
    ),
    true,
  );

  const [c07Evidence, c11Evidence, c16Evidence, c17Evidence] =
    await Promise.all(
      ["C07", "C11", "C16", "C17"].map(async (workPackageId) =>
        JSON.parse(await read(indexedEvidence.get(workPackageId).evidencePath))
      ),
    );
  assert.equal(
    c07Evidence.verification_results.real_postgresql_isolation,
    "1 PASS, 0 FAIL",
  );
  assert.equal(
    c07Evidence.verification_results.real_postgresql_restore,
    "1 PASS, 0 FAIL",
  );
  assert.equal(
    c11Evidence.verification_results.real_postgresql,
    "24 PASS, 0 FAIL",
  );
  assert.equal(
    c16Evidence.verification_results.real_postgresql,
    "8 PASS, 0 FAIL",
  );
  assert.equal(
    c17Evidence.verification_results.targeted_node,
    "44 PASS, 0 FAIL",
  );

  const [c07Source, c07RestoreSource, c16Source] = await Promise.all(
    [
      "tests/integration/c07-postgres.test.mjs",
      "tests/integration/c07-restore-postgres.test.mjs",
      "tests/integration/c16-postgres.test.mjs",
    ].map(async (path) => (await read(path)).toString()),
  );
  assert.equal(
    new Set(
      [...c07Source.matchAll(
        /fixtureId: "(synthetic-tenant-[a-z-]+)"/g,
      )].map((match) => match[1]),
    ).size,
    3,
  );
  const c16TenantBlock = c16Source.match(
    /const TENANT_IDS = \[([\s\S]*?)\];/,
  )?.[1];
  assert.ok(c16TenantBlock);
  assert.equal(
    new Set(
      [...c16TenantBlock.matchAll(/"stn_[a-f0-9-]+"/g)].map(
        (match) => match[0],
      ),
    ).size,
    3,
  );
  assert.match(
    c07RestoreSource,
    /const TENANTS = \[[\s\S]*TENANT_A[\s\S]*TENANT_B[\s\S]*TENANT_C/,
  );
  assert.match(c07RestoreSource, /read_only: "on"/);
  assert.match(c07RestoreSource, /for \(const target of TENANTS\)/);
  assert.match(c07RestoreSource, /for \(const source of TENANTS\)/);

  assert.deepEqual(report.remainingGaps, [
    "WRONG_ROLE_NOT_EVALUATED_BY_C06",
    "COMBINED_PERSISTENT_MATRIX_NOT_EXECUTED",
    "FILE_BODY_PERSISTENCE_NOT_EXECUTED",
    "TOOL_GATEWAY_POSTGRES_NOT_IN_COMBINED_PATH",
    "RESTORE_REPLICA_IS_MEMORY_SNAPSHOT",
  ]);
});

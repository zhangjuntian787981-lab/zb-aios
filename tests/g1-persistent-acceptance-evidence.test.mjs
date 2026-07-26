import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = new URL("../", import.meta.url);
const repoPath = fileURLToPath(root);
const sourceCommit =
  "6a23e93ed37eabec1201ff3a7bb00a0d9231fc49";
const sourceTree = "e98a7662b8f86fc2f3a2da31531195686612bcff";
const packageLockSha256 =
  "sha256:8c0b7396f16b2aa26a0b960e55711834f2220e948c71ebb0719e6ccc0c533e6d";
const dependencyTreeSha256 =
  "sha256:addb1298f1895c2804039f8cc17702ad696f22a6db727fa09f623b75b6c8ab62";
const deploymentSha256 =
  "sha256:0ad6c07cea92ea050232b34af2bf1362e7599ae5f694a5c6d23968e18c066162";
const receiptPath =
  "implementation/gates/g1/g1-live-verification-receipt.v1.json";
const runtimePath =
  "implementation/gates/g1/g1-persistent-runtime-evidence.v1.json";
const isolationPath =
  "implementation/gates/g1/g1-persistent-isolation-evidence.v1.json";
const indexPath =
  "implementation/gates/g1/p1-module-evidence-index.v1.json";
const acceptancePath =
  "implementation/gates/g1/g1-acceptance-package.v1.json";

async function read(path) {
  return readFile(new URL(path, root));
}

async function json(path) {
  return JSON.parse(await read(path));
}

function sha256(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

function source(path) {
  return execFileSync(
    "git",
    ["-C", repoPath, "show", `${sourceCommit}:${path}`],
    { maxBuffer: 10 * 1024 * 1024 },
  );
}

async function assertRef(ref, { atSource = false } = {}) {
  const content = atSource ? source(ref.path) : await read(ref.path);
  assert.equal(sha256(content), ref.sha256, ref.path);
}

function frozenRecords(output) {
  const records = [];
  for (const line of output.split("\n")) {
    if (!line.startsWith("{")) continue;
    const record = JSON.parse(line);
    if (record.schemaVersion?.startsWith("g1-frozen-verification-")) {
      records.push(record);
    }
  }
  return records;
}

function tapCounts(output) {
  const values = (label) =>
    [...output.matchAll(new RegExp(`^ℹ ${label} (\\d+)$`, "gmu"))]
      .map((match) => Number(match[1]));
  return {
    tests: values("tests"),
    pass: values("pass"),
    fail: values("fail"),
  };
}

function allKeys(value, result = new Set()) {
  if (Array.isArray(value)) {
    for (const item of value) allKeys(item, result);
    return result;
  }
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      result.add(key);
      allKeys(nested, result);
    }
  }
  return result;
}

test("frozen receipt binds seven clean fresh-install runs to one source candidate", async () => {
  const receipt = await json(receiptPath);
  assert.deepEqual(Object.keys(receipt), [
    "schemaVersion",
    "recordType",
    "gateId",
    "phase",
    "recordedAt",
    "candidate",
    "runner",
    "runs",
    "environment",
    "boundaries",
  ]);
  assert.deepEqual(Object.keys(receipt.candidate), [
    "commit",
    "tree",
    "packageLockSha256",
    "npmDependencyTreeSha256",
  ]);
  assert.equal(receipt.schemaVersion, "g1-live-verification-receipt.v1");
  assert.equal(receipt.recordType, "COMMAND_RUN_RECEIPT");
  assert.equal(receipt.candidate.commit, sourceCommit);
  assert.equal(receipt.candidate.tree, sourceTree);
  assert.equal(receipt.candidate.packageLockSha256, packageLockSha256);
  assert.equal(
    receipt.candidate.npmDependencyTreeSha256,
    dependencyTreeSha256,
  );
  assert.equal(
    execFileSync(
      "git",
      ["-C", repoPath, "rev-parse", `${sourceCommit}^{tree}`],
      { encoding: "utf8" },
    ).trim(),
    sourceTree,
  );
  assert.equal(sha256(source("package-lock.json")), packageLockSha256);
  assert.equal(sha256(source(receipt.runner.path)), receipt.runner.sha256);
  assert.equal(receipt.runner.freshDetachedWorktreePerRun, true);
  assert.equal(receipt.runner.freshDependencyInstallPerRun, true);
  assert.equal(receipt.runner.successfulRunCount, 7);
  assert.deepEqual(
    receipt.runs.map(({ mode }) => mode),
    [
      "dependencies",
      "build",
      "c06",
      "c15",
      "runtime",
      "isolation",
      "lint",
    ],
  );

  const runIds = new Set();
  for (const run of receipt.runs) {
    assert.deepEqual(Object.keys(run), [
      "mode",
      "command",
      "combinedOutputPath",
      "combinedOutputSha256",
      "exitCode",
      "result",
    ]);
    assert.equal(run.exitCode, 0);
    const outputBuffer = await read(run.combinedOutputPath);
    assert.equal(sha256(outputBuffer), run.combinedOutputSha256);
    const output = outputBuffer.toString("utf8");
    const records = frozenRecords(output);
    assert.equal(records.length, 3, run.mode);
    const [start, dependencies, complete] = records;
    assert.deepEqual(
      records.map(({ schemaVersion }) => schemaVersion),
      [
        "g1-frozen-verification-start.v1",
        "g1-frozen-verification-dependencies-complete.v1",
        "g1-frozen-verification-complete.v1",
      ],
    );
    assert.equal(start.runId, dependencies.runId);
    assert.equal(start.runId, complete.runId);
    assert.equal(runIds.has(start.runId), false);
    runIds.add(start.runId);
    for (const record of records) {
      assert.equal(record.mode, run.mode);
      assert.equal(record.verificationCommand, run.command);
      assert.equal(
        record.dependencyInstallCommand,
        receipt.runner.dependencyInstallCommand,
      );
      assert.equal(record.candidateCommit, sourceCommit);
      assert.equal(record.candidateTree, sourceTree);
      assert.equal(record.packageLockSha256, packageLockSha256);
      assert.equal(record.trackedWorktreeClean, true);
      assert.equal(record.nodeModulesPresentAtStart, false);
      assert.equal(record.nodeVersion, receipt.environment.nodeVersion);
      assert.equal(record.npmVersion, receipt.environment.npmVersion);
      assert.equal(
        record.operatingSystem,
        receipt.environment.operatingSystem,
      );
      assert.equal(record.architecture, receipt.environment.architecture);
    }
    assert.equal(start.freshDependencyInstallCompleted, false);
    assert.equal(start.npmDependencyTreeSha256, null);
    assert.equal(dependencies.freshDependencyInstallCompleted, true);
    assert.equal(
      dependencies.npmDependencyTreeSha256,
      dependencyTreeSha256,
    );
    assert.equal(complete.freshDependencyInstallCompleted, true);
    assert.equal(complete.npmDependencyTreeSha256, dependencyTreeSha256);
    assert.equal(complete.exitCode, 0);

    const counts = tapCounts(output);
    if (run.mode === "c15") {
      assert.deepEqual(counts, {
        tests: [46, 33, 1],
        pass: [46, 33, 1],
        fail: [0, 0, 0],
      });
    }
    if (["c06", "runtime", "isolation"].includes(run.mode)) {
      assert.deepEqual(counts, {
        tests: [1],
        pass: [1],
        fail: [0],
      });
    }
    if (run.mode === "dependencies") {
      assert.match(output, /added 518 packages/);
    }
    if (run.mode === "build") {
      assert.match(output, /Build complete/);
    }
    if (run.mode === "lint") {
      assert.match(output, /eslint \./);
    }
  }
});

test("persistent runtime evidence binds two-process attribution replay", async () => {
  const evidence = await json(runtimePath);
  assert.deepEqual(Object.keys(evidence), [
    "schemaVersion",
    "recordType",
    "gateId",
    "phase",
    "conditionIds",
    "verificationStatus",
    "verifiedSourceCommit",
    "approvedG0SubmissionSha256",
    "recordedAt",
    "runReceipt",
    "runtime",
    "deployment",
    "replay",
    "attributionReplay",
    "externalEffects",
    "verificationBoundary",
    "sourceRefs",
    "productionVerificationStatus",
    "enterpriseIntegrationStatus",
    "limitations",
  ]);
  assert.equal(evidence.verifiedSourceCommit, sourceCommit);
  assert.equal(evidence.verificationStatus, "VERIFIED");
  assert.equal(evidence.deployment.sha256, deploymentSha256);
  assert.equal(evidence.runtime.nodeProcesses, 2);
  assert.equal(evidence.replay.stableBusinessTableCount, 18);
  assert.equal(evidence.replay.stableBusinessRowsChangedOnReplay, 0);
  assert.equal(evidence.attributionReplay.quotaAccountCount, 6);
  assert.equal(evidence.attributionReplay.settledReservationCount, 6);
  assert.equal(evidence.attributionReplay.usageSettledLedgerCount, 6);
  assert.equal(evidence.attributionReplay.meterKeysUnique, true);
  assert.equal(
    evidence.attributionReplay.quotaConsumedEqualsBookedCost,
    true,
  );
  assert.equal(evidence.attributionReplay.firstAndReplaySnapshotsEqual, true);
  assert.equal(evidence.externalEffects.externalEffectCount, 0);
  assert.equal(evidence.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(evidence.enterpriseIntegrationStatus, "P3_REQUIRED");
  await assertRef(evidence.runReceipt);
  assert.equal(evidence.runReceipt.mode, "runtime");
  for (const ref of evidence.sourceRefs) {
    await assertRef(ref, { atSource: true });
  }
});

test("persistent isolation evidence binds the orthogonal 288-case matrix", async () => {
  const evidence = await json(isolationPath);
  assert.deepEqual(Object.keys(evidence), [
    "schemaVersion",
    "recordType",
    "gateId",
    "phase",
    "conditionId",
    "verificationStatus",
    "verifiedSourceCommit",
    "approvedG0SubmissionSha256",
    "recordedAt",
    "runReceipt",
    "orchestrationContractGateStatus",
    "orchestrationContractRemainingGaps",
    "independentSourceBackedIntegrationStatus",
    "deploymentSha256",
    "deploymentBinding",
    "dependencies",
    "matrix",
    "surfaces",
    "restore",
    "externalEffects",
    "sourceRefs",
    "productionVerificationStatus",
    "enterpriseIntegrationStatus",
    "acceptedStageLimitations",
  ]);
  assert.equal(evidence.verifiedSourceCommit, sourceCommit);
  assert.equal(evidence.verificationStatus, "VERIFIED");
  assert.equal(
    evidence.orchestrationContractGateStatus,
    "SATISFIED_WITH_INDEPENDENT_SOURCE_BACKED_INTEGRATION",
  );
  assert.deepEqual(evidence.orchestrationContractRemainingGaps, []);
  assert.equal(evidence.deploymentSha256, deploymentSha256);
  assert.equal(
    evidence.deploymentBinding.runtimeEvidenceSha256,
    sha256(await read(runtimePath)),
  );
  assert.equal(evidence.matrix.caseCount, 288);
  assert.equal(evidence.matrix.allowCount, 72);
  assert.equal(evidence.matrix.denyCount, 216);
  assert.equal(evidence.matrix.wrongUserOrthogonalCount, 72);
  assert.equal(evidence.matrix.wrongRoleOrthogonalCount, 72);
  assert.equal(evidence.matrix.negativeBackendTouchCount, 0);
  assert.equal(evidence.matrix.observedLeakCount, 0);
  assert.equal(evidence.matrix.wrongAttributionCount, 0);
  assert.equal(evidence.restore.actualPgDumpRestore, true);
  assert.equal(evidence.restore.readOnly, true);
  assert.equal(evidence.externalEffects.externalEffectCount, 0);
  await assertRef(evidence.runReceipt);
  assert.equal(evidence.runReceipt.mode, "isolation");
  for (const ref of evidence.sourceRefs) {
    await assertRef(ref, { atSource: true });
  }
});

test("G1 package is complete, acyclic and still awaits Product Owner approval", async () => {
  const [acceptance, index, receipt, runtime, isolation] =
    await Promise.all([
      json(acceptancePath),
      json(indexPath),
      json(receiptPath),
      json(runtimePath),
      json(isolationPath),
    ]);
  assert.deepEqual(Object.keys(acceptance), [
    "schemaVersion",
    "recordType",
    "gateId",
    "phaseFrom",
    "phaseTo",
    "verifiedSourceCommit",
    "approvedG0SubmissionSha256",
    "recordedAt",
    "packageStatus",
    "gateDecisionStatus",
    "p2EntryStatus",
    "p2EntryAuthorized",
    "productOwner",
    "productionVerificationStatus",
    "enterpriseIntegrationStatus",
    "evidenceRefs",
    "conditions",
    "verificationBoundary",
    "blockingTechnicalGaps",
    "pendingHumanActions",
    "acceptedStageLimitations",
  ]);
  assert.equal(acceptance.verifiedSourceCommit, sourceCommit);
  assert.equal(
    acceptance.packageStatus,
    "READY_FOR_PRODUCT_OWNER_APPROVAL",
  );
  assert.equal(acceptance.gateDecisionStatus, "PENDING");
  assert.equal(acceptance.p2EntryStatus, "BLOCKED_UNTIL_G1_APPROVAL");
  assert.equal(acceptance.p2EntryAuthorized, false);
  assert.equal(acceptance.productOwner, "EXTERNAL_PRODUCT_OWNER");
  assert.deepEqual(acceptance.blockingTechnicalGaps, []);
  assert.deepEqual(
    acceptance.conditions.map(({ status }) => status),
    [
      "SATISFIED",
      "SATISFIED",
      "SATISFIED",
      "SATISFIED",
      "SATISFIED",
      "PENDING_PRODUCT_OWNER_APPROVAL",
    ],
  );
  assert.equal(acceptance.verificationBoundary.enterpriseDataPresent, false);
  assert.equal(
    acceptance.verificationBoundary.enterpriseConnectorsEnabled,
    false,
  );
  assert.equal(
    acceptance.verificationBoundary.arbitraryCodeExecutionEnabled,
    false,
  );
  assert.equal(acceptance.verificationBoundary.realExternalEffectCount, 0);

  for (const ref of acceptance.evidenceRefs) {
    await assertRef(ref);
    assert.notEqual(ref.path, acceptancePath);
    assert.doesNotMatch(ref.path, /gate-decision/iu);
  }
  assert.equal(index.modules.length, 19);
  assert.equal(
    sha256(await read(indexPath)),
    acceptance.evidenceRefs[0].sha256,
  );

  const moduleEvidence = await Promise.all(
    index.modules.map(({ evidencePath }) => json(evidencePath)),
  );
  const reviews = await Promise.all(
    [
      "implementation/gates/g1/reviews/c06-sql-security-review.v1.json",
      "implementation/gates/g1/reviews/c15-sql-security-review.v1.json",
      "implementation/gates/g1/reviews/c15-final-spec-review.v1.json",
      "implementation/gates/g1/reviews/c19-sql-security-review.v1.json",
    ].map(json),
  );
  const technicalEvidence = [
    receipt,
    runtime,
    isolation,
    index,
    ...moduleEvidence,
    ...reviews,
  ];
  const forbiddenTechnicalKeys = [
    "gateDecisionStatus",
    "p2EntryStatus",
    "p2EntryAuthorized",
    "productOwner",
    "packageHash",
    "approvedAt",
    "approvedBy",
  ];
  for (const evidence of technicalEvidence) {
    const keys = allKeys(evidence);
    for (const key of forbiddenTechnicalKeys) {
      assert.equal(keys.has(key), false, key);
    }
    assert.doesNotMatch(JSON.stringify(evidence), /gate-decision/iu);
    assert.doesNotMatch(JSON.stringify(evidence), /g1-acceptance-package/iu);
  }
  for (const forbidden of [
    "packageHash",
    "approvedAt",
    "approvedBy",
    "decisionId",
  ]) {
    assert.equal(Object.hasOwn(acceptance, forbidden), false);
  }
});

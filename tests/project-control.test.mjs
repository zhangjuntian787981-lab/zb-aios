import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createFrozenEvidenceVerifier } from "../lib/frozen-evidence.mjs";
import {
  createMemoryJournal,
  createProjectControl,
} from "../lib/project-control.mjs";

const manifestPath = new URL(
  "../implementation/governance/work-package-manifest.v1.json",
  import.meta.url,
);
const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const f01EvidenceFrozenCommit = "f43b861da7775d39d069d438a5e7dc2d941ae831";

async function loadManifest() {
  return JSON.parse(await readFile(manifestPath, "utf8"));
}

async function loadJson(relativePath) {
  return JSON.parse(
    await readFile(new URL(`../implementation/governance/${relativePath}`, import.meta.url), "utf8"),
  );
}

function fileHash(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

const owner = {
  actorId: "external_product_owner",
  roles: ["PRODUCT_OWNER"],
};

function command(kind, values, revision, key) {
  return {
    kind,
    ...values,
    expectedRevision: revision,
    idempotencyKey: key,
  };
}

const testEvidenceRecords = ["F01", "F02", "F03", "F04"].map(
  (workPackageId, index) => ({
    workPackageId,
    evidenceRefs: [`evidence/${workPackageId}.json`],
    evidenceHashes: [`sha256:${String(index + 1).repeat(64)}`],
  }),
);
testEvidenceRecords.push({
  workPackageId: "F04",
  evidenceRefs: ["evidence/F04-v2.json"],
  evidenceHashes: [`sha256:${"e".repeat(64)}`],
});
const verifyTestFrozenEvidence = createFrozenEvidenceVerifier({
  schemaVersion: "frozen-evidence-catalog.v1",
  records: testEvidenceRecords,
});
const syntheticReferenceReviewPolicy = Object.freeze({
  schemaVersion: "reference-review-policy.v1",
});
const verifySyntheticP0ReferenceReview = async ({ boundary, workPackageId }) =>
  ["PRE_START", "IMPLEMENTATION_CONFORMANCE"].includes(boundary) &&
  ["F01", "F02", "F03", "F04"].includes(workPackageId);
const syntheticReferenceReviewPrerequisites = Object.freeze({
  referenceReviewPolicy: syntheticReferenceReviewPolicy,
  verifyReferenceReviewReadiness:
    verifySyntheticP0ReferenceReview,
});

async function verifyPackage(control, packageId, revision) {
  const evidence = testEvidenceRecords.find(
    ({ workPackageId }) => workPackageId === packageId,
  );
  return control.execute(
    owner,
    command(
      "RECORD_WORK_PACKAGE",
      {
        workPackageId: packageId,
        implementationStatus: "IMPLEMENTED",
        verificationStatus: "VERIFIED",
        evidenceRefs: evidence.evidenceRefs,
        evidenceHashes: evidence.evidenceHashes,
        note: `${packageId} verification`,
      },
      revision,
      `verify-${packageId}`,
    ),
  );
}

function historicalG0Replay(manifest, p0EvidenceIndex, includeDecision = true) {
  const invalidF04Hashes = [
    "sha256:851851fcec6d961efaf17f6a0ced172c12dad2dced6746c9c9b805a205c95f62",
    "sha256:1ac738d40ed6fb0bdaadb876c92b4f3cbde0d722142093bb786447365c9c5de0",
  ];
  const historicalScope = p0EvidenceIndex.records.map((entry) => {
    const definition = manifest.work_packages.find(
      ({ id }) => id === entry.workPackageId,
    );
    return {
      work_package_id: entry.workPackageId,
      applicability: definition.applicability,
      implementation_status: "IMPLEMENTED",
      verification_status: "VERIFIED",
      evidence_refs: entry.evidenceRefs,
      evidence_hashes:
        entry.workPackageId === "F04"
          ? invalidF04Hashes
          : entry.evidenceHashes,
    };
  });
  const packageEvents = historicalScope.map((entry, index) => ({
    id: `historical-${entry.work_package_id.toLowerCase()}`,
    type: "WORK_PACKAGE_RECORDED",
    actorId: "external_product_owner",
    createdAt: `2026-07-26T02:00:0${index}.000Z`,
    payload: {
      workPackageId: entry.work_package_id,
      implementationStatus: entry.implementation_status,
      verificationStatus: entry.verification_status,
      evidenceRefs: entry.evidence_refs,
      evidenceHashes: entry.evidence_hashes,
      note: `historical ${entry.work_package_id} evidence`,
    },
  }));
  const submission = {
    id: "historical-g0-submission-event",
    type: "GATE_SUBMITTED",
    actorId: "external_product_owner",
    createdAt: "2026-07-26T02:01:00.000Z",
    payload: {
      gate_id: "G0",
      submission_id: "historical-g0-submission",
      package_hash:
        "sha256:77d8707a602a83729b557c028bd6cf87c5a0e5d921145b9dc3a5a1e79bf32a07",
      submitted_at: "2026-07-26T02:01:00.000Z",
      submitted_by: "external_product_owner",
      source_revision: 4,
      work_package_scope: historicalScope,
      evidence_refs: historicalScope.flatMap(
        ({ evidence_refs }) => evidence_refs,
      ),
      supersedes: null,
    },
  };
  const decision = {
    id: "historical-g0-decision-event",
    type: "GATE_DECIDED",
    actorId: "external_product_owner",
    createdAt: "2026-07-26T02:02:00.000Z",
    payload: {
      decision_id: "historical-g0-decision",
      submission_id: "historical-g0-submission",
      package_hash: submission.payload.package_hash,
      decision: "APPROVE",
      decided_by: "external_product_owner",
      decided_at: "2026-07-26T02:02:00.000Z",
      accepted_exclusions: [],
      evidence_refs: ["historical-product-owner-decision"],
    },
  };
  return {
    historicalScope,
    events: includeDecision
      ? [...packageEvents, submission, decision]
      : [...packageEvents, submission],
  };
}

test("the manifest compiles exactly 37 unique work packages and four gates", async () => {
  const control = createProjectControl({
    manifest: await loadManifest(),
    journal: createMemoryJournal(),
  });
  const snapshot = await control.snapshot(owner);

  assert.equal(snapshot.workPackages.length, 37);
  assert.equal(new Set(snapshot.workPackages.map(({ id }) => id)).size, 37);
  assert.deepEqual(
    Object.fromEntries(
      ["P0", "P1", "P2", "P3"].map((phase) => [
        phase,
        snapshot.workPackages.filter((item) => item.phase === phase).length,
      ]),
    ),
    { P0: 4, P1: 19, P2: 6, P3: 8 },
  );
  assert.deepEqual(
    snapshot.gates.map(({ id }) => id),
    ["G0", "G1", "G2", "G3"],
  );
});

test("manifest compilation fails closed when a phase gate omits required work", async () => {
  const invalid = structuredClone(await loadManifest());
  invalid.gates[0].required_work_packages = ["F01", "F02", "F03"];

  assert.throws(
    () =>
      createProjectControl({
        manifest: invalid,
        journal: createMemoryJournal(),
      }),
    (error) => error.code === "INVALID_MANIFEST",
  );
});

test("gate artifacts have machine-readable schemas and all four decision examples", async () => {
  const submissionSchema = await loadJson("schemas/gate-submission.schema.json");
  const decisionSchema = await loadJson("schemas/gate-decision.schema.json");
  const examples = await loadJson("examples/gate-decisions.v1.json");

  assert.equal(submissionSchema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(decisionSchema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual(decisionSchema.properties.decision.enum, [
    "APPROVE",
    "APPROVE_WITH_EXCLUSIONS",
    "RETURN",
    "HOLD",
  ]);
  assert.deepEqual(
    examples.map(({ decision }) => decision),
    ["APPROVE", "APPROVE_WITH_EXCLUSIONS", "RETURN", "HOLD"],
  );
  assert.ok(
    examples.every(({ package_hash }) => /^sha256:[a-f0-9]{64}$/.test(package_hash)),
  );
});

test("F01 verification evidence hashes every frozen artifact", async () => {
  const manifest = await loadManifest();
  const f01 = manifest.work_packages.find(({ id }) => id === "F01");
  const evidencePath = f01.artifact_refs.find((path) =>
    /implementation\/p0\/evidence\/f01-evidence\.v\d+\.json$/.test(path),
  );
  assert.ok(evidencePath);
  const evidenceText = execFileSync(
    "git",
    ["show", `${f01EvidenceFrozenCommit}:${evidencePath}`],
    { cwd: repositoryRoot },
  );
  const evidence = JSON.parse(evidenceText);
  for (const artifact of evidence.artifacts) {
    const contents = execFileSync(
      "git",
      ["show", `${f01EvidenceFrozenCommit}:${artifact.path}`],
      { cwd: repositoryRoot },
    );
    assert.equal(fileHash(contents), artifact.sha256, artifact.path);
  }
  assert.ok(f01.artifact_refs.includes(evidence.evidence_ref));
  assert.ok(f01.evidence_hashes.includes(fileHash(evidenceText)));
});

test("an empty D1 journal does not inherit work-package state from the Manifest", async () => {
  const control = createProjectControl({
    manifest: await loadManifest(),
    journal: createMemoryJournal(),
  });
  const snapshot = await control.snapshot(owner);
  const f01 = snapshot.workPackages.find(({ id }) => id === "F01");
  const f02 = snapshot.workPackages.find(({ id }) => id === "F02");
  const c03 = snapshot.workPackages.find(({ id }) => id === "C03");

  assert.equal(snapshot.progress.product.verified, 0);
  assert.equal(snapshot.progress.product.total, 29);
  assert.equal(snapshot.progress.portfolio.verified, 0);
  assert.equal(snapshot.progress.portfolio.total, 37);
  assert.equal(f01.implementationStatus, "NOT_STARTED");
  assert.equal(f01.verificationStatus, "NOT_VERIFIED");
  assert.deepEqual(f01.evidenceRefs, []);
  assert.equal(f02.verificationStatus, "NOT_VERIFIED");
  assert.equal(f02.allowedToStart, false);
  assert.ok(f02.blockers.includes("F01"));
  assert.equal(c03.allowedToStart, false);
  assert.ok(c03.blockers.includes("G0"));
  assert.equal(snapshot.gates[0].status, "NOT_READY");
});

test("a verified work package rejects evidence outside the frozen Git catalog", async () => {
  const control = createProjectControl({
    manifest: await loadManifest(),
    journal: createMemoryJournal(),
    verifyFrozenEvidence: verifyTestFrozenEvidence,
  });

  const before = await control.snapshot(owner);
  await assert.rejects(
    control.execute(
      owner,
      command(
        "RECORD_WORK_PACKAGE",
        {
          workPackageId: "F01",
          implementationStatus: "IMPLEMENTED",
          verificationStatus: "VERIFIED",
          evidenceRefs: ["evidence/F01.json"],
          evidenceHashes: [`sha256:${"f".repeat(64)}`],
          note: "format-only fake evidence",
        },
        0,
        "reject-fake-f01",
      ),
    ),
    (error) => error.code === "EVIDENCE_NOT_FROZEN",
  );
  const after = await control.snapshot(owner);
  assert.equal(after.revision, before.revision);
  assert.equal(after.events.length, before.events.length);
});

test("an unfrozen historical event keeps its recorded D1 status and raises a governance issue", async () => {
  const control = createProjectControl({
    manifest: await loadManifest(),
    journal: createMemoryJournal([
      {
        id: "forged-f01",
        type: "WORK_PACKAGE_RECORDED",
        actorId: "forged_actor",
        createdAt: "2026-07-28T00:00:00.000Z",
        payload: {
          workPackageId: "F01",
          implementationStatus: "IMPLEMENTED",
          verificationStatus: "VERIFIED",
          evidenceRefs: ["unreferenced.json"],
          evidenceHashes: [`sha256:${"f".repeat(64)}`],
          note: "forged direct journal event",
        },
      },
    ]),
  });

  const snapshot = await control.snapshot(owner);
  const f01 = snapshot.workPackages.find(({ id }) => id === "F01");
  assert.equal(f01.implementationStatus, "IMPLEMENTED");
  assert.equal(f01.verificationStatus, "VERIFIED");
  assert.deepEqual(snapshot.evidenceValidationIssues, [
    {
      code: "EVIDENCE_NOT_FROZEN",
      workPackageId: "F01",
      eventId: "forged-f01",
      revision: 1,
    },
  ]);
});

test("a later frozen event repairs an invalid historical evidence event append-only", async () => {
  const validEvidence = testEvidenceRecords.find(
    ({ workPackageId }) => workPackageId === "F01",
  );
  const control = createProjectControl({
    manifest: await loadManifest(),
    verifyFrozenEvidence: verifyTestFrozenEvidence,
    journal: createMemoryJournal([
      {
        id: "invalid-f01",
        type: "WORK_PACKAGE_RECORDED",
        actorId: "external_product_owner",
        createdAt: "2026-07-27T00:00:00.000Z",
        payload: {
          workPackageId: "F01",
          implementationStatus: "IMPLEMENTED",
          verificationStatus: "VERIFIED",
          evidenceRefs: ["unreferenced.json"],
          evidenceHashes: [`sha256:${"f".repeat(64)}`],
          note: "invalid historical evidence",
        },
      },
      {
        id: "repaired-f01",
        type: "WORK_PACKAGE_RECORDED",
        actorId: "external_product_owner",
        createdAt: "2026-07-28T00:00:00.000Z",
        payload: {
          workPackageId: "F01",
          implementationStatus: "IMPLEMENTED",
          verificationStatus: "VERIFIED",
          evidenceRefs: validEvidence.evidenceRefs,
          evidenceHashes: validEvidence.evidenceHashes,
          note: "append-only repair",
        },
      },
    ]),
  });

  const snapshot = await control.snapshot(owner);
  const f01 = snapshot.workPackages.find(({ id }) => id === "F01");
  assert.equal(f01.verificationStatus, "VERIFIED");
  assert.deepEqual(snapshot.evidenceValidationIssues, []);
});

test("historical F04 evidence health does not rewrite D1 or G0, while new Gate action is blocked", async () => {
  const manifest = await loadManifest();
  const p0EvidenceIndex = await loadJson("p0-frozen-evidence-index.v1.json");
  const verifyFrozenEvidence = createFrozenEvidenceVerifier(p0EvidenceIndex);
  const replay = historicalG0Replay(manifest, p0EvidenceIndex);
  const control = createProjectControl({
    manifest,
    verifyFrozenEvidence,
    journal: createMemoryJournal(replay.events),
    ...syntheticReferenceReviewPrerequisites,
  });

  let snapshot = await control.snapshot(owner);
  assert.equal(snapshot.gates[0].status, "APPROVED");
  assert.deepEqual(snapshot.gates[0].missingWorkPackages, []);
  assert.equal(snapshot.phaseEntry.P1, true);
  assert.equal(
    snapshot.workPackages.filter(
      ({ phase, verificationStatus }) =>
        phase === "P0" && verificationStatus === "VERIFIED",
    ).length,
    4,
  );
  assert.equal(
    snapshot.workPackages.find(({ id }) => id === "F04")
      .verificationStatus,
    "VERIFIED",
  );
  assert.deepEqual(
    snapshot.workPackages.find(({ id }) => id === "F04").evidenceHashes,
    replay.historicalScope.find(
      ({ work_package_id }) => work_package_id === "F04",
    ).evidence_hashes,
  );
  assert.equal(snapshot.evidenceValidationIssues[0].workPackageId, "F04");

  const beforeBlockedSubmission = {
    revision: snapshot.revision,
    eventCount: snapshot.events.length,
  };
  await assert.rejects(
    control.execute(
      owner,
      command(
        "SUBMIT_GATE",
        {
          gateId: "G0",
          evidenceRefs: replay.historicalScope.flatMap(
            ({ evidence_refs }) => evidence_refs,
          ),
          supersedes: "historical-g0-submission",
        },
        snapshot.revision,
        "blocked-g0-resubmission",
      ),
    ),
    (error) => error.code === "EVIDENCE_NOT_FROZEN",
  );
  snapshot = await control.snapshot(owner);
  assert.equal(snapshot.revision, beforeBlockedSubmission.revision);
  assert.equal(snapshot.events.length, beforeBlockedSubmission.eventCount);

  const validF04 = p0EvidenceIndex.records.find(
    ({ workPackageId }) => workPackageId === "F04",
  );
  await control.execute(
    owner,
    command(
      "RECORD_WORK_PACKAGE",
      {
        workPackageId: "F04",
        implementationStatus: "IMPLEMENTED",
        verificationStatus: "VERIFIED",
        evidenceRefs: validF04.evidenceRefs,
        evidenceHashes: validF04.evidenceHashes,
        note: "append-only F04 evidence repair",
      },
      snapshot.revision,
      "repair-f04",
    ),
  );

  snapshot = await control.snapshot(owner);
  assert.equal(snapshot.gates[0].status, "READY_TO_SUBMIT");
  assert.deepEqual(snapshot.gates[0].missingWorkPackages, []);
  assert.deepEqual(snapshot.evidenceValidationIssues, []);
  assert.equal(snapshot.gates[0].latestDecision.decision, "APPROVE");
  assert.equal(snapshot.phaseEntry.P1, false);
});

test("a new Gate decision is blocked when its phase has unfrozen evidence", async () => {
  const manifest = await loadManifest();
  const p0EvidenceIndex = await loadJson("p0-frozen-evidence-index.v1.json");
  const replay = historicalG0Replay(manifest, p0EvidenceIndex, false);
  const control = createProjectControl({
    manifest,
    verifyFrozenEvidence: createFrozenEvidenceVerifier(p0EvidenceIndex),
    journal: createMemoryJournal(replay.events),
  });
  const snapshot = await control.snapshot(owner);

  assert.equal(snapshot.gates[0].status, "AWAITING_DECISION");
  const beforeBlockedDecision = {
    revision: snapshot.revision,
    eventCount: snapshot.events.length,
  };
  await assert.rejects(
    control.execute(
      owner,
      command(
        "DECIDE_GATE",
        {
          submissionId: "historical-g0-submission",
          expectedPackageHash:
            "sha256:77d8707a602a83729b557c028bd6cf87c5a0e5d921145b9dc3a5a1e79bf32a07",
          decision: "APPROVE",
          acceptedExclusions: [],
          evidenceRefs: ["product-owner-decision"],
        },
        snapshot.revision,
        "blocked-g0-decision",
      ),
    ),
    (error) => error.code === "EVIDENCE_NOT_FROZEN",
  );
  const after = await control.snapshot(owner);
  assert.equal(after.revision, beforeBlockedDecision.revision);
  assert.equal(after.events.length, beforeBlockedDecision.eventCount);
});

test("a D1 state event cannot redefine a Manifest work package", async () => {
  const manifest = await loadManifest();
  const definition = manifest.work_packages.find(({ id }) => id === "F01");
  const control = createProjectControl({
    manifest,
    journal: createMemoryJournal([
      {
        id: "state-only-f01",
        type: "WORK_PACKAGE_RECORDED",
        actorId: "external_product_owner",
        createdAt: "2026-07-28T00:00:00.000Z",
        payload: {
          workPackageId: "F01",
          title: "D1 must not replace this title",
          phase: "P3",
          depends_on: ["T08"],
          implementationStatus: "IN_PROGRESS",
          verificationStatus: "NOT_VERIFIED",
          evidenceRefs: [],
          evidenceHashes: [],
          note: "state-only event",
        },
      },
    ]),
  });

  const f01 = (await control.snapshot(owner)).workPackages.find(
    ({ id }) => id === "F01",
  );
  assert.equal(f01.title, definition.title);
  assert.equal(f01.phase, definition.phase);
  assert.deepEqual(f01.dependencies, definition.depends_on);
  assert.equal(f01.implementationStatus, "IN_PROGRESS");
});

test("revision-64 P1 evidence references replay without false governance issues", async () => {
  const bindings = await loadJson(
    "p1-d1-evidence-bindings.revision-64.v1.json",
  );
  const control = createProjectControl({
    manifest: await loadManifest(),
    verifyFrozenEvidence: createFrozenEvidenceVerifier(bindings),
    journal: createMemoryJournal(
      bindings.records.map((entry, index) => ({
        id: `revision-64-${entry.workPackageId.toLowerCase()}`,
        type: "WORK_PACKAGE_RECORDED",
        actorId: "external_product_owner",
        createdAt: `2026-07-27T01:00:${String(index).padStart(2, "0")}.000Z`,
        payload: {
          workPackageId: entry.workPackageId,
          implementationStatus: "IMPLEMENTED",
          verificationStatus: "VERIFIED",
          evidenceRefs: entry.evidenceRefs,
          evidenceHashes: entry.evidenceHashes,
          note: `revision-64 ${entry.workPackageId}`,
        },
      })),
    ),
  });

  const snapshot = await control.snapshot(owner);
  assert.deepEqual(snapshot.evidenceValidationIssues, []);
  assert.equal(
    snapshot.workPackages.filter(
      ({ phase, verificationStatus }) =>
        phase === "P1" && verificationStatus === "VERIFIED",
    ).length,
    19,
  );
});

test("dependencies and phase gates are enforced by the shared module", async () => {
  const control = createProjectControl({
    manifest: await loadManifest(),
    journal: createMemoryJournal(),
  });

  await assert.rejects(
    control.execute(
      owner,
      command(
        "RECORD_WORK_PACKAGE",
        {
          workPackageId: "F03",
          implementationStatus: "IN_PROGRESS",
          verificationStatus: "NOT_VERIFIED",
          evidenceRefs: [],
          evidenceHashes: [],
          note: "premature start",
        },
        0,
        "premature-f03",
      ),
    ),
    (error) => error.code === "DEPENDENCY_BLOCKED",
  );

  await assert.rejects(
    control.execute(
      owner,
      command(
        "RECORD_WORK_PACKAGE",
        {
          workPackageId: "C03",
          implementationStatus: "IN_PROGRESS",
          verificationStatus: "NOT_VERIFIED",
          evidenceRefs: [],
          evidenceHashes: [],
          note: "premature phase start",
        },
        0,
        "premature-c03",
      ),
    ),
    (error) => error.code === "DEPENDENCY_BLOCKED",
  );
});

test("P2 stays closed unless both G0 and G1 are approved", async () => {
  const manifest = await loadManifest();
  const p1Definitions = manifest.work_packages.filter(
    ({ phase }) => phase === "P1",
  );
  const p1Events = p1Definitions.map((item, index) => ({
    id: `historical-${item.id.toLowerCase()}`,
    type: "WORK_PACKAGE_RECORDED",
    actorId: "external_product_owner",
    createdAt: `2026-07-27T00:00:${String(index).padStart(2, "0")}.000Z`,
    payload: {
      workPackageId: item.id,
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
      evidenceRefs: [`evidence/${item.id}.json`],
      evidenceHashes: [`sha256:${String(index + 1).padStart(64, "0")}`],
      note: `historical ${item.id}`,
    },
  }));
  const g1Scope = p1Definitions.map((item, index) => ({
    work_package_id: item.id,
    applicability: item.applicability,
    implementation_status: "IMPLEMENTED",
    verification_status: "VERIFIED",
    evidence_refs: [`evidence/${item.id}.json`],
    evidence_hashes: [`sha256:${String(index + 1).padStart(64, "0")}`],
  }));
  const control = createProjectControl({
    manifest,
    journal: createMemoryJournal([
      ...p1Events,
      {
        id: "historical-g1-submission-event",
        type: "GATE_SUBMITTED",
        actorId: "external_product_owner",
        createdAt: "2026-07-27T00:01:00.000Z",
        payload: {
          gate_id: "G1",
          submission_id: "historical-g1-submission",
          package_hash: `sha256:${"a".repeat(64)}`,
          submitted_at: "2026-07-27T00:01:00.000Z",
          submitted_by: "external_product_owner",
          source_revision: 19,
          work_package_scope: g1Scope,
          evidence_refs: g1Scope.flatMap(
            ({ evidence_refs }) => evidence_refs,
          ),
          supersedes: null,
        },
      },
      {
        id: "historical-g1-decision-event",
        type: "GATE_DECIDED",
        actorId: "external_product_owner",
        createdAt: "2026-07-27T00:02:00.000Z",
        payload: {
          decision_id: "historical-g1-decision",
          submission_id: "historical-g1-submission",
          package_hash: `sha256:${"a".repeat(64)}`,
          decision: "APPROVE",
          decided_by: "external_product_owner",
          decided_at: "2026-07-27T00:02:00.000Z",
          accepted_exclusions: [],
          evidence_refs: ["historical-product-owner-decision"],
        },
      },
    ]),
  });

  const snapshot = await control.snapshot(owner);
  const o02 = snapshot.workPackages.find(({ id }) => id === "O02");
  assert.equal(snapshot.gates.find(({ id }) => id === "G1").status, "APPROVED");
  assert.equal(snapshot.phaseEntry.P2, false);
  assert.equal(o02.allowedToStart, false);
  assert.ok(o02.blockers.includes("G0"));
  await assert.rejects(
    control.execute(
      owner,
      command(
        "SUBMIT_GATE",
        {
          gateId: "G2",
          evidenceRefs: ["synthetic-g2-evidence"],
          supersedes: null,
        },
        snapshot.revision,
        "blocked-g2-predecessor",
      ),
    ),
    (error) => error.code === "GATE_PREDECESSOR_NOT_APPROVED",
  );
  const after = await control.snapshot(owner);
  assert.equal(after.revision, snapshot.revision);
  assert.equal(after.events.length, snapshot.events.length);
});

test("a gate submission is hashed by the module and a decision is immutable", async () => {
  const control = createProjectControl({
    manifest: await loadManifest(),
    journal: createMemoryJournal(),
    verifyFrozenEvidence: verifyTestFrozenEvidence,
    ...syntheticReferenceReviewPrerequisites,
    clock: () => "2026-07-26T00:00:00.000Z",
    idFactory: (() => {
      let value = 0;
      return () => `immutable-${++value}`;
    })(),
  });

  let revision = 0;
  for (const packageId of ["F01", "F02", "F03", "F04"]) {
    const receipt = await verifyPackage(control, packageId, revision);
    revision = receipt.revision;
  }

  let snapshot = await control.snapshot(owner);
  assert.equal(snapshot.gates[0].status, "READY_TO_SUBMIT");

  const submissionReceipt = await control.execute(
    owner,
    command(
      "SUBMIT_GATE",
      { gateId: "G0", evidenceRefs: ["evidence/g0-package.json"] },
      revision,
      "submit-g0",
    ),
  );
  revision = submissionReceipt.revision;
  const { submission } = submissionReceipt.output;
  assert.match(submission.package_hash, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(submission).sort(), [
    "evidence_refs",
    "gate_id",
    "package_hash",
    "source_revision",
    "submission_id",
    "submitted_at",
    "submitted_by",
    "supersedes",
    "work_package_scope",
  ]);

  const comparisonControl = createProjectControl({
    manifest: await loadManifest(),
    journal: createMemoryJournal(),
    verifyFrozenEvidence: verifyTestFrozenEvidence,
    ...syntheticReferenceReviewPrerequisites,
    idFactory: () => "different-record-id",
  });
  let comparisonRevision = 0;
  for (const packageId of ["F01", "F02", "F03", "F04"]) {
    comparisonRevision = (
      await verifyPackage(comparisonControl, packageId, comparisonRevision)
    ).revision;
  }
  const comparisonSubmission = await comparisonControl.execute(
    owner,
    command(
      "SUBMIT_GATE",
      { gateId: "G0", evidenceRefs: ["evidence/g0-package.json"] },
      comparisonRevision,
      "comparison-submit-g0",
    ),
  );
  assert.equal(
    comparisonSubmission.output.submission.package_hash,
    submission.package_hash,
  );

  snapshot = await control.snapshot(owner);
  assert.equal(snapshot.gates[0].status, "AWAITING_DECISION");

  const decisionReceipt = await control.execute(
    owner,
    command(
      "DECIDE_GATE",
      {
        submissionId: submission.submission_id,
        expectedPackageHash: submission.package_hash,
        decision: "APPROVE",
        acceptedExclusions: [],
        evidenceRefs: ["evidence/product-owner-g0.json"],
      },
      revision,
      "decide-g0",
    ),
  );
  revision = decisionReceipt.revision;
  assert.deepEqual(Object.keys(decisionReceipt.output.decision).sort(), [
    "accepted_exclusions",
    "decided_at",
    "decided_by",
    "decision",
    "decision_id",
    "evidence_refs",
    "package_hash",
    "submission_id",
  ]);

  snapshot = await control.snapshot(owner);
  assert.equal(snapshot.gates[0].status, "APPROVED");
  assert.equal(snapshot.phaseEntry.P1, true);

  await assert.rejects(
    control.execute(
      owner,
      command(
        "DECIDE_GATE",
        {
          submissionId: submission.submission_id,
          expectedPackageHash: submission.package_hash,
          decision: "HOLD",
          acceptedExclusions: [],
          evidenceRefs: ["evidence/second-decision.json"],
        },
        revision,
        "decide-g0-again",
      ),
    ),
    (error) => error.code === "DECISION_EXISTS",
  );
});

test("a decision must name the exact frozen package hash", async () => {
  const control = createProjectControl({
    manifest: await loadManifest(),
    journal: createMemoryJournal(),
    verifyFrozenEvidence: verifyTestFrozenEvidence,
    ...syntheticReferenceReviewPrerequisites,
  });

  let revision = 0;
  for (const packageId of ["F01", "F02", "F03", "F04"]) {
    revision = (await verifyPackage(control, packageId, revision)).revision;
  }
  const receipt = await control.execute(
    owner,
    command(
      "SUBMIT_GATE",
      { gateId: "G0", evidenceRefs: ["evidence/g0-package.json"] },
      revision,
      "submit-g0-hash-check",
    ),
  );

  await assert.rejects(
    control.execute(
      owner,
      command(
        "DECIDE_GATE",
        {
          submissionId: receipt.output.submission.submission_id,
          expectedPackageHash: `sha256:${"0".repeat(64)}`,
          decision: "APPROVE",
          acceptedExclusions: [],
          evidenceRefs: ["evidence/product-owner-g0.json"],
        },
        receipt.revision,
        "wrong-hash",
      ),
    ),
    (error) => error.code === "HASH_MISMATCH",
  );
});

test("returned work needs changed evidence and a superseding submission", async () => {
  const control = createProjectControl({
    manifest: await loadManifest(),
    journal: createMemoryJournal(),
    verifyFrozenEvidence: verifyTestFrozenEvidence,
    ...syntheticReferenceReviewPrerequisites,
  });
  let revision = 0;
  for (const packageId of ["F01", "F02", "F03", "F04"]) {
    revision = (await verifyPackage(control, packageId, revision)).revision;
  }
  const first = await control.execute(
    owner,
    command(
      "SUBMIT_GATE",
      { gateId: "G0", evidenceRefs: ["evidence/g0-v1.json"] },
      revision,
      "submit-g0-v1",
    ),
  );
  revision = first.revision;
  const returned = await control.execute(
    owner,
    command(
      "DECIDE_GATE",
      {
        submissionId: first.output.submission.submission_id,
        expectedPackageHash: first.output.submission.package_hash,
        decision: "RETURN",
        acceptedExclusions: [],
        evidenceRefs: ["evidence/g0-return.json"],
      },
      revision,
      "return-g0-v1",
    ),
  );
  revision = returned.revision;
  assert.equal((await control.snapshot(owner)).gates[0].status, "RETURNED");

  const revised = await control.execute(
    owner,
    command(
      "RECORD_WORK_PACKAGE",
      {
        workPackageId: "F04",
        implementationStatus: "IMPLEMENTED",
        verificationStatus: "VERIFIED",
        evidenceRefs: ["evidence/F04-v2.json"],
        evidenceHashes: [`sha256:${"e".repeat(64)}`],
        note: "F04 revised after return",
      },
      revision,
      "revise-f04",
    ),
  );
  revision = revised.revision;
  assert.equal(
    (await control.snapshot(owner)).gates[0].status,
    "READY_TO_SUBMIT",
  );

  await assert.rejects(
    control.execute(
      owner,
      command(
        "SUBMIT_GATE",
        { gateId: "G0", evidenceRefs: ["evidence/g0-v2.json"] },
        revision,
        "submit-g0-v2-without-link",
      ),
    ),
    (error) => error.code === "INVALID_SUPERSEDES",
  );

  const second = await control.execute(
    owner,
    command(
      "SUBMIT_GATE",
      {
        gateId: "G0",
        evidenceRefs: ["evidence/g0-v2.json"],
        supersedes: first.output.submission.submission_id,
      },
      revision,
      "submit-g0-v2",
    ),
  );
  assert.notEqual(
    second.output.submission.package_hash,
    first.output.submission.package_hash,
  );
});

test("idempotent command replay does not append a second event", async () => {
  const control = createProjectControl({
    manifest: await loadManifest(),
    journal: createMemoryJournal(),
    ...syntheticReferenceReviewPrerequisites,
  });
  const first = command(
    "RECORD_WORK_PACKAGE",
    {
      workPackageId: "F01",
      implementationStatus: "IN_PROGRESS",
      verificationStatus: "NOT_VERIFIED",
      evidenceRefs: [],
      evidenceHashes: [],
      note: "started",
    },
    0,
    "same-command",
  );

  const receipt = await control.execute(owner, first);
  const replay = await control.execute(owner, first);

  assert.equal(receipt.revision, 1);
  assert.equal(replay.revision, 1);
  assert.equal(replay.duplicate, true);
  assert.equal((await control.snapshot(owner)).revision, 1);
});

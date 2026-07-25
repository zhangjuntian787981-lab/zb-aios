import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createMemoryJournal,
  createProjectControl,
} from "../lib/project-control.mjs";

const manifestPath = new URL(
  "../implementation/governance/work-package-manifest.v1.json",
  import.meta.url,
);

async function loadManifest() {
  return JSON.parse(await readFile(manifestPath, "utf8"));
}

async function loadFreshP0Manifest() {
  const manifest = await loadManifest();
  for (const item of manifest.work_packages.filter(({ id }) =>
    ["F02", "F03", "F04"].includes(id),
  )) {
    item.status = "NOT_STARTED";
    item.plan_status = "PLANNED";
    item.implementation_status = "NOT_STARTED";
    item.verification_status = "NOT_VERIFIED";
    item.artifact_refs = [];
    item.evidence_hashes = [];
    item.verified_at = null;
  }
  return manifest;
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

async function verifyPackage(control, packageId, revision) {
  return control.execute(
    owner,
    command(
      "RECORD_WORK_PACKAGE",
      {
        workPackageId: packageId,
        implementationStatus: "IMPLEMENTED",
        verificationStatus: "VERIFIED",
        evidenceRefs: [`evidence/${packageId}.json`],
        evidenceHashes: [`sha256:${packageId.toLowerCase().padEnd(64, "a")}`],
        note: `${packageId} verification`,
      },
      revision,
      `verify-${packageId}`,
    ),
  );
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
  const evidenceText = await readFile(
    new URL(`../${evidencePath}`, import.meta.url),
  );
  const evidence = JSON.parse(evidenceText);
  for (const artifact of evidence.artifacts) {
    const contents = await readFile(new URL(`../${artifact.path}`, import.meta.url));
    assert.equal(fileHash(contents), artifact.sha256, artifact.path);
  }
  assert.ok(f01.artifact_refs.includes(evidence.evidence_ref));
  assert.ok(f01.evidence_hashes.includes(fileHash(evidenceText)));
});

test("the current baseline reports only evidence-verified work and keeps G0 closed", async () => {
  const control = createProjectControl({
    manifest: await loadManifest(),
    journal: createMemoryJournal(),
  });
  const snapshot = await control.snapshot(owner);
  const f01 = snapshot.workPackages.find(({ id }) => id === "F01");
  const f02 = snapshot.workPackages.find(({ id }) => id === "F02");
  const c03 = snapshot.workPackages.find(({ id }) => id === "C03");

  assert.equal(snapshot.progress.product.verified, 3);
  assert.equal(snapshot.progress.product.total, 29);
  assert.equal(snapshot.progress.portfolio.verified, 3);
  assert.equal(snapshot.progress.portfolio.total, 37);
  assert.equal(f01.verificationStatus, "VERIFIED");
  assert.equal(f02.verificationStatus, "VERIFIED");
  assert.equal(f02.allowedToStart, true);
  assert.equal(c03.allowedToStart, false);
  assert.ok(c03.blockers.includes("G0"));
  assert.equal(snapshot.gates[0].status, "NOT_READY");
});

test("dependencies and phase gates are enforced by the shared module", async () => {
  const control = createProjectControl({
    manifest: await loadFreshP0Manifest(),
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

test("a gate submission is hashed by the module and a decision is immutable", async () => {
  const control = createProjectControl({
    manifest: await loadFreshP0Manifest(),
    journal: createMemoryJournal(),
    clock: () => "2026-07-26T00:00:00.000Z",
    idFactory: (() => {
      let value = 0;
      return () => `immutable-${++value}`;
    })(),
  });

  let revision = 0;
  for (const packageId of ["F02", "F03", "F04"]) {
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
    manifest: await loadFreshP0Manifest(),
    journal: createMemoryJournal(),
    idFactory: () => "different-record-id",
  });
  let comparisonRevision = 0;
  for (const packageId of ["F02", "F03", "F04"]) {
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
    manifest: await loadFreshP0Manifest(),
    journal: createMemoryJournal(),
  });

  let revision = 0;
  for (const packageId of ["F02", "F03", "F04"]) {
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
    manifest: await loadFreshP0Manifest(),
    journal: createMemoryJournal(),
  });
  let revision = 0;
  for (const packageId of ["F02", "F03", "F04"]) {
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
    manifest: await loadFreshP0Manifest(),
    journal: createMemoryJournal(),
  });
  const first = command(
    "RECORD_WORK_PACKAGE",
    {
      workPackageId: "F02",
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

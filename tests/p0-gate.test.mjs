import assert from "node:assert/strict";
import test from "node:test";
import {
  createMemoryJournal,
  createProjectControl,
} from "../lib/project-control.mjs";
import {
  evaluateP0,
  loadGovernanceSnapshot,
  loadJson,
} from "../scripts/p0-gate.mjs";

const baselinePath = new URL(
  "../implementation/p0/baseline.json",
  import.meta.url,
);
const manifestPath = new URL(
  "../implementation/governance/work-package-manifest.v1.json",
  import.meta.url,
);
const owner = {
  actorId: "external_product_owner",
  roles: ["PRODUCT_OWNER"],
};

async function approvedG0Snapshot() {
  const control = createProjectControl({
    manifest: await loadJson(manifestPath),
    journal: createMemoryJournal(),
  });
  let revision = 0;
  for (const id of ["F02", "F03", "F04"]) {
    const receipt = await control.execute(owner, {
      kind: "RECORD_WORK_PACKAGE",
      workPackageId: id,
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
      evidenceRefs: [`evidence/${id}.json`],
      evidenceHashes: [`sha256:${id.toLowerCase().padEnd(64, "a")}`],
      note: `${id} verified`,
      expectedRevision: revision,
      idempotencyKey: `verify-${id}`,
    });
    revision = receipt.revision;
  }
  const submission = await control.execute(owner, {
    kind: "SUBMIT_GATE",
    gateId: "G0",
    evidenceRefs: ["evidence/g0.json"],
    expectedRevision: revision,
    idempotencyKey: "submit-g0",
  });
  revision = submission.revision;
  await control.execute(owner, {
    kind: "DECIDE_GATE",
    submissionId: submission.output.submission.submission_id,
    expectedPackageHash: submission.output.submission.package_hash,
    decision: "APPROVE",
    acceptedExclusions: [],
    evidenceRefs: ["evidence/g0-decision.json"],
    expectedRevision: revision,
    idempotencyKey: "approve-g0",
  });
  return control.snapshot();
}

test("current P0 truth is NOT_READY because F02-F04 and G0 remain incomplete", async () => {
  const result = evaluateP0(
    await loadJson(baselinePath),
    await loadGovernanceSnapshot(),
  );

  assert.equal(result.status, "NOT_READY");
  assert.equal(result.p1Allowed, false);
  assert.equal(result.securityIssues.length, 0);
  assert.equal(result.authorityReady, true);
  assert.equal(result.gateStatus, "NOT_READY");
  assert.deepEqual(result.verifiedWorkPackages, ["F01"]);
  assert.deepEqual(result.missingWorkPackages, ["F02", "F03", "F04"]);
});

test("P0 becomes READY only after a real immutable G0 approval", async () => {
  const result = evaluateP0(
    await loadJson(baselinePath),
    await approvedG0Snapshot(),
  );
  assert.equal(result.status, "READY");
  assert.equal(result.p1Allowed, true);
  assert.equal(result.gateStatus, "APPROVED");
});

test("a legacy mutable stage_approval label cannot open P1", async () => {
  const baseline = await loadJson(baselinePath);
  baseline.stage_approval = {
    status: "APPROVED",
    approved_by: "external_product_owner",
    artifact_hash: `sha256:${"a".repeat(64)}`,
  };

  const result = evaluateP0(baseline, await loadGovernanceSnapshot());
  assert.equal(result.status, "NOT_READY");
  assert.equal(result.gateStatus, "NOT_READY");
  assert.equal(result.p1Allowed, false);
});

test("connector credentials or network access block the gate", async () => {
  const baseline = await loadJson(baselinePath);
  baseline.connectors[0].credentials_present = true;
  baseline.connectors[0].outbound_network = true;

  const result = evaluateP0(baseline, await approvedG0Snapshot());
  assert.equal(result.status, "BLOCKED");
  assert.equal(result.p1Allowed, false);
  assert.match(result.securityIssues.join("\n"), /生产凭据/);
  assert.match(result.securityIssues.join("\n"), /出站网络/);
});

test("enterprise information before P3 is a security block", async () => {
  const baseline = await loadJson(baselinePath);
  baseline.enterprise_boundary.information_present = true;
  baseline.source_modes.approved_snapshot_enabled = true;

  const result = evaluateP0(baseline, await loadGovernanceSnapshot());
  assert.equal(result.status, "BLOCKED");
  assert.match(result.securityIssues.join("\n"), /企业内部资料/);
  assert.match(result.securityIssues.join("\n"), /企业快照/);
});

test("missing Product Owner authority keeps an approved gate closed", async () => {
  const baseline = await loadJson(baselinePath);
  baseline.approval_authority.status = "NOT_CONFIGURED";
  baseline.approval_authority.evidence_refs = [];

  const result = evaluateP0(baseline, await approvedG0Snapshot());
  assert.equal(result.status, "NOT_READY");
  assert.equal(result.authorityReady, false);
  assert.equal(result.p1Allowed, false);
});

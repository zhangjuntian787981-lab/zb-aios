import assert from "node:assert/strict";
import test from "node:test";
import { evaluateP0, loadBaseline } from "../scripts/p0-gate.mjs";

const baselinePath = new URL(
  "../implementation/p0/baseline.json",
  import.meta.url,
);

async function fullyReadyBaseline() {
  const ready = structuredClone(await loadBaseline(baselinePath));
  ready.approval_authority = {
    ...ready.approval_authority,
    status: "ACTIVE",
    product_owner_id: "external_product_owner",
    authority_basis: "USER_DEFINED_PRODUCT_GOVERNANCE",
    evidence_refs: ["evidence/product-owner-directive.md"],
  };
  ready.decision_gates.forEach((gate) => {
    gate.status = "CONFIRMED";
    gate.evidence_refs = [`evidence/${gate.id}.md`];
  });
  ready.stage_approval = {
    ...ready.stage_approval,
    status: "APPROVED",
    approved_by: "external_product_owner",
    approved_at: "2026-08-02T00:00:00Z",
    artifact_hash: `sha256:${"a".repeat(64)}`,
    evidence_refs: ["evidence/p0-stage-approval.md"],
  };
  ready.technical_gates.forEach((gate) => {
    gate.status = "VERIFIED";
    gate.evidence_refs = [`evidence/${gate.id}.json`];
  });
  return ready;
}

test("current generic-product P0 remains gated by technical evidence and stage approval", async () => {
  const result = evaluateP0(await loadBaseline(baselinePath));

  assert.equal(result.status, "NOT_READY");
  assert.equal(result.p1Allowed, false);
  assert.equal(result.securityIssues.length, 0);
  assert.equal(result.missingDecisions.length, 0);
  assert.equal(result.authorityReady, true);
  assert.equal(result.stageApproval, "NOT_DECIDED");
  assert.ok(result.missingTechnicalEvidence.length > 0);
});

test("P0 becomes ready only after technical proof and Product Owner stage approval", async () => {
  const result = evaluateP0(await fullyReadyBaseline());
  assert.equal(result.status, "READY");
  assert.equal(result.p1Allowed, true);
});

test("connector credentials or network access block the gate", async () => {
  const baseline = await loadBaseline(baselinePath);
  const unsafe = structuredClone(baseline);
  unsafe.connectors[0].credentials_present = true;
  unsafe.connectors[0].outbound_network = true;

  const result = evaluateP0(unsafe);
  assert.equal(result.status, "BLOCKED");
  assert.equal(result.p1Allowed, false);
  assert.match(result.securityIssues.join("\n"), /生产凭据/);
  assert.match(result.securityIssues.join("\n"), /出站网络/);
});

test("labels alone cannot pass without evidence and an authorized decision", async () => {
  const baseline = await loadBaseline(baselinePath);
  const labelsOnly = structuredClone(baseline);
  labelsOnly.decision_gates.forEach((gate) => {
    gate.status = "CONFIRMED";
    gate.evidence_refs = [];
  });
  labelsOnly.technical_gates.forEach((gate) => {
    gate.status = "VERIFIED";
    gate.evidence_refs = [];
  });
  labelsOnly.stage_approval.status = "APPROVED";
  labelsOnly.stage_approval.approved_by = "external_product_owner";
  labelsOnly.stage_approval.approved_at = "2026-08-02T00:00:00Z";
  labelsOnly.stage_approval.artifact_hash = `sha256:${"b".repeat(64)}`;
  labelsOnly.stage_approval.evidence_refs = [];

  const result = evaluateP0(labelsOnly);
  assert.equal(result.status, "NOT_READY");
  assert.equal(
    result.missingDecisions.length,
    labelsOnly.decision_gates.length,
  );
  assert.equal(
    result.missingTechnicalEvidence.length,
    labelsOnly.technical_gates.length,
  );
  assert.equal(result.p1Allowed, false);
});

test("missing Product Owner authority keeps P0 not ready", async () => {
  const missingAuthority = await fullyReadyBaseline();
  missingAuthority.approval_authority.status = "NOT_CONFIGURED";
  missingAuthority.approval_authority.evidence_refs = [];

  const result = evaluateP0(missingAuthority);
  assert.equal(result.status, "NOT_READY");
  assert.equal(result.authorityReady, false);
  assert.equal(result.p1Allowed, false);
});

test("stage approval by anyone except the external Product Owner is rejected", async () => {
  const wrongApprover = await fullyReadyBaseline();
  wrongApprover.stage_approval.approved_by = "target_enterprise_employee";

  const result = evaluateP0(wrongApprover);
  assert.equal(result.status, "NOT_READY");
  assert.equal(result.p1Allowed, false);
});

test("stage approval without a real sha256 artifact hash is rejected", async () => {
  const invalidHash = await fullyReadyBaseline();
  invalidHash.stage_approval.artifact_hash = "sha256:approved-by-label";

  const result = evaluateP0(invalidHash);
  assert.equal(result.status, "NOT_READY");
  assert.equal(result.p1Allowed, false);
});

test("enterprise information before P3 is a security block", async () => {
  const prematureEnterpriseData = await loadBaseline(baselinePath);
  const unsafe = structuredClone(prematureEnterpriseData);
  unsafe.enterprise_boundary.information_present = true;
  unsafe.source_modes.approved_snapshot_enabled = true;

  const result = evaluateP0(unsafe);
  assert.equal(result.status, "BLOCKED");
  assert.match(result.securityIssues.join("\n"), /企业内部资料/);
  assert.match(result.securityIssues.join("\n"), /企业快照/);
  assert.equal(result.p1Allowed, false);
});

test("premature P1 permission is a security block", async () => {
  const baseline = await loadBaseline(baselinePath);
  const premature = structuredClone(baseline);
  premature.p1.allowed = true;

  const result = evaluateP0(premature);
  assert.equal(result.status, "BLOCKED");
  assert.match(result.securityIssues.join("\n"), /P1/);
});

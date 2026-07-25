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
    status: "AUTHORIZED",
    routine_p0_approver_id: "project-lead",
    p1_gate_approver_id: "executive-sponsor",
    delegated_by: "general-manager",
    delegated_at: "2026-08-01T00:00:00Z",
    evidence_refs: ["evidence/executive-delegation.md"],
  };
  ready.decision_gates.forEach((gate) => {
    gate.status = "CONFIRMED";
    gate.evidence_refs = [`evidence/${gate.id}.md`];
    if (gate.requires_owner_ack) {
      gate.owner_ack_refs = [`evidence/${gate.id}-owner-ack.md`];
    }
  });
  ready.consolidated_approval = {
    ...ready.consolidated_approval,
    status: "APPROVED",
    approved_by: "project-lead",
    approved_at: "2026-08-02T00:00:00Z",
    artifact_hash: "sha256:approved-package",
    evidence_refs: ["evidence/consolidated-approval.md"],
  };
  ready.technical_gates.forEach((gate) => {
    gate.status = "VERIFIED";
    gate.evidence_refs = [`evidence/${gate.id}.json`];
  });
  ready.final_decision = {
    status: "GO",
    decided_by: "executive-sponsor",
    decided_at: "2026-08-03T00:00:00Z",
    evidence_refs: ["evidence/p0-go.md"],
  };
  return ready;
}

test("authorized P0 still cannot pretend to be ready without owner facts", async () => {
  const result = evaluateP0(await loadBaseline(baselinePath));

  assert.equal(result.status, "NOT_READY");
  assert.equal(result.p1Allowed, false);
  assert.equal(result.securityIssues.length, 0);
  assert.equal(result.missingDecisions.length, 6);
  assert.equal(result.authorityReady, true);
  assert.equal(result.consolidatedApproval, "NOT_DECIDED");
  assert.ok(result.missingTechnicalEvidence.length > 0);
});

test("P0 becomes ready only after every decision and technical gate", async () => {
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
  labelsOnly.final_decision.status = "GO";

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

test("missing executive authorization alone keeps P0 not ready", async () => {
  const missingExecutiveApproval = await fullyReadyBaseline();
  const executiveGate = missingExecutiveApproval.decision_gates.find(
    (gate) => gate.id === "executive_authorization",
  );
  executiveGate.status = "AWAITING_CONFIRMATION";
  executiveGate.evidence_refs = [];

  const result = evaluateP0(missingExecutiveApproval);
  assert.equal(result.status, "NOT_READY");
  assert.deepEqual(
    result.missingDecisions.map((gate) => gate.id),
    ["executive_authorization"],
  );
  assert.equal(result.p1Allowed, false);
});

test("AI recommendations and central approval cannot replace owner facts", async () => {
  const missingOwnerFacts = await fullyReadyBaseline();
  missingOwnerFacts.decision_gates.forEach((gate) => {
    if (gate.requires_owner_ack) gate.owner_ack_refs = [];
  });

  const result = evaluateP0(missingOwnerFacts);
  assert.equal(result.status, "NOT_READY");
  assert.equal(result.missingDecisions.length, 6);
  assert.equal(result.p1Allowed, false);
});

test("an unauthorized final approver cannot release P1", async () => {
  const unauthorized = await fullyReadyBaseline();
  unauthorized.final_decision.decided_by = "any-authenticated-user";

  const result = evaluateP0(unauthorized);
  assert.equal(result.status, "NOT_READY");
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

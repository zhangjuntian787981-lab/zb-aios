import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateP0,
  loadBaseline,
} from "../scripts/p0-gate.mjs";

const baselinePath = new URL(
  "../implementation/p0/baseline.json",
  import.meta.url,
);

test("current P0 baseline cannot pretend to be ready", async () => {
  const result = evaluateP0(await loadBaseline(baselinePath));

  assert.equal(result.status, "NOT_READY");
  assert.equal(result.p1Allowed, false);
  assert.equal(result.securityIssues.length, 0);
  assert.equal(result.missingDecisions.length, 7);
  assert.ok(result.missingTechnicalEvidence.length > 0);
});

test("P0 becomes ready only after every decision and technical gate", async () => {
  const baseline = await loadBaseline(baselinePath);
  const ready = structuredClone(baseline);
  ready.decision_gates.forEach((gate) => {
    gate.status = "CONFIRMED";
    gate.evidence_refs = [`evidence/${gate.id}.md`];
  });
  ready.technical_gates.forEach((gate) => {
    gate.status = "VERIFIED";
    gate.evidence_refs = [`evidence/${gate.id}.json`];
  });
  ready.final_decision = {
    status: "GO",
    decided_by: "authorized-human",
    decided_at: "2026-08-01T00:00:00Z",
    evidence_refs: ["evidence/p0-go.md"],
  };

  const result = evaluateP0(ready);
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
  assert.equal(result.missingDecisions.length, labelsOnly.decision_gates.length);
  assert.equal(
    result.missingTechnicalEvidence.length,
    labelsOnly.technical_gates.length,
  );
  assert.equal(result.p1Allowed, false);
});

test("missing executive authorization alone keeps P0 not ready", async () => {
  const baseline = await loadBaseline(baselinePath);
  const missingExecutiveApproval = structuredClone(baseline);
  missingExecutiveApproval.decision_gates.forEach((gate) => {
    if (gate.id !== "executive_authorization") {
      gate.status = "CONFIRMED";
      gate.evidence_refs = [`evidence/${gate.id}.md`];
    }
  });
  missingExecutiveApproval.technical_gates.forEach((gate) => {
    gate.status = "VERIFIED";
    gate.evidence_refs = [`evidence/${gate.id}.json`];
  });
  missingExecutiveApproval.final_decision = {
    status: "GO",
    decided_by: "authorized-human",
    decided_at: "2026-08-01T00:00:00Z",
    evidence_refs: ["evidence/p0-go.md"],
  };

  const result = evaluateP0(missingExecutiveApproval);
  assert.equal(result.status, "NOT_READY");
  assert.deepEqual(
    result.missingDecisions.map((gate) => gate.id),
    ["executive_authorization"],
  );
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

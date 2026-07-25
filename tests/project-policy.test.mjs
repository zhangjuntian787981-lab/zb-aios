import assert from "node:assert/strict";
import test from "node:test";
import {
  canAcceptStageGate,
  canAdvanceConnector,
  canStartPhase,
  isStageApprovalTask,
  isValidConnectorAdvanceEvidence,
  isValidStageApprovalEvidence,
  isProductOwner,
} from "../scripts/project-policy.mjs";

test("only the configured external Product Owner can change project state", () => {
  assert.equal(
    isProductOwner("owner@example.com", "OWNER@example.com"),
    true,
  );
  assert.equal(isProductOwner("viewer@example.com", "owner@example.com"), false);
  assert.equal(isProductOwner("", "owner@example.com"), false);
});

test("later phases cannot start before the prior Product Owner stage gate", () => {
  const statuses = {
    "v4-p0-09-stage-approval": "accepted",
    "v4-p1-03-stage-approval": "not_started",
    "v4-p2-02-stage-approval": "not_started",
  };

  assert.equal(canStartPhase("P1", statuses), true);
  assert.equal(canStartPhase("P2", statuses), false);
  assert.equal(canStartPhase("P3", statuses), false);
});

test("a stage gate cannot be accepted before its build tasks", () => {
  const incomplete = {
    "v4-p0-01-engineering-plan": "accepted",
    "v4-p0-02-beginner-plan": "accepted",
    "v4-p0-03-progress-center": "ready_for_acceptance",
    "v4-p0-04-product-owner": "accepted",
    "v4-p0-05-synthetic-boundary": "accepted",
    "v4-p0-06-tenant-boundary": "in_progress",
    "v4-p0-07-public-context": "accepted",
    "v4-p0-08-technical-gates": "in_progress",
  };

  assert.equal(
    canAcceptStageGate("v4-p0-09-stage-approval", incomplete),
    false,
  );
  assert.equal(
    canAcceptStageGate("v4-p0-09-stage-approval", {
      ...incomplete,
      "v4-p0-03-progress-center": "accepted",
      "v4-p0-06-tenant-boundary": "accepted",
      "v4-p0-08-technical-gates": "accepted",
    }),
    true,
  );

  assert.equal(
    canAcceptStageGate("v4-p2-02-stage-approval", {
      "v4-p2-01-product-hardening": "in_progress",
    }),
    false,
  );
  assert.equal(
    canAcceptStageGate("v4-p2-02-stage-approval", {
      "v4-p2-01-product-hardening": "accepted",
    }),
    true,
  );
  assert.equal(
    canAcceptStageGate("v4-p3-02-stage-approval", {
      "v4-p3-01-enterprise-onboarding": "accepted",
    }),
    true,
  );
});

test("Connector activation stays locked until Product Owner accepts P2", () => {
  assert.equal(
    canAdvanceConnector({ "v4-p2-02-stage-approval": "in_progress" }),
    false,
  );
  assert.equal(
    canAdvanceConnector({ "v4-p2-02-stage-approval": "accepted" }),
    true,
  );
});

test("stage approvals are explicit and require a sha256 artifact hash", () => {
  assert.equal(isStageApprovalTask("v4-p0-09-stage-approval"), true);
  assert.equal(isStageApprovalTask("v4-p2-01-product-hardening"), false);
  assert.equal(isStageApprovalTask("v4-p3-02-stage-approval"), true);
  assert.equal(
    isValidStageApprovalEvidence(
      "v4-p0-09-stage-approval",
      `P0 v4.0 sha256:${"a".repeat(64)}`,
    ),
    true,
  );
  assert.equal(
    isValidStageApprovalEvidence(
      "v4-p0-09-stage-approval",
      "P0 v4.0 approved",
    ),
    false,
  );
});

test("the first enterprise Connector activation requires authorization and a hash", () => {
  const hash = `sha256:${"b".repeat(64)}`;
  assert.equal(
    isValidConnectorAdvanceEvidence("C0", "C1", `${hash} snapshot-ready`),
    false,
  );
  assert.equal(
    isValidConnectorAdvanceEvidence(
      "C0",
      "C1",
      `enterprise-authorization:tenant-a-2026-01 ${hash}`,
    ),
    true,
  );
  assert.equal(isValidConnectorAdvanceEvidence("C1", "C2", hash), true);
  assert.equal(
    isValidConnectorAdvanceEvidence("C1", "C2", "read-only passed"),
    false,
  );
});

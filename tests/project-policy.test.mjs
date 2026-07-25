import assert from "node:assert/strict";
import test from "node:test";
import {
  isProductOwner,
  isValidConnectorAdvanceEvidence,
} from "../scripts/project-policy.mjs";

test("only the configured external Product Owner can change project state", () => {
  assert.equal(
    isProductOwner("owner@example.com", "OWNER@example.com"),
    true,
  );
  assert.equal(isProductOwner("viewer@example.com", "owner@example.com"), false);
  assert.equal(isProductOwner("", "owner@example.com"), false);
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
  assert.equal(isValidConnectorAdvanceEvidence("UNKNOWN", "C1", hash), false);
});

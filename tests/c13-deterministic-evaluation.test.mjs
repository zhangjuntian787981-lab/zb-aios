import assert from "node:assert/strict";
import test from "node:test";
import {
  verifyC13DeterministicEvaluation,
} from "../scripts/run-c13-evaluation.mjs";

test("C13 deterministic frozen gate verifies every checked-in release", async () => {
  const result = await verifyC13DeterministicEvaluation();
  assert.deepEqual(result, {
    status: "PASS",
    workPackage: "C13",
    phase: "P1_SYNTHETIC_ONLY",
    engine: "BUILTIN_F04_DETERMINISTIC_GATE",
    engineClaim: "FROZEN_GATE_EQUIVALENCE_ONLY",
    promptfooStatus: "NOT_VERIFIED",
    promptfooEvidenceAccepted: false,
    releasesChecked: 4,
    blockedReleases: 4,
    reportedCaseCount: 0,
    externalGovernanceEventArchiveStatus: "PENDING_G1_ARCHIVE",
  });
});

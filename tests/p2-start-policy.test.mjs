import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { P2_V2_CANDIDATE_START_POLICY } from "../lib/p2-start-authorization.mjs";

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

test("candidate start policy pins the exact recipe, Profile, Schema and validator bytes", async () => {
  assert.deepEqual(P2_V2_CANDIDATE_START_POLICY.executionBaselineRecipe, {
    path:
      "implementation/p2/acceptance/p2-execution-baseline-recipe.profile-v2.v1.json",
    schemaVersion: "p2-execution-baseline-recipe.v1",
    sha256:
      "sha256:fa35085d2d18131920d932b3321fd77bc370c1d44cfb927feb91c34604c0c89e",
  });
  assert.deepEqual(P2_V2_CANDIDATE_START_POLICY.profile, {
    path: "implementation/p2/acceptance/p2-acceptance-profile.v2.json",
    schemaVersion: "p2-acceptance-profile.v2",
    sha256:
      "sha256:ed6836e5e212a95b66dd386e8bfbe1cf6aa5f37c1b281cfb0514e9aa9f7213f5",
  });
  assert.equal(
    P2_V2_CANDIDATE_START_POLICY.validator.sha256,
    "sha256:ff8da36988ace70213e58368b8b3894677e732e0c0e262f87ba8824fac6347a7",
  );
  for (const subject of [
    P2_V2_CANDIDATE_START_POLICY.executionBaselineRecipe,
    P2_V2_CANDIDATE_START_POLICY.profile,
    P2_V2_CANDIDATE_START_POLICY.receiptSchema,
    P2_V2_CANDIDATE_START_POLICY.validator,
  ]) {
    const bytes = await readFile(new URL(`../${subject.path}`, import.meta.url));
    assert.equal(sha256(bytes), subject.sha256, subject.path);
  }
});

test("candidate policy protects only O02 and O03 and is not mutable", () => {
  assert.deepEqual(P2_V2_CANDIDATE_START_POLICY.protectedWorkPackages, [
    "O02",
    "O03",
  ]);
  assert.equal(Object.isFrozen(P2_V2_CANDIDATE_START_POLICY), true);
  assert.equal(
    Object.isFrozen(P2_V2_CANDIDATE_START_POLICY.protectedWorkPackages),
    true,
  );
});

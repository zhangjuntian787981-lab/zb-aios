import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { P2_V2_CANDIDATE_START_POLICY } from "../lib/p2-start-authorization.mjs";

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

test("candidate start policy pins the exact recipe, Profile, Schema and validator bytes", async () => {
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

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const historicalEvidenceUrl = new URL(
  "../implementation/p1/c03/c03-implementation-evidence.v1.json",
  import.meta.url,
);

test("C03 historical implementation evidence remains intact", async () => {
  const historicalContent = await readFile(historicalEvidenceUrl);
  const historicalSha256 = `sha256:${createHash("sha256")
    .update(historicalContent)
    .digest("hex")}`;
  assert.equal(
    historicalSha256,
    "sha256:879561dc2dc2b9e4ce6d6ac69c306ae22bec4eb94a8891303906f2791baab6f5",
  );
});

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const rootUrl = new URL("../", import.meta.url);
const evidenceUrl = new URL(
  "../implementation/p1/c03/c03-implementation-evidence.v1.json",
  import.meta.url,
);

test("C03 implementation evidence is intact and remains explicitly unverified", async () => {
  const evidence = JSON.parse(await readFile(evidenceUrl, "utf8"));

  assert.equal(evidence.work_package_id, "C03");
  assert.equal(evidence.implementation_status, "IMPLEMENTED");
  assert.equal(evidence.verification_status, "NOT_VERIFIED");
  assert.equal(evidence.verification_results.real_postgresql_runtime, "NOT_RUN");
  assert.ok(
    evidence.limitations.some((item) => item.includes("不得标记为 VERIFIED")),
  );

  for (const artifact of evidence.artifacts) {
    const content = await readFile(new URL(artifact.path, rootUrl));
    const actual = `sha256:${createHash("sha256")
      .update(content)
      .digest("hex")}`;
    assert.equal(actual, artifact.sha256, artifact.path);
  }
});

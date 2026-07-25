import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

function sha256(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

async function read(relativePath) {
  return readFile(new URL(relativePath, root));
}

async function readJson(relativePath) {
  return JSON.parse(await read(relativePath));
}

test("F02 and F03 verified evidence and F04 pending-human evidence are intact", async () => {
  const manifest = await readJson(
    "implementation/governance/work-package-manifest.v1.json",
  );
  const expectations = {
    F02: {
      implementation: "IMPLEMENTED",
      verification: "VERIFIED",
    },
    F03: {
      implementation: "IMPLEMENTED",
      verification: "VERIFIED",
    },
    F04: {
      implementation: "IMPLEMENTED",
      verification: "NOT_VERIFIED",
    },
  };

  for (const [workPackageId, expected] of Object.entries(expectations)) {
    const item = manifest.work_packages.find(({ id }) => id === workPackageId);
    assert.ok(item, workPackageId);
    assert.equal(item.implementation_status, expected.implementation);
    assert.equal(item.verification_status, expected.verification);

    const evidencePath = `implementation/p0/evidence/${workPackageId.toLowerCase()}-evidence.v1.json`;
    const evidenceContent = await read(evidencePath);
    const evidence = JSON.parse(evidenceContent);
    assert.equal(evidence.work_package_id, workPackageId);
    assert.ok(item.artifact_refs.includes(evidencePath));
    assert.ok(item.evidence_hashes.includes(sha256(evidenceContent)));

    for (const artifact of evidence.artifacts) {
      assert.equal(
        sha256(await read(artifact.path)),
        artifact.sha256,
        `${workPackageId}: ${artifact.path}`,
      );
    }
  }
});

test("the human baseline candidate is pending, complete, and bound to the API hash", async () => {
  const candidatePath =
    "implementation/p0/f04/human-baseline-candidate.v1.json";
  const candidateContent = await read(candidatePath);
  const candidate = JSON.parse(candidateContent);
  const route = await read("app/api/progress/route.ts");
  const digest = sha256(candidateContent);

  assert.equal(candidate.status, "PENDING_HUMAN_VALIDATION");
  assert.equal(candidate.source, "AI_RECOMMENDATION_REQUIRES_HUMAN_DECISION");
  assert.equal(candidate.reviewer, null);
  assert.equal(candidate.enterprise_data_used, false);
  assert.equal(candidate.items.length, 10);
  assert.equal(new Set(candidate.items.map(({ case_id }) => case_id)).size, 10);
  assert.match(route.toString(), new RegExp(digest));
});

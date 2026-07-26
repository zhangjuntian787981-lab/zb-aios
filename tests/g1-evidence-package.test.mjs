import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = new URL("../", import.meta.url);
const rootPath = fileURLToPath(root);
const indexPath =
  "implementation/gates/g1/p1-module-evidence-index.v1.json";
const approvedG0SubmissionSha256 =
  "sha256:77d8707a602a83729b557c028bd6cf87c5a0e5d921145b9dc3a5a1e79bf32a07";
const expectedModules = Array.from({ length: 19 }, (_, index) => {
  const workPackageId = `C${String(index + 1).padStart(2, "0")}`;
  const version = {
    C03: "v2",
    C06: "v3",
    C15: "v2",
    C19: "v3",
  }[workPackageId] ?? "v1";
  return {
    workPackageId,
    evidencePath:
      `implementation/p1/${workPackageId.toLowerCase()}/` +
      `${workPackageId.toLowerCase()}-verification-evidence.${version}.json`,
  };
});

async function read(path) {
  return readFile(new URL(path, root));
}

function sha256(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

function verificationScope(evidence) {
  if (evidence.verification_scope) return evidence.verification_scope;
  if (evidence.runtime_boundary?.data_classification === "SYNTHETIC_ONLY") {
    return "P1_SYNTHETIC_ONLY";
  }
  return undefined;
}

function productionVerificationStatus(evidence) {
  if (evidence.production_verification_status) {
    return evidence.production_verification_status;
  }
  if (evidence.runtime_boundary?.production_verification_status) {
    return evidence.runtime_boundary.production_verification_status;
  }
  if (
    evidence.work_package_id === "C03" &&
    evidence.limitations.some((item) =>
      item.includes("C03 VERIFIED 不证明数据库高可用")
    )
  ) {
    return "NOT_VERIFIED";
  }
  return undefined;
}

function enterpriseConnectors(evidence) {
  if (evidence.enterprise_connectors) return evidence.enterprise_connectors;
  if (evidence.runtime_boundary?.enterprise_connectors) {
    return evidence.runtime_boundary.enterprise_connectors;
  }
  if (
    evidence.work_package_id === "C03" &&
    evidence.verified_assertions.some((item) =>
      item.includes("企业 Connector 保持 C0")
    )
  ) {
    return "C0_DISABLED";
  }
  return undefined;
}

test("G1 indexes exactly the frozen C01-C19 P1 module evidence", async () => {
  const index = JSON.parse(await read(indexPath));

  assert.deepEqual(Object.keys(index), [
    "schemaVersion",
    "recordType",
    "gateId",
    "phase",
    "approvedG0SubmissionSha256",
    "modules",
  ]);
  assert.equal(index.schemaVersion, "g1-p1-module-evidence-index.v1");
  assert.equal(index.recordType, "MODULE_EVIDENCE_INDEX");
  assert.equal(index.gateId, "G1");
  assert.equal(index.phase, "P1");
  assert.equal(
    index.approvedG0SubmissionSha256,
    approvedG0SubmissionSha256,
  );
  assert.equal(index.modules.length, 19);
  assert.deepEqual(
    index.modules.map(({ workPackageId, evidencePath }) => ({
      workPackageId,
      evidencePath,
    })),
    expectedModules,
  );
  assert.equal(
    new Set(index.modules.map(({ workPackageId }) => workPackageId)).size,
    19,
  );

  for (const entry of index.modules) {
    assert.deepEqual(Object.keys(entry), [
      "workPackageId",
      "evidencePath",
      "evidenceSha256",
      "verifiedSourceCommit",
    ]);
    const evidenceContent = await read(entry.evidencePath);
    const evidence = JSON.parse(evidenceContent);

    assert.equal(evidence.work_package_id, entry.workPackageId);
    assert.equal(evidence.evidence_ref, entry.evidencePath);
    assert.equal(evidence.verification_status, "VERIFIED");
    assert.equal(verificationScope(evidence), "P1_SYNTHETIC_ONLY");
    assert.equal(productionVerificationStatus(evidence), "NOT_VERIFIED");
    assert.equal(enterpriseConnectors(evidence), "C0_DISABLED");
    if (evidence.approved_g0_submission_sha256 !== undefined) {
      assert.equal(
        evidence.approved_g0_submission_sha256,
        approvedG0SubmissionSha256,
      );
    } else {
      assert.equal(entry.workPackageId, "C03");
    }
    assert.equal(evidence.verified_source_commit, entry.verifiedSourceCommit);
    assert.match(entry.verifiedSourceCommit, /^[a-f0-9]{40}$/);
    assert.equal(sha256(evidenceContent), entry.evidenceSha256);

    assert.doesNotThrow(() => {
      execFileSync(
        "git",
        ["merge-base", "--is-ancestor", entry.verifiedSourceCommit, "HEAD"],
        { cwd: rootPath, stdio: "pipe" },
      );
    }, `${entry.workPackageId} verified source commit must be a HEAD ancestor`);
  }
});

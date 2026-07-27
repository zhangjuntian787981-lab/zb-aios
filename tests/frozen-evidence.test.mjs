import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createFrozenEvidenceVerifier } from "../lib/frozen-evidence.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const p0IndexPath = new URL(
  "../implementation/governance/p0-frozen-evidence-index.v1.json",
  import.meta.url,
);
const p1IndexPath = new URL(
  "../implementation/gates/g1/p1-module-evidence-index.v1.json",
  import.meta.url,
);
const p1BindingsPath = new URL(
  "../implementation/governance/p1-d1-evidence-bindings.revision-64.v1.json",
  import.meta.url,
);
const p1IndexGitPath =
  "implementation/gates/g1/p1-module-evidence-index.v1.json";
const p1IndexFrozenCommit = "9aab0cb19d14848dfd837729dd7df07828043258";

const record = {
  workPackageId: "F01",
  evidenceRefs: ["implementation/p0/evidence/f01-evidence.v2.json"],
  evidenceHashes: [
    "sha256:11baffbcb40eebd6496b5739798974aecb0a01cb214abe7a3c884d6e6f531f13",
  ],
};

test("the frozen evidence verifier accepts only an exact catalog record", async () => {
  const verify = createFrozenEvidenceVerifier({
    schemaVersion: "frozen-evidence-catalog.v1",
    records: [record],
  });

  assert.equal(await verify(record), true);
  assert.equal(
    await verify({
      ...record,
      evidenceRefs: [...record.evidenceRefs, "unreferenced.json"],
    }),
    false,
  );
  assert.equal(
    await verify({
      ...record,
      evidenceHashes: [`sha256:${"f".repeat(64)}`],
    }),
    false,
  );
  assert.equal(await verify({ ...record, workPackageId: "F02" }), false);
});

test("the P0 evidence index points to immutable Git objects for its parent package", async () => {
  const catalog = JSON.parse(await readFile(p0IndexPath, "utf8"));
  const verify = createFrozenEvidenceVerifier(catalog);

  for (const entry of catalog.records) {
    execFileSync(
      "git",
      ["merge-base", "--is-ancestor", entry.frozenCommit, "HEAD"],
      { cwd: repositoryRoot },
    );
    for (const reference of entry.evidenceRefs) {
      execFileSync("git", ["cat-file", "-e", `${entry.frozenCommit}:${reference}`], {
        cwd: repositoryRoot,
      });
    }
    for (const object of entry.hashedObjects) {
      const contents = execFileSync(
        "git",
        ["show", `${entry.frozenCommit}:${object.path}`],
        { cwd: repositoryRoot },
      );
      const actualHash = `sha256:${createHash("sha256")
        .update(contents)
        .digest("hex")}`;
      assert.equal(actualHash, object.sha256, object.path);
    }
    const evidence = JSON.parse(
      execFileSync(
        "git",
        ["show", `${entry.frozenCommit}:${entry.primaryEvidenceRef}`],
        { cwd: repositoryRoot, encoding: "utf8" },
      ),
    );
    assert.equal(evidence.work_package_id, entry.workPackageId);
    assert.equal(evidence.evidence_ref, entry.primaryEvidenceRef);
    assert.equal(await verify(entry), true);
  }

  const f04 = catalog.records.find(
    ({ workPackageId }) => workPackageId === "F04",
  );
  assert.equal(
    await verify({
      ...f04,
      evidenceHashes: [
        "sha256:851851fcec6d961efaf17f6a0ced172c12dad2dced6746c9c9b805a205c95f62",
        "sha256:1ac738d40ed6fb0bdaadb876c92b4f3cbde0d722142093bb786447365c9c5de0",
      ],
    }),
    false,
  );
});

test("the P1 module index resolves to exact runtime records backed by frozen Git objects", async () => {
  const indexText = await readFile(p1IndexPath, "utf8");
  const index = JSON.parse(indexText);
  const bindings = JSON.parse(await readFile(p1BindingsPath, "utf8"));
  const verify = createFrozenEvidenceVerifier(bindings);

  execFileSync(
    "git",
    ["merge-base", "--is-ancestor", p1IndexFrozenCommit, "HEAD"],
    { cwd: repositoryRoot },
  );
  const frozenIndex = execFileSync(
    "git",
    ["show", `${p1IndexFrozenCommit}:${p1IndexGitPath}`],
    { cwd: repositoryRoot },
  );
  assert.equal(
    `sha256:${createHash("sha256").update(indexText).digest("hex")}`,
    bindings.frozenEvidenceIndex.sha256,
  );
  assert.equal(
    createHash("sha256").update(indexText).digest("hex"),
    createHash("sha256").update(frozenIndex).digest("hex"),
  );
  assert.equal(bindings.source.d1Revision, 64);
  assert.equal(bindings.source.readEndpoint, "GET /api/progress");
  assert.equal(bindings.records.length, 19);

  for (const entry of index.modules) {
    const binding = bindings.records.find(
      ({ workPackageId }) => workPackageId === entry.workPackageId,
    );
    assert.ok(binding, entry.workPackageId);
    assert.equal(binding.primaryEvidenceRef, entry.evidencePath);
    assert.equal(binding.verifiedSourceCommit, entry.verifiedSourceCommit);
    assert.deepEqual(binding.evidenceHashes, [entry.evidenceSha256]);
    execFileSync(
      "git",
      ["merge-base", "--is-ancestor", entry.verifiedSourceCommit, "HEAD"],
      { cwd: repositoryRoot },
    );
    const evidenceText = execFileSync(
      "git",
      ["show", `${p1IndexFrozenCommit}:${entry.evidencePath}`],
      { cwd: repositoryRoot },
    );
    assert.equal(
      `sha256:${createHash("sha256").update(evidenceText).digest("hex")}`,
      entry.evidenceSha256,
    );
    const evidence = JSON.parse(evidenceText);
    assert.equal(evidence.work_package_id, entry.workPackageId);
    assert.equal(evidence.evidence_ref, entry.evidencePath);
    assert.equal(await verify(binding), true);
    assert.equal(
      await verify({
        workPackageId: entry.workPackageId,
        evidenceRefs: [entry.evidencePath],
        evidenceHashes: [entry.evidenceSha256],
      }),
      false,
    );
  }

  const c04 = bindings.records.find(
    ({ workPackageId }) => workPackageId === "C04",
  );
  assert.deepEqual(c04.evidenceRefs, [
    "implementation/p1/c04/c04-verification-evidence.v1.json sha256:554df39362987342eaab88b5146b04a70bc3db8b566a81c6af5b1866816063de source_commit:a24cb1a02c2fee0ac46c3558c42f5e7143957ac8 evidence_commit:93772e891ab032ac6ea88bd6dec5847a2c748420",
  ]);
});

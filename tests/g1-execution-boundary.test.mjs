import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = new URL("../", import.meta.url);
const repositoryRoot = fileURLToPath(root);
const evidencePath =
  "implementation/gates/g1/g1-execution-boundary-evidence.v5.json";
const sourceRoots = ["app", "lib"];
const sourceExtensions = new Set([
  ".js",
  ".jsx",
  ".mjs",
  ".ts",
  ".tsx",
]);
const prohibitedPatterns = [
  /\b(?:node:)?child_process\b/u,
  /\bnode:vm\b/u,
  /\bworker_threads\b/u,
  /\beval\s*\(/u,
  /\bnew\s+Function\s*\(/u,
  /\b(?:execFile|execFileSync|execSync|spawn|fork)\s*\(/u,
];

async function json(path) {
  return JSON.parse(await readFile(new URL(path, root), "utf8"));
}

function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

function deployableSourceManifest(commit) {
  const paths = execFileSync(
    "git",
    ["ls-tree", "-r", "--name-only", commit, "--", ...sourceRoots],
    { cwd: repositoryRoot, encoding: "utf8" },
  )
    .trim()
    .split("\n")
    .filter((path) => {
      const extension = path.slice(path.lastIndexOf("."));
      return sourceExtensions.has(extension);
    })
    .sort();
  const records = paths.map((path) => {
    const content = execFileSync(
      "git",
      ["show", `${commit}:${path}`],
      { cwd: repositoryRoot },
    );
    return { path, content, fileSha256: sha256(content) };
  });
  const manifest = records
    .map(({ path, fileSha256 }) => `${path}\0${fileSha256}\n`)
    .join("");
  return {
    records,
    manifestSha256: `sha256:${sha256(manifest)}`,
  };
}

test("G1 keeps arbitrary code execution absent from the deployable P1 runtime", async () => {
  const evidence = await json(evidencePath);
  const manifest = deployableSourceManifest(evidence.sourceCommit);

  assert.deepEqual(Object.keys(evidence), [
    "schemaVersion",
    "recordType",
    "gateId",
    "phase",
    "sourceCommit",
    "scannedSourceRoots",
    "sourceFileCount",
    "sourceManifestSha256",
    "prohibitedPrimitiveMatches",
    "skillExecution",
    "connectorBoundary",
    "governanceBoundary",
  ]);
  assert.equal(
    evidence.schemaVersion,
    "g1-execution-boundary-evidence.v5",
  );
  assert.equal(
    evidence.recordType,
    "SUPPLEMENTAL_EXECUTION_BOUNDARY_EVIDENCE",
  );
  assert.equal(evidence.gateId, "G1");
  assert.equal(evidence.phase, "P1_SYNTHETIC_ONLY");
  assert.deepEqual(evidence.scannedSourceRoots, sourceRoots);
  assert.equal(evidence.sourceFileCount, manifest.records.length);
  assert.equal(evidence.sourceManifestSha256, manifest.manifestSha256);

  const matches = [];
  for (const { path, content } of manifest.records) {
    const source = content.toString("utf8");
    for (const pattern of prohibitedPatterns) {
      if (pattern.test(source)) {
        matches.push({ path, pattern: pattern.source });
      }
    }
  }
  assert.deepEqual(matches, []);
  assert.equal(evidence.prohibitedPrimitiveMatches, 0);
  assert.deepEqual(evidence.governanceBoundary, {
    supplementOnly: true,
    d1LedgerChanged: false,
    workPackageStatusChanged: false,
    gateSubmissionChanged: false,
    gateDecisionChanged: false,
    manifestChanged: false,
  });
});

test("G1 freezes Skills as instructions and Connectors as disabled read-only mocks", async () => {
  const evidence = await json(evidencePath);
  const [skillCatalog, toolCatalog, connectorCatalog, connectorFixtures] =
    [
      "implementation/p1/c13/synthetic-skill-catalog.v1.json",
      "implementation/p1/c16/operation-catalog.v1.json",
      "implementation/p1/c17/connector-templates.v1.json",
      "implementation/p1/c17/synthetic-connector-fixtures.v1.json",
    ].map((path) =>
      JSON.parse(
        execFileSync(
          "git",
          ["show", `${evidence.sourceCommit}:${path}`],
          { cwd: repositoryRoot, encoding: "utf8" },
        ),
      )
    );

  assert.equal(skillCatalog.scriptExecution, "DISABLED");
  assert.equal(skillCatalog.allowedToolsGrantAuthorization, false);
  assert.equal(
    skillCatalog.tenants
      .flatMap(({ releases }) => releases)
      .every(({ manifest }) =>
        manifest.executionMode === "INSTRUCTIONS_ONLY"
      ),
    true,
  );
  assert.deepEqual(evidence.skillExecution, {
    scriptExecution: "DISABLED",
    executionMode: "INSTRUCTIONS_ONLY",
    sandboxRuntime: "ABSENT_UNTIL_P2",
  });

  for (const catalog of [
    toolCatalog,
    connectorCatalog,
    connectorFixtures,
  ]) {
    assert.equal(catalog.networkAccess, "DISABLED");
  }
  assert.equal(connectorCatalog.connectorStage, "C0_DISABLED");
  assert.equal(connectorFixtures.connectorStage, "C0_DISABLED");
  assert.equal(
    toolCatalog.operations.every(({ mode }) => mode === "READ_ONLY"),
    true,
  );
  assert.equal(
    connectorCatalog.templates.every(({ mode }) => mode === "READ_ONLY"),
    true,
  );
  assert.deepEqual(evidence.connectorBoundary, {
    connectorStage: "C0_DISABLED",
    networkAccess: "DISABLED",
    mode: "READ_ONLY",
    adapter: "REGISTERED_SYNTHETIC_MOCK_ONLY",
    externalEffectCount: 0,
  });
});

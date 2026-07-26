import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { relative } from "node:path";
import test from "node:test";

const root = new URL("../", import.meta.url);
const evidencePath =
  "implementation/gates/g1/g1-execution-boundary-evidence.v1.json";
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

async function sourceFiles(directoryUrl) {
  const entries = await readdir(directoryUrl, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const url = new URL(`${entry.name}${entry.isDirectory() ? "/" : ""}`, directoryUrl);
    if (entry.isDirectory()) {
      files.push(...await sourceFiles(url));
      continue;
    }
    const extension = entry.name.slice(entry.name.lastIndexOf("."));
    if (sourceExtensions.has(extension)) files.push(url);
  }
  return files;
}

function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

async function deployableSourceManifest() {
  const files = (
    await Promise.all(
      sourceRoots.map((path) => sourceFiles(new URL(`${path}/`, root))),
    )
  )
    .flat()
    .sort((left, right) => left.pathname.localeCompare(right.pathname));
  const records = [];
  for (const url of files) {
    const path = relative(new URL(".", root).pathname, url.pathname);
    const content = await readFile(url);
    records.push({ path, content, fileSha256: sha256(content) });
  }
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
  const manifest = await deployableSourceManifest();

  assert.deepEqual(Object.keys(evidence), [
    "schemaVersion",
    "recordType",
    "gateId",
    "phase",
    "scannedSourceRoots",
    "sourceFileCount",
    "sourceManifestSha256",
    "prohibitedPrimitiveMatches",
    "skillExecution",
    "connectorBoundary",
  ]);
  assert.equal(
    evidence.schemaVersion,
    "g1-execution-boundary-evidence.v1",
  );
  assert.equal(evidence.recordType, "EXECUTION_BOUNDARY_EVIDENCE");
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
});

test("G1 freezes Skills as instructions and Connectors as disabled read-only mocks", async () => {
  const evidence = await json(evidencePath);
  const [skillCatalog, toolCatalog, connectorCatalog, connectorFixtures] =
    await Promise.all([
      json("implementation/p1/c13/synthetic-skill-catalog.v1.json"),
      json("implementation/p1/c16/operation-catalog.v1.json"),
      json("implementation/p1/c17/connector-templates.v1.json"),
      json("implementation/p1/c17/synthetic-connector-fixtures.v1.json"),
    ]);

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

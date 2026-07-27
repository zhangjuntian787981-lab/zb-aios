import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  createMemoryPersonalMemoryStore,
} from "../lib/c09-personal-memory.mjs";

const root = new URL("../", import.meta.url);
const repositoryRoot = fileURLToPath(root);

async function text(path) {
  return readFile(new URL(path, root), "utf8");
}

async function json(path) {
  return JSON.parse(await text(path));
}

const catalog = await json(
  "implementation/p1/c09/personal-memory-data-surface-catalog.v1.json",
);
const evidence = await json(
  "implementation/p1/c09/c09-ac06-supplemental-evidence.v1.json",
);
const schema = await text(
  "implementation/p1/c09/postgresql/0015_personal_memory.sql",
);
const api = await text(
  "implementation/p1/c09/personal-memory.openapi.v1.json",
);
const memoryModule = await text("lib/c09-personal-memory.mjs");
const postgresStore = await text(
  "lib/c09-personal-memory-postgres-store.mjs",
);

test("C09-AC06 catalog classifies every content or reference surface without N/A", () => {
  assert.equal(catalog.acceptanceId, "C09-AC06");
  assert.equal(catalog.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(catalog.evidenceStatus, "GIT_FROZEN");
  assert.equal(
    catalog.surfaces.some(
      (surface) =>
        surface.implementationStatus === "N/A" ||
        surface.implementationStatus === "NOT_APPLICABLE",
    ),
    false,
  );
  assert.deepEqual(
    catalog.surfaces.map((surface) => [
      surface.surfaceId,
      surface.implementationStatus,
    ]),
    [
      ["PRIMARY_MEMORY_RECORD", "IMPLEMENTED"],
      ["RELATIONAL_RECALL_INDEX", "IMPLEMENTED"],
      ["CHECKPOINT_REFERENCE", "IMPLEMENTED"],
      ["HASH_ONLY_MEMORY_EVENT", "IMPLEMENTED"],
      ["COMMAND_RECEIPT", "IMPLEMENTED"],
      ["IN_MEMORY_RECOVERY_SNAPSHOT", "IMPLEMENTED"],
      ["POSTGRES_FRESH_RESTORE", "IMPLEMENTED"],
      ["VECTOR_EMBEDDING_INDEX", "NOT_IMPLEMENTED_IN_P1"],
      ["PERSONAL_MEMORY_CACHE", "NOT_IMPLEMENTED_IN_P1"],
    ],
  );
  assert.deepEqual(catalog.probe, {
    tenantId: "stn_018f0000-0000-7000-8000-000000000010",
    principalId: "prn_018f0000-0000-7000-8000-000000000001",
    memoryId: "mem_018f0000-0000-7000-8000-000000001001",
    checkpointId: "ckp_018f0000-0000-7000-8000-000000001004",
    contentCanary:
      "Synthetic preference: concise weekly summaries.",
  });
});

test("C09 schema and Store expose no hidden vector or cache data plane", () => {
  const tables = [
    ...schema.matchAll(
      /CREATE TABLE aios_personal_memory\.([a-z_]+) \(/g,
    ),
  ].map((match) => match[1]);
  assert.deepEqual(tables, [
    "personal_scope_signing_secret",
    "personal_profile",
    "personal_memory",
    "conversation_checkpoint",
    "memory_event",
    "command_receipt",
  ]);
  assert.deepEqual(
    Object.keys(createMemoryPersonalMemoryStore()),
    [
      "apply",
      "readCommandReceipt",
      "listRecallMetadata",
      "readRecallContent",
      "readProfile",
      "readConsentTarget",
      "readCheckpoint",
      "materializeExpiry",
      "inspectForTest",
      "exportRecoverySnapshot",
    ],
  );
  for (const source of [schema, api, memoryModule, postgresStore]) {
    assert.doesNotMatch(source, /\b(?:embedding|vector|cache)\b/i);
  }
  assert.match(
    schema,
    /CREATE INDEX personal_memory_recall_idx[\s\S]*tenant_id,[\s\S]*principal_id,[\s\S]*state,[\s\S]*expires_at/,
  );
});

test("support tables are inventoried but cannot hold personal-memory content", () => {
  assert.deepEqual(catalog.supportSurfaces, [
    {
      surfaceId: "PERSONAL_PROFILE",
      implementationStatus: "IMPLEMENTED_SUPPORT_ONLY",
      reason: "Owner and pause state only; no Memory ID or content column.",
    },
    {
      surfaceId: "PRINCIPAL_SCOPE_SIGNING_SECRET",
      implementationStatus: "IMPLEMENTED_SUPPORT_ONLY",
      reason: "Principal-scope signing material only; no Memory ID or content column.",
    },
  ]);
  const profileBlock =
    /CREATE TABLE aios_personal_memory\.personal_profile \(([\s\S]*?)\n\);/.exec(
      schema,
    )[1];
  const secretBlock =
    /CREATE TABLE aios_personal_memory\.personal_scope_signing_secret \(([\s\S]*?)\n\);/.exec(
      schema,
    )[1];
  assert.doesNotMatch(profileBlock, /\b(?:memory_id|content)\b/);
  assert.doesNotMatch(secretBlock, /\b(?:memory_id|content)\b/);
});

test("P1-B09 evidence resolves to exact Git-frozen data-surface artifacts", () => {
  assert.equal(evidence.workPackageId, "C09");
  assert.equal(evidence.acceptanceId, "C09-AC06");
  assert.equal(evidence.supplementId, "P1-B09");
  assert.equal(evidence.evidenceStatus, "PASS_GIT_FROZEN");
  assert.equal(evidence.freezeStatus, "GIT_FROZEN");
  assert.deepEqual(evidence.probe, catalog.probe);
  assert.deepEqual(evidence.surfaceResults, {
    catalogedSurfaces: 9,
    implementedSurfaces: 7,
    notImplementedInP1Surfaces: 2,
    supportOnlySurfaces: 2,
    sourcePostgresTombstones: 1,
    sourcePostgresLiveOrPlaintextHits: 0,
    sourcePostgresCheckpointReferenceHits: 0,
    sourcePostgresEventPlaintextHits: 0,
    sourcePostgresReceiptPlaintextHits: 0,
    freshRestoreTombstones: 1,
    freshRestoreLiveOrPlaintextHits: 0,
    freshRestoreCheckpointReferenceHits: 0,
    freshRestoreRecallHits: 0,
    vectorOrCacheRuntimeObjects: 0,
  });
  assert.deepEqual(evidence.governanceBoundary, {
    d1LedgerChanged: false,
    workPackageStatusChanged: false,
    gateSubmissionChanged: false,
    gateDecisionChanged: false,
    manifestChanged: false,
    historicalEvidenceChanged: false,
  });
  assert.equal(evidence.dataScope, "SYNTHETIC_ONLY");
  assert.equal(evidence.enterpriseData, "NOT_PRESENT");
  execFileSync(
    "git",
    ["merge-base", "--is-ancestor", evidence.sourceCommit, "HEAD"],
    { cwd: repositoryRoot },
  );
  for (const artifact of evidence.artifacts) {
    const bytes = execFileSync(
      "git",
      ["show", `${evidence.sourceCommit}:${artifact.path}`],
      { cwd: repositoryRoot },
    );
    assert.equal(
      `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
      artifact.sha256,
      artifact.path,
    );
  }
});

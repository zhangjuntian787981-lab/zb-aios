import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import catalog from "../implementation/governance/p0-frozen-evidence-index.v1.json" with { type: "json" };
import manifest from "../implementation/governance/work-package-manifest.v1.json" with { type: "json" };
import schema from "../implementation/governance/schemas/p0-b11-evidence-projection.v1.schema.json" with { type: "json" };
import {
  F04_HISTORICAL_AUTHORITY_BINDING,
  assertUniqueF04HistoricalAuthority,
} from "../lib/f04-historical-authority.mjs";
import {
  createP0B11EvidenceGet,
  projectP0B11Evidence,
} from "../lib/p0-b11-evidence-projection.mjs";
import { sha256ProjectValue } from "../lib/project-control.mjs";

const PRODUCT_OWNER = "product-owner@example.test";
const ROUTE_ORIGIN = "https://example.test";
const FIXED_NOW = "2026-07-30T03:00:00.000Z";
const CURRENT_SUBMISSION_ID =
  "be08e1d3-1e9c-43a0-aa2e-f93a800b5105";
const CURRENT_PACKAGE_HASH =
  "sha256:d4e449a305a6f496e24fb777d1d883d8c02f0d7e3165d00fc90561c1d14421b0";
const ACTOR_ID_SHA256 =
  "sha256:759fdbe3760a3c181d1ff1f00017a6e3fea193cfe2cfce67f1fca37f2f463830";
const IDEMPOTENCY_KEY_SHA256 =
  "sha256:9b061edf27d2851fec4505ce8ebbd9d7f26e492ecb6301d4fcac9d7dd3f15e3d";
const REMEDIATION_ROOT_KEY = "g0-remediation-20260729-001";
const CURRENT_DECISION_KEY =
  "g0-decision-be08e1d3-approve-20260729-001";
const ROUTE_URL = new URL(
  "../app/api/governance/p0-b11-evidence/route.ts",
  import.meta.url,
);
const REMEDIATION_URL = new URL(
  "../lib/g0-remediation.mjs",
  import.meta.url,
);
const ADJACENT_ROUTES = [
  new URL("../app/api/governance/p2-readiness/route.ts", import.meta.url),
  new URL("../app/api/governance/g0-decision/route.ts", import.meta.url),
  new URL("../app/api/governance/g0-stale-audit/route.ts", import.meta.url),
];

const ajv = new Ajv2020({ strict: true, allErrors: true });
const validateSchema = ajv.compile(schema);

function clone(value) {
  return structuredClone(value);
}

function createdAt(revision) {
  return new Date(
    Date.parse("2026-07-28T18:00:00.000Z") + revision * 1_000,
  ).toISOString();
}

function currentScope() {
  return catalog.records.map((record) => ({
    work_package_id: record.workPackageId,
    applicability: manifest.work_packages.find(
      ({ id }) => id === record.workPackageId,
    ).applicability,
    implementation_status: "IMPLEMENTED",
    verification_status: "VERIFIED",
    evidence_refs: [...record.evidenceRefs],
    evidence_hashes: [...record.evidenceHashes],
  }));
}

function historicalScope() {
  return currentScope().map((item) => ({
    ...item,
    evidence_hashes:
      item.work_package_id === "F04"
        ? [
            F04_HISTORICAL_AUTHORITY_BINDING.engineeringEvidenceSha256,
            F04_HISTORICAL_AUTHORITY_BINDING.humanEvidenceSha256,
          ]
        : item.evidence_hashes,
  }));
}

async function bindCommand(event, command) {
  event.commandHash = await sha256ProjectValue({
    actorId: event.actorId,
    command,
  });
  return event;
}

async function bindF04Command(event) {
  return bindCommand(event, {
      kind: "RECORD_WORK_PACKAGE",
      workPackageId: "F04",
      implementationStatus: event.payload.implementationStatus,
      verificationStatus: event.payload.verificationStatus,
      evidenceRefs: event.payload.evidenceRefs,
      evidenceHashes: event.payload.evidenceHashes,
      note: event.payload.note ?? "",
      expectedRevision: event.revision - 1,
      idempotencyKey: event.idempotencyKey,
  });
}

async function authoritativeF04Event({
  revision = 1,
  id = "historical-f04-authoritative-human-validation",
  idempotencyKey = "historical-f04-authority",
} = {}) {
  return bindF04Command({
    id,
    revision,
    type: "WORK_PACKAGE_RECORDED",
    actorId: "external_product_owner",
    idempotencyKey,
    commandHash: null,
    createdAt: createdAt(revision),
    payload: {
      workPackageId: "F04",
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
      evidenceRefs: [...F04_HISTORICAL_AUTHORITY_BINDING.evidenceRefs],
      evidenceHashes: [
        F04_HISTORICAL_AUTHORITY_BINDING.engineeringEvidenceSha256,
        F04_HISTORICAL_AUTHORITY_BINDING.humanEvidenceSha256,
      ],
      note:
        `外部产品所有者确认十项 F04 人工基线：${F04_HISTORICAL_AUTHORITY_BINDING.humanEvidenceSha256}`,
    },
  });
}

async function validJournalState() {
  const oldScope = historicalScope();
  const oldEvidenceRefs = oldScope.flatMap(
    ({ evidence_refs: evidenceRefs }) => evidenceRefs,
  );
  const oldSubmissionKey = "historical-g0-submission-key";
  const oldDecisionKey = "historical-g0-decision-key";
  const oldDecisionEvidence = [
    `product-owner-decision:${F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId}:${F04_HISTORICAL_AUTHORITY_BINDING.g0PackageHash}`,
  ];
  const events = [
    await authoritativeF04Event(),
    await bindCommand({
      id: "historical-g0-submission",
      revision: 2,
      type: "GATE_SUBMITTED",
      actorId: "external_product_owner",
      idempotencyKey: oldSubmissionKey,
      commandHash: null,
      createdAt: createdAt(2),
      payload: {
        gate_id: "G0",
        submission_id:
          F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId,
        package_hash:
          F04_HISTORICAL_AUTHORITY_BINDING.g0PackageHash,
        submitted_at: createdAt(2),
        submitted_by: "external_product_owner",
        source_revision: 1,
        work_package_scope: oldScope,
        evidence_refs: oldEvidenceRefs,
        supersedes: null,
      },
    }, {
      kind: "SUBMIT_GATE",
      gateId: "G0",
      evidenceRefs: oldEvidenceRefs,
      supersedes: null,
      expectedRevision: 1,
      idempotencyKey: oldSubmissionKey,
    }),
    await bindCommand({
      id: "historical-g0-decision",
      revision: 3,
      type: "GATE_DECIDED",
      actorId: "external_product_owner",
      idempotencyKey: oldDecisionKey,
      commandHash: null,
      createdAt: createdAt(3),
      payload: {
        decision_id: "historical-g0-decision-id",
        submission_id:
          F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId,
        package_hash:
          F04_HISTORICAL_AUTHORITY_BINDING.g0PackageHash,
        decision: "APPROVE",
        decided_by: "external_product_owner",
        decided_at: createdAt(3),
        accepted_exclusions: [],
        evidence_refs: oldDecisionEvidence,
      },
    }, {
      kind: "DECIDE_GATE",
      submissionId:
        F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId,
      expectedPackageHash:
        F04_HISTORICAL_AUTHORITY_BINDING.g0PackageHash,
      decision: "APPROVE",
      acceptedExclusions: [],
      evidenceRefs: oldDecisionEvidence,
      expectedRevision: 2,
      idempotencyKey: oldDecisionKey,
    }),
  ];
  for (let revision = 4; revision <= 64; revision += 1) {
    events.push({
      id: `unrelated-governance-event-${revision}`,
      revision,
      type: "PLAN_BASELINE_APPROVED",
      actorId: "external_product_owner",
      idempotencyKey: `unrelated-key-${revision}`,
      commandHash: `sha256:${String(revision % 10).repeat(64)}`,
      createdAt: createdAt(revision),
      payload: { baseline: `unrelated-${revision}` },
    });
  }
  for (const record of catalog.records) {
    const revision = events.length + 1;
    const position = revision - 64;
    const idempotencyKey =
      `${REMEDIATION_ROOT_KEY}:${String(position).padStart(2, "0")}-${record.workPackageId}`;
    const note =
      record.workPackageId === "F04"
        ? `G0 remediation preserves F04 human-baseline authority from online D1 revision 1 (${F04_HISTORICAL_AUTHORITY_BINDING.humanEvidenceSha256}).`
        : "G0 remediation from the frozen P0 evidence catalog.";
    const event = {
      id: `remediated-${record.workPackageId.toLowerCase()}`,
      revision,
      type: "WORK_PACKAGE_RECORDED",
      actorId: "external_product_owner",
      idempotencyKey,
      commandHash: null,
      createdAt: createdAt(revision),
      payload: {
        workPackageId: record.workPackageId,
        implementationStatus: "IMPLEMENTED",
        verificationStatus: "VERIFIED",
        evidenceRefs: [...record.evidenceRefs],
        evidenceHashes: [...record.evidenceHashes],
        note,
      },
    };
    events.push(await bindCommand(event, {
      kind: "RECORD_WORK_PACKAGE",
      workPackageId: record.workPackageId,
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
      evidenceRefs: [...record.evidenceRefs],
      evidenceHashes: [...record.evidenceHashes],
      note,
      expectedRevision: revision - 1,
      idempotencyKey,
    }));
  }
  const submissionEvidence = catalog.records.flatMap(
    (record) => record.evidenceRefs,
  );
  const submissionKey = `${REMEDIATION_ROOT_KEY}:05-G0-SUBMIT`;
  events.push(await bindCommand({
    id: "current-g0-submission-event",
    revision: 69,
    type: "GATE_SUBMITTED",
    actorId: "external_product_owner",
    idempotencyKey: submissionKey,
    commandHash: null,
    createdAt: createdAt(69),
    payload: {
      gate_id: "G0",
      submission_id: CURRENT_SUBMISSION_ID,
      package_hash: CURRENT_PACKAGE_HASH,
      submitted_at: createdAt(69),
      submitted_by: "external_product_owner",
      source_revision: 68,
      work_package_scope: currentScope(),
      evidence_refs: submissionEvidence,
      supersedes:
        F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId,
    },
  }, {
    kind: "SUBMIT_GATE",
    expectedRevision: 68,
    idempotencyKey: submissionKey,
    gateId: "G0",
    evidenceRefs: submissionEvidence,
    supersedes: F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId,
  }));
  const decisionEvidence = [
    `product-owner-decision:${CURRENT_SUBMISSION_ID}:${CURRENT_PACKAGE_HASH}:APPROVE`,
  ];
  events.push(await bindCommand({
    id: "current-g0-decision-event",
    revision: 70,
    type: "GATE_DECIDED",
    actorId: "external_product_owner",
    idempotencyKey: CURRENT_DECISION_KEY,
    commandHash: null,
    createdAt: createdAt(70),
    payload: {
      decision_id: "current-g0-decision-id",
      submission_id: CURRENT_SUBMISSION_ID,
      package_hash: CURRENT_PACKAGE_HASH,
      decision: "APPROVE",
      decided_by: "external_product_owner",
      decided_at: createdAt(70),
      accepted_exclusions: [],
      evidence_refs: decisionEvidence,
    },
  }, {
    kind: "DECIDE_GATE",
    submissionId: CURRENT_SUBMISSION_ID,
    expectedPackageHash: CURRENT_PACKAGE_HASH,
    decision: "APPROVE",
    acceptedExclusions: [],
    evidenceRefs: decisionEvidence,
    expectedRevision: 69,
    idempotencyKey: CURRENT_DECISION_KEY,
  }));
  return { revision: 70, events };
}

function request(actor = PRODUCT_OWNER, suffix = "") {
  const headers = new Headers();
  if (actor) headers.set("oai-authenticated-user-email", actor);
  return new Request(
    `${ROUTE_ORIGIN}/api/governance/p0-b11-evidence${suffix}`,
    { method: "GET", headers },
  );
}

function createGet(overrides = {}) {
  return createP0B11EvidenceGet({
    configuredProductOwner: () => PRODUCT_OWNER,
    isProductOwner: (actor, owner) =>
      actor.trim().toLowerCase() === owner.trim().toLowerCase(),
    loadJournalState: validJournalState,
    catalog,
    manifest,
    clock: () => FIXED_NOW,
    ...overrides,
  });
}

async function responseBytes(response) {
  return Buffer.from(await response.clone().arrayBuffer());
}

async function assertResponseEvidence(response) {
  const bytes = await responseBytes(response);
  const hex = createHash("sha256").update(bytes).digest("hex");
  const base64 = createHash("sha256").update(bytes).digest("base64");
  assert.equal(
    response.headers.get("content-digest"),
    `sha-256=:${base64}:`,
  );
  assert.equal(
    response.headers.get("x-response-body-sha256"),
    `sha256:${hex}`,
  );
  assert.equal(
    response.headers.get("x-response-body-length"),
    String(bytes.byteLength),
  );
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(
    response.headers.get("content-type"),
    "application/json; charset=utf-8",
  );
  assert.ok(bytes.byteLength < 16 * 1024);
  return {
    bytes,
    body: JSON.parse(bytes.toString("utf8")),
  };
}

test("authentication and Product Owner authorization fail closed before D1", async (t) => {
  const cases = [
    {
      name: "missing identity",
      actor: null,
      configuredProductOwner: () => PRODUCT_OWNER,
      status: 401,
      code: "AUTHENTICATION_REQUIRED",
    },
    {
      name: "Product Owner not configured",
      actor: PRODUCT_OWNER,
      configuredProductOwner: () => undefined,
      status: 503,
      code: "PRODUCT_OWNER_NOT_CONFIGURED",
    },
    {
      name: "non Product Owner",
      actor: "another-user@example.test",
      configuredProductOwner: () => PRODUCT_OWNER,
      status: 403,
      code: "PRODUCT_OWNER_REQUIRED",
    },
  ];
  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      let loads = 0;
      const GET = createGet({
        configuredProductOwner: testCase.configuredProductOwner,
        loadJournalState: async () => {
          loads += 1;
          throw new Error("D1 must not be read.");
        },
      });
      const response = await GET(request(testCase.actor));
      const { body } = await assertResponseEvidence(response);
      assert.equal(response.status, testCase.status);
      assert.equal(body.code, testCase.code);
      assert.equal(loads, 0);
    });
  }
});

test("query parameters are rejected without reading D1", async () => {
  let loads = 0;
  const GET = createGet({
    loadJournalState: async () => {
      loads += 1;
      return validJournalState();
    },
  });
  const response = await GET(request(PRODUCT_OWNER, "?revision=1"));
  assert.equal(response.status, 400);
  assert.equal((await response.json()).code, "QUERY_PARAMETERS_NOT_ALLOWED");
  assert.equal(loads, 0);
});

test("empty or unavailable D1 fails closed without leaking storage details", async (t) => {
  for (const testCase of [
    {
      name: "empty D1",
      loadJournalState: async () => ({ revision: 0, events: [] }),
    },
    {
      name: "D1 read failure",
      loadJournalState: async () => {
        throw new Error(
          "secret database governance_events token@example.test",
        );
      },
    },
  ]) {
    await t.test(testCase.name, async () => {
      const GET = createGet({
        loadJournalState: testCase.loadJournalState,
      });
      const response = await GET(request());
      const text = await response.text();
      assert.equal(response.status, 503);
      assert.match(text, /P0_B11_EVIDENCE_UNAVAILABLE/);
      assert.doesNotMatch(
        text,
        /secret|database|governance_events|token@example/i,
      );
    });
  }
});

test("the historical F04 authority predicate rejects missing, ambiguous, or malformed authority", async (t) => {
  const cases = [
    {
      name: "historical authority missing",
      mutate(events) {
        events[0].type = "PLAN_BASELINE_APPROVED";
      },
      code: "F04_HUMAN_AUTHORITY_UNPROVEN",
    },
    {
      name: "revision one content is wrong",
      mutate(events) {
        events[0].payload.verificationStatus = "NOT_VERIFIED";
      },
      code: "F04_HUMAN_AUTHORITY_UNPROVEN",
    },
    {
      name: "historical authority event ID is missing",
      mutate(events) {
        events[0].id = "";
      },
      code: "F04_HUMAN_AUTHORITY_UNPROVEN",
    },
    {
      name: "evidenceRefs are changed",
      mutate(events) {
        events[0].payload.evidenceRefs = ["implementation/p0/f04/other"];
      },
      code: "F04_HUMAN_AUTHORITY_UNPROVEN",
    },
    {
      name: "evidenceHashes are changed",
      mutate(events) {
        events[0].payload.evidenceHashes = [
          F04_HISTORICAL_AUTHORITY_BINDING.humanEvidenceSha256,
        ];
      },
      code: "F04_HUMAN_AUTHORITY_UNPROVEN",
    },
    {
      name: "commandHash is changed",
      mutate(events) {
        events[0].commandHash = `sha256:${"f".repeat(64)}`;
      },
      code: "F04_HUMAN_AUTHORITY_UNPROVEN",
    },
    {
      name: "idempotency binding is changed",
      mutate(events) {
        events[0].idempotencyKey = "changed-authority-key";
      },
      code: "F04_HUMAN_AUTHORITY_UNPROVEN",
    },
  ];
  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      const state = await validJournalState();
      testCase.mutate(state.events);
      await assert.rejects(
        assertUniqueF04HistoricalAuthority({
          journalState: state,
          catalog,
        }),
        (error) => error?.code === testCase.code,
      );
    });
  }

  await t.test("multiple matching authority events", async () => {
    const state = await validJournalState();
    state.events[3] = await authoritativeF04Event({
      revision: 4,
      id: "second-semantic-f04-authority",
      idempotencyKey: "second-semantic-f04-authority-key",
    });
    await assert.rejects(
      assertUniqueF04HistoricalAuthority({
        journalState: state,
        catalog,
      }),
      (error) => error?.code === "F04_HUMAN_AUTHORITY_AMBIGUOUS",
    );
  });

  await t.test("changed note with a recomputed commandHash", async () => {
    const state = await validJournalState();
    state.events[0].payload.note = "Changed authority note.";
    await bindF04Command(state.events[0]);
    await assert.doesNotReject(
      assertUniqueF04HistoricalAuthority({
        journalState: state,
        catalog,
      }),
    );
  });
});

test("the historical G0 anchor rejects scope, actor, and decision provenance drift", async (t) => {
  const cases = [
    {
      name: "historical Submission scope changed",
      mutate(events) {
        events[1].payload.work_package_scope[3].evidence_hashes = [
          F04_HISTORICAL_AUTHORITY_BINDING.humanEvidenceSha256,
        ];
      },
    },
    {
      name: "historical Submission actor changed",
      mutate(events) {
        events[1].actorId = "another_actor";
      },
    },
    {
      name: "historical Decision exclusions changed",
      mutate(events) {
        events[2].payload.accepted_exclusions = ["UNAPPROVED"];
      },
    },
  ];
  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      const state = await validJournalState();
      testCase.mutate(state.events);
      await assert.rejects(
        assertUniqueF04HistoricalAuthority({
          journalState: state,
          catalog,
        }),
        (error) => error?.code === "G0_HISTORICAL_ANCHOR_MISMATCH",
      );
    });
  }
});

test("the projection rejects journal gaps, duplicate IDs, and missing event time", async (t) => {
  const cases = [
    {
      name: "revision gap",
      mutate(state) {
        state.events[10].revision = 12;
      },
    },
    {
      name: "duplicate event ID",
      mutate(state) {
        state.events[10].id = state.events[9].id;
      },
    },
    {
      name: "missing event time",
      mutate(state) {
        delete state.events[0].createdAt;
      },
    },
  ];
  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      const state = await validJournalState();
      testCase.mutate(state);
      await assert.rejects(
        projectP0B11Evidence({
          journalState: state,
          catalog,
          manifest,
          serverTime: FIXED_NOW,
        }),
        (error) => error?.code === "ONLINE_D1_INVALID",
      );
    });
  }
});

test("the projection rejects inconsistent current G0 Submission and Decision", async (t) => {
  const cases = [
    {
      name: "different submission IDs",
      mutate(events) {
        events[69].payload.submission_id = "different-submission";
      },
    },
    {
      name: "different package hashes",
      mutate(events) {
        events[69].payload.package_hash = `sha256:${"f".repeat(64)}`;
      },
    },
    {
      name: "missing submission time",
      mutate(events) {
        delete events[68].createdAt;
      },
    },
    {
      name: "missing decision time",
      mutate(events) {
        delete events[69].createdAt;
      },
    },
  ];
  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      const state = await validJournalState();
      testCase.mutate(state.events);
      await assert.rejects(
        projectP0B11Evidence({
          journalState: state,
          catalog,
          manifest,
          serverTime: FIXED_NOW,
        }),
      );
    });
  }
});

test("the current G0 confirmation rejects actor, idempotency, command, and decision evidence drift", async (t) => {
  const cases = [
    {
      name: "work-package actor changed",
      mutate(events) {
        events[64].actorId = "another_actor";
      },
    },
    {
      name: "work-package idempotency changed",
      mutate(events) {
        events[64].idempotencyKey = "another-key";
      },
    },
    {
      name: "Submission actor changed",
      mutate(events) {
        events[68].actorId = "another_actor";
        events[68].payload.submitted_by = "another_actor";
      },
    },
    {
      name: "Submission commandHash changed",
      mutate(events) {
        events[68].commandHash = `sha256:${"f".repeat(64)}`;
      },
    },
    {
      name: "Decision actor changed",
      mutate(events) {
        events[69].actorId = "another_actor";
        events[69].payload.decided_by = "another_actor";
      },
    },
    {
      name: "Decision evidence changed",
      mutate(events) {
        events[69].payload.evidence_refs = [
          "product-owner-decision:changed",
        ];
      },
    },
    {
      name: "Decision commandHash changed",
      mutate(events) {
        events[69].commandHash = `sha256:${"e".repeat(64)}`;
      },
    },
  ];
  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      const state = await validJournalState();
      testCase.mutate(state.events);
      await assert.rejects(
        projectP0B11Evidence({
          journalState: state,
          catalog,
          manifest,
          serverTime: FIXED_NOW,
        }),
        (error) =>
          error?.code === "CURRENT_G0_CONFIRMATION_MISMATCH",
      );
    });
  }
});

test("the current G0 confirmation is bound to the server Manifest", async () => {
  const changedManifest = clone(manifest);
  changedManifest.manifest_version = "1.0.1";
  await assert.rejects(
    projectP0B11Evidence({
      journalState: await validJournalState(),
      catalog,
      manifest: changedManifest,
      serverTime: FIXED_NOW,
    }),
    (error) => error?.code === "CURRENT_G0_CONFIRMATION_MISMATCH",
  );
});

test("a valid online ledger returns the closed, privacy-preserving P0-B11 summary", async () => {
  let loads = 0;
  const GET = createGet({
    loadJournalState: async () => {
      loads += 1;
      return validJournalState();
    },
  });
  const response = await GET(request());
  const { body } = await assertResponseEvidence(response);

  assert.equal(response.status, 200);
  assert.equal(loads, 1);
  assert.equal(validateSchema(body), true, JSON.stringify(validateSchema.errors));
  assert.deepEqual(body, {
    schemaVersion: "p0-b11-evidence-projection.v1",
    source: "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER",
    currentRevision: 70,
    f04HumanBaselineAuthority: {
      eventId: "historical-f04-authoritative-human-validation",
      revision: 1,
      recordedAt: createdAt(1),
      workPackageId: "F04",
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
      evidenceRefs: [...F04_HISTORICAL_AUTHORITY_BINDING.evidenceRefs],
      evidenceHashes: [
        F04_HISTORICAL_AUTHORITY_BINDING.engineeringEvidenceSha256,
        F04_HISTORICAL_AUTHORITY_BINDING.humanEvidenceSha256,
      ],
      commandHash:
        "sha256:c44c90ae815c5710cf4a08e42fac4a907e0f513b566800ffa00945a1dacc6f63",
      actorBinding: {
        actorIdSha256: ACTOR_ID_SHA256,
        persistedRole: null,
        authorizationPath: "PRODUCT_OWNER_ONLY",
      },
      idempotencyKeySha256: IDEMPOTENCY_KEY_SHA256,
    },
    g0Submission: {
      eventId: "current-g0-submission-event",
      revision: 69,
      submissionId: CURRENT_SUBMISSION_ID,
      sourceRevision: 68,
      packageHash: CURRENT_PACKAGE_HASH,
      recordedAt: createdAt(69),
    },
    g0Decision: {
      eventId: "current-g0-decision-event",
      revision: 70,
      decisionId: "current-g0-decision-id",
      submissionId: CURRENT_SUBMISSION_ID,
      packageHash: CURRENT_PACKAGE_HASH,
      decision: "APPROVE",
      recordedAt: createdAt(70),
    },
    structuredAdjudicationPersisted: false,
    serverTime: FIXED_NOW,
  });
});

test("the response omits raw authority identity, idempotency, notes, and unrelated events", async () => {
  const state = await validJournalState();
  state.events[10].payload = {
    note: "secret token cookie authorization user@example.test",
  };
  const GET = createGet({ loadJournalState: async () => state });
  const response = await GET(request());
  const { bytes, body } = await assertResponseEvidence(response);
  const text = bytes.toString("utf8");

  assert.equal(response.status, 200);
  assert.equal(body.structuredAdjudicationPersisted, false);
  assert.equal(
    body.f04HumanBaselineAuthority.actorBinding.persistedRole,
    null,
  );
  assert.doesNotMatch(
    text,
    /external_product_owner|"historical-f04-authority"|secret token|cookie|user@example/i,
  );
  assert.equal("events" in body, false);
  assert.equal("note" in body.f04HumanBaselineAuthority, false);
  assert.deepEqual(Object.keys(body), [
    "schemaVersion",
    "source",
    "currentRevision",
    "f04HumanBaselineAuthority",
    "g0Submission",
    "g0Decision",
    "structuredAdjudicationPersisted",
    "serverTime",
  ]);
});

test("the closed schema rejects added fields and unsafe evidence references", async () => {
  const body = await projectP0B11Evidence({
    journalState: await validJournalState(),
    catalog,
    manifest,
    serverTime: FIXED_NOW,
  });
  const added = clone(body);
  added.actor = "external_product_owner";
  assert.equal(validateSchema(added), false);

  const unsafe = clone(body);
  unsafe.f04HumanBaselineAuthority.evidenceRefs[0] = "../secret";
  assert.equal(validateSchema(unsafe), false);
});

test("GET has no seed, execute, or append capability and the route exports GET only", async () => {
  const counts = {
    load: 0,
    seedIfNeeded: 0,
    execute: 0,
    append: 0,
  };
  const boundary = {
    async load() {
      counts.load += 1;
      return validJournalState();
    },
    async seedIfNeeded() {
      counts.seedIfNeeded += 1;
    },
    async execute() {
      counts.execute += 1;
    },
    async append() {
      counts.append += 1;
    },
  };
  const GET = createGet({ loadJournalState: boundary.load });
  const response = await GET(request());
  assert.equal(response.status, 200);
  assert.deepEqual(counts, {
    load: 1,
    seedIfNeeded: 0,
    execute: 0,
    append: 0,
  });

  const route = await readFile(ROUTE_URL, "utf8");
  const methods = [
    ...route.matchAll(
      /export (?:async function|const) (GET|POST|PUT|PATCH|DELETE)\b/g,
    ),
  ].map((match) => match[1]);
  assert.deepEqual(methods, ["GET"]);
  assert.doesNotMatch(
    route,
    /ensureDatabase|seedIfNeeded|control\.execute|journal\.append/,
  );
});

test("G0 remediation imports and reuses the same historical authority predicate", async () => {
  const source = await readFile(REMEDIATION_URL, "utf8");
  assert.match(
    source,
    /import[\s\S]*assertF04HistoricalAuthority[\s\S]*from "\.\/f04-historical-authority\.mjs"/,
  );
  assert.match(source, /await assertF04HistoricalAuthority\(/);
  assert.doesNotMatch(source, /async function validateHistoricalAnchor/);
});

test("adjacent governance HTTP methods and public progress actions remain unchanged", async () => {
  const [readiness, decision, stale, progress] = await Promise.all([
    ...ADJACENT_ROUTES.map((url) => readFile(url, "utf8")),
    readFile(new URL("../app/api/progress/route.ts", import.meta.url), "utf8"),
  ]);
  const methods = (source) =>
    [
      ...source.matchAll(
        /export (?:async function|const) (GET|POST|PUT|PATCH|DELETE)\b/g,
      ),
    ]
      .map((match) => match[1])
      .sort();
  assert.deepEqual(methods(readiness), ["GET"]);
  assert.deepEqual(methods(decision), ["GET", "POST"]);
  assert.deepEqual(methods(stale), ["GET"]);
  const actions = [
    ...progress.matchAll(/payload\.action === "([^"]+)"/g),
  ]
    .map((match) => match[1])
    .sort();
  assert.deepEqual(actions, [
    "decide_gate",
    "submit_gate",
    "update_connector",
    "update_task",
    "validate_human_baseline",
  ]);
});

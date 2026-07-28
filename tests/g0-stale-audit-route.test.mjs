import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createG0StaleAuditGet } from "../lib/g0-stale-audit-projection.mjs";
import { createProjectControl } from "../lib/project-control.mjs";

const PRODUCT_OWNER = "product-owner@example.test";
const P0_IDS = ["F01", "F02", "F03", "F04"];
const EVIDENCE_HASHES = Object.freeze({
  F01: `sha256:${"1".repeat(64)}`,
  F02: `sha256:${"2".repeat(64)}`,
  F03: `sha256:${"3".repeat(64)}`,
  F04: `sha256:${"4".repeat(64)}`,
});
const G0_PACKAGE_HASH = `sha256:${"a".repeat(64)}`;

function canonicalSha256(value) {
  return `sha256:${createHash("sha256")
    .update(JSON.stringify(value))
    .digest("hex")}`;
}

function requestFor(actor = null, suffix = "") {
  const headers = new Headers();
  if (actor) headers.set("oai-authenticated-user-email", actor);
  return new Request(
    `https://example.test/api/governance/g0-stale-audit${suffix}`,
    { headers },
  );
}

function createGet(overrides = {}) {
  return createG0StaleAuditGet({
    configuredProductOwner: () => PRODUCT_OWNER,
    isProductOwner: (actor, configured) =>
      actor.trim().toLowerCase() === configured.trim().toLowerCase(),
    loadAuditInput: async () => {
      throw new Error("The ledger must not be read before authentication.");
    },
    clock: () => "2026-07-29T01:00:00.000Z",
    ...overrides,
  });
}

async function assertByteBoundResponseEvidence(response) {
  const bytes = Buffer.from(await response.clone().arrayBuffer());
  const sha256Hex = createHash("sha256").update(bytes).digest("hex");
  const sha256Base64 = createHash("sha256").update(bytes).digest("base64");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);

  assert.equal(
    response.headers.get("content-digest"),
    `sha-256=:${sha256Base64}:`,
  );
  assert.equal(
    response.headers.get("x-response-body-sha256"),
    `sha256:${sha256Hex}`,
  );
  assert.equal(
    response.headers.get("x-response-body-length"),
    String(bytes.byteLength),
  );
  assert.deepEqual(Buffer.from(text, "utf8"), bytes);
  assert.ok(bytes.byteLength < 16 * 1024);
  assert.doesNotMatch(
    JSON.stringify(Object.fromEntries(response.headers)),
    /product-owner@example\.test|secret|token|credential/i,
  );
  assert.doesNotMatch(
    text,
    /content-digest|x-response-body-sha256|x-response-body-length/i,
  );
  return JSON.parse(text);
}

async function loadManifest() {
  return JSON.parse(
    await readFile(
      new URL(
        "../implementation/governance/work-package-manifest.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
}

async function createProjectedGet(initialEvents = [], counters = {}) {
  const manifest = await loadManifest();
  const events = initialEvents.map((event, index) => ({
    ...structuredClone(event),
    revision: event.revision ?? index + 1,
  }));
  const journalState = {
    revision: events.at(-1)?.revision ?? 0,
    events,
  };
  const capturedJournal = {
    async load() {
      counters.load = (counters.load ?? 0) + 1;
      return structuredClone(journalState);
    },
    async append() {
      counters.append = (counters.append ?? 0) + 1;
      throw new Error("GET must never append a governance event.");
    },
  };
  const control = createProjectControl({
    manifest,
    journal: capturedJournal,
    verifyFrozenEvidence: async () => true,
  });
  return createGet({
    async loadAuditInput() {
      return {
        journalState: structuredClone(journalState),
        snapshot: await control.snapshot(),
      };
    },
  });
}

function createdAt(second) {
  return new Date(Date.UTC(2026, 6, 28, 19, 20, second)).toISOString();
}

function workPackageEvent(workPackageId, revision, overrides = {}) {
  return {
    id: `wp-${workPackageId.toLowerCase()}-${revision}`,
    revision,
    type: "WORK_PACKAGE_RECORDED",
    actorId: "external-product-owner",
    createdAt: createdAt(revision),
    payload: {
      workPackageId,
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
      evidenceRefs: [`git:evidence/${workPackageId.toLowerCase()}.json`],
      evidenceHashes: [EVIDENCE_HASHES[workPackageId]],
      note: `private ${workPackageId} note`,
      ...overrides,
    },
  };
}

function scopeFromPackageEvents(events) {
  return P0_IDS.map((workPackageId) => {
    const event = events
      .filter(
        ({ type, payload }) =>
          type === "WORK_PACKAGE_RECORDED" &&
          payload.workPackageId === workPackageId,
      )
      .at(-1);
    return {
      work_package_id: workPackageId,
      applicability: "REQUIRED",
      implementation_status: event.payload.implementationStatus,
      verification_status: event.payload.verificationStatus,
      evidence_refs: [...event.payload.evidenceRefs],
      evidence_hashes: [...event.payload.evidenceHashes],
    };
  });
}

function approvedG0Events() {
  const events = P0_IDS.map((id, index) => workPackageEvent(id, index + 1));
  events.push({
    id: "g0-submission-event",
    revision: 5,
    type: "GATE_SUBMITTED",
    actorId: "external-product-owner",
    createdAt: createdAt(5),
    payload: {
      gate_id: "G0",
      submission_id: "g0-submission",
      package_hash: G0_PACKAGE_HASH,
      submitted_at: createdAt(5),
      submitted_by: "external-product-owner",
      source_revision: 4,
      work_package_scope: scopeFromPackageEvents(events),
      evidence_refs: ["git:evidence/g0.json"],
      supersedes: null,
    },
  });
  events.push({
    id: "g0-decision-event",
    revision: 6,
    type: "GATE_DECIDED",
    actorId: "external-product-owner",
    createdAt: createdAt(6),
    payload: {
      decision_id: "g0-decision",
      submission_id: "g0-submission",
      package_hash: G0_PACKAGE_HASH,
      decision: "APPROVE",
      decided_by: "external-product-owner",
      decided_at: createdAt(6),
      accepted_exclusions: [],
      evidence_refs: ["git:evidence/g0-decision.json"],
    },
  });
  return events;
}

test("G0 stale audit requires an authenticated Product Owner identity", async () => {
  let loadCount = 0;
  const response = await createGet({
    loadAuditInput: async () => {
      loadCount += 1;
      throw new Error("The ledger must not be read before authentication.");
    },
  })(requestFor());

  assert.equal(response.status, 401);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(loadCount, 0);
  assert.deepEqual(await response.json(), {
    schemaVersion: "g0-stale-audit-error.v1",
    code: "AUTHENTICATION_REQUIRED",
    error: "需要先通过工作区身份验证。",
  });
});

test("G0 stale audit fails closed when the Product Owner is not configured", async () => {
  let loadCount = 0;
  const response = await createGet({
    configuredProductOwner: () => undefined,
    loadAuditInput: async () => {
      loadCount += 1;
    },
  })(requestFor(PRODUCT_OWNER));

  assert.equal(response.status, 503);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(loadCount, 0);
  assert.deepEqual(await response.json(), {
    schemaVersion: "g0-stale-audit-error.v1",
    code: "PRODUCT_OWNER_NOT_CONFIGURED",
    error: "产品所有者身份尚未配置。",
  });
});

test("G0 stale audit rejects a non-Product Owner identity", async () => {
  let loadCount = 0;
  const response = await createGet({
    loadAuditInput: async () => {
      loadCount += 1;
    },
  })(requestFor("another-user@example.test"));

  assert.equal(response.status, 403);
  assert.equal(loadCount, 0);
  assert.deepEqual(await response.json(), {
    schemaVersion: "g0-stale-audit-error.v1",
    code: "PRODUCT_OWNER_REQUIRED",
    error: "只有外部产品所有者可以读取 G0 stale 审计。",
  });
});

test("G0 stale audit rejects every caller-supplied query parameter", async () => {
  let loadCount = 0;
  const response = await createGet({
    loadAuditInput: async () => {
      loadCount += 1;
    },
  })(
    requestFor(
      PRODUCT_OWNER,
      "?gate=G1&revision=64&workPackage=F04&tenant=forged",
    ),
  );

  assert.equal(response.status, 400);
  assert.equal(loadCount, 0);
  assert.deepEqual(await response.json(), {
    schemaVersion: "g0-stale-audit-error.v1",
    code: "QUERY_PARAMETERS_NOT_ALLOWED",
    error: "该只读端点不接受查询参数。",
  });
});

test("an empty online ledger does not inherit P0 status from the Manifest", async () => {
  const response = await (await createProjectedGet())(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(body, {
    schemaVersion: "g0-stale-audit.v1",
    source: "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER",
    revision: 0,
    g0: {
      status: "NOT_READY",
      staleReasonCode: null,
      staleCondition: {
        latestSubmissionExists: false,
        latestDecisionExists: false,
        scopeMismatch: false,
        requiredNotVerified: true,
        evaluatesToStale: false,
      },
    },
    latestSubmission: null,
    latestDecision: null,
    workPackages: {
      F01: null,
      F02: null,
      F03: null,
      F04: null,
    },
    scopeDiff: [],
    scopeMatch: null,
    allRequiredVerified: false,
    hasSupersession: false,
    progressRequestGovernanceEventRevisions: [],
    governanceEventsWriteAssessment: "UNPROVABLE",
    serverTime: "2026-07-29T01:00:00.000Z",
  });
});

test("an exact approved G0 returns only the latest bounded event metadata", async () => {
  const response = await (await createProjectedGet(approvedG0Events()))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.revision, 6);
  assert.deepEqual(body.g0, {
    status: "APPROVED",
    staleReasonCode: null,
    staleCondition: {
      latestSubmissionExists: true,
      latestDecisionExists: true,
      scopeMismatch: false,
      requiredNotVerified: false,
      evaluatesToStale: false,
    },
  });
  assert.deepEqual(body.latestSubmission, {
    eventId: "g0-submission-event",
    revision: 5,
    submissionId: "g0-submission",
    sourceRevision: 4,
    packageHash: G0_PACKAGE_HASH,
    recordedAt: createdAt(5),
  });
  assert.deepEqual(body.latestDecision, {
    eventId: "g0-decision-event",
    revision: 6,
    decisionId: "g0-decision",
    submissionId: "g0-submission",
    packageHash: G0_PACKAGE_HASH,
    decision: "APPROVE",
    recordedAt: createdAt(6),
  });
  assert.deepEqual(body.workPackages.F04, {
    eventId: "wp-f04-4",
    revision: 4,
    implementationStatus: "IMPLEMENTED",
    verificationStatus: "VERIFIED",
    evidenceHashes: [EVIDENCE_HASHES.F04],
    recordedAt: createdAt(4),
  });
  assert.deepEqual(Object.keys(body.workPackages), P0_IDS);
  assert.deepEqual(body.scopeDiff, []);
  assert.equal(body.scopeMatch, true);
  assert.equal(body.allRequiredVerified, true);
  assert.equal(body.hasSupersession, false);
});

test("a verified evidence revision makes an approved mismatched scope ready to resubmit", async () => {
  const events = approvedG0Events();
  const replacementHash = `sha256:${"9".repeat(64)}`;
  events.push(
    workPackageEvent("F04", 7, {
      evidenceRefs: ["git:evidence/f04-v2.json"],
      evidenceHashes: [replacementHash],
    }),
  );

  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.g0.status, "READY_TO_SUBMIT");
  assert.equal(body.g0.staleReasonCode, null);
  assert.equal(body.scopeMatch, false);
  assert.equal(body.allRequiredVerified, true);
  assert.deepEqual(body.scopeDiff, [
    {
      workPackageId: "F04",
      fields: {
        evidenceHashes: {
          submitted: [EVIDENCE_HASHES.F04],
          current: [replacementHash],
        },
        evidenceRefs: {
          submittedCount: 1,
          currentCount: 1,
          submittedSha256: canonicalSha256(["git:evidence/f04.json"]),
          currentSha256: canonicalSha256(["git:evidence/f04-v2.json"]),
        },
      },
    },
  ]);
});

test("a mismatched scope with an unverified required package is STALE_SUBMISSION", async () => {
  const events = approvedG0Events();
  events.push(
    workPackageEvent("F04", 7, {
      verificationStatus: "NOT_VERIFIED",
      evidenceRefs: [],
      evidenceHashes: [],
    }),
  );

  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(body.g0, {
    status: "STALE_SUBMISSION",
    staleReasonCode: "CURRENT_SCOPE_MISMATCH_REQUIRED_NOT_VERIFIED",
    staleCondition: {
      latestSubmissionExists: true,
      latestDecisionExists: true,
      scopeMismatch: true,
      requiredNotVerified: true,
      evaluatesToStale: true,
    },
  });
  assert.equal(body.scopeMatch, false);
  assert.equal(body.allRequiredVerified, false);
  assert.deepEqual(body.workPackages.F04.evidenceHashes, []);
  assert.deepEqual(body.scopeDiff, [
    {
      workPackageId: "F04",
      fields: {
        verificationStatus: {
          submitted: "VERIFIED",
          current: "NOT_VERIFIED",
        },
        evidenceHashes: {
          submitted: [EVIDENCE_HASHES.F04],
          current: [],
        },
        evidenceRefs: {
          submittedCount: 1,
          currentCount: 0,
          submittedSha256: canonicalSha256(["git:evidence/f04.json"]),
          currentSha256: canonicalSha256([]),
        },
      },
    },
  ]);
});

test("every response binds digest, SHA-256 and length to the exact UTF-8 body", async (t) => {
  const cases = [
    {
      name: "200 audit",
      response: async () =>
        (await createProjectedGet(approvedG0Events()))(
          requestFor(PRODUCT_OWNER),
        ),
      status: 200,
    },
    {
      name: "400 query rejected",
      response: async () =>
        createGet()(requestFor(PRODUCT_OWNER, "?revision=64")),
      status: 400,
    },
    {
      name: "401 unauthenticated",
      response: async () => createGet()(requestFor()),
      status: 401,
    },
    {
      name: "403 non-Product Owner",
      response: async () =>
        createGet()(requestFor("another-user@example.test")),
      status: 403,
    },
    {
      name: "503 Product Owner not configured",
      response: async () =>
        createGet({
          configuredProductOwner: () => undefined,
        })(requestFor(PRODUCT_OWNER)),
      status: 503,
    },
    {
      name: "503 D1 unavailable",
      response: async () =>
        createGet({
          loadAuditInput: async () => {
            throw new Error(
              "database secret token credential product-owner@example.test",
            );
          },
        })(requestFor(PRODUCT_OWNER)),
      status: 503,
    },
  ];

  for (const item of cases) {
    await t.test(item.name, async () => {
      const response = await item.response();
      const body = await assertByteBoundResponseEvidence(response);
      assert.equal(response.status, item.status);
      assert.equal(response.headers.get("cache-control"), "no-store");
      assert.equal(
        response.headers.get("content-type"),
        "application/json; charset=utf-8",
      );
      assert.equal(Object.hasOwn(body, "contentDigest"), false);
      assert.equal(Object.hasOwn(body, "responseBodySha256"), false);
      assert.equal(Object.hasOwn(body, "responseBodyLength"), false);
    });
  }
});

test("the bounded response excludes actors, notes, credentials, other Gates and other work packages", async () => {
  const events = approvedG0Events();
  events[0].actorId = "product-owner@example.test";
  events[0].payload.note =
    "secret token credential product-owner@example.test";
  events.push({
    id: "unrelated-o02-event",
    revision: 7,
    type: "WORK_PACKAGE_RECORDED",
    actorId: "product-owner@example.test",
    createdAt: createdAt(7),
    payload: {
      workPackageId: "O02",
      implementationStatus: "IN_PROGRESS",
      verificationStatus: "NOT_VERIFIED",
      evidenceRefs: [
        "secret token credential product-owner@example.test",
      ],
      evidenceHashes: [],
      note: "private note",
    },
  });

  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();
  const serialized = JSON.stringify(body);

  assert.equal(response.status, 200);
  assert.deepEqual(Object.keys(body.workPackages), P0_IDS);
  assert.equal(Object.hasOwn(body, "events"), false);
  assert.equal(Object.hasOwn(body, "gates"), false);
  assert.doesNotMatch(
    serialized,
    /actor|note|secret|token|credential|product-owner@example\.test|O02|G1/i,
  );
});

test("sensitive text in public identifier fields fails closed instead of being reflected", async (t) => {
  const cases = [
    {
      name: "work-package event ID contains an email",
      mutate(events) {
        events[0].id = "product-owner@example.test";
      },
    },
    {
      name: "Submission ID contains a token marker",
      mutate(events) {
        events[4].payload.submission_id = "secret-token";
        events[5].payload.submission_id = "secret-token";
      },
    },
    {
      name: "Decision ID contains a credential marker",
      mutate(events) {
        events[5].payload.decision_id = "credential";
      },
    },
  ];

  for (const item of cases) {
    await t.test(item.name, async () => {
      const events = approvedG0Events();
      item.mutate(events);
      const response = await (await createProjectedGet(events))(
        requestFor(PRODUCT_OWNER),
      );
      const text = await response.text();

      assert.equal(response.status, 503);
      assert.doesNotMatch(
        text,
        /product-owner@example\.test|secret|token|credential/i,
      );
    });
  }
});

test("revision gaps, duplicate event IDs and invalid Gate causality fail closed", async (t) => {
  const cases = [
    {
      name: "revision gap",
      events() {
        const events = approvedG0Events();
        events.at(-1).revision = 7;
        return events;
      },
    },
    {
      name: "duplicate event ID",
      events() {
        const events = approvedG0Events();
        events[1].id = events[0].id;
        return events;
      },
    },
    {
      name: "Decision before Submission",
      events() {
        const events = approvedG0Events();
        const submission = events[4];
        const decision = events[5];
        events[4] = { ...decision, revision: 5 };
        events[5] = {
          ...submission,
          revision: 6,
          payload: {
            ...submission.payload,
            source_revision: 5,
          },
        };
        return events;
      },
    },
    {
      name: "wrong Submission source revision",
      events() {
        const events = approvedG0Events();
        events[4].payload.source_revision = 3;
        return events;
      },
    },
    {
      name: "Decision package hash mismatch",
      events() {
        const events = approvedG0Events();
        events[5].payload.package_hash = `sha256:${"b".repeat(64)}`;
        return events;
      },
    },
    {
      name: "incomplete Submission scope",
      events() {
        const events = approvedG0Events();
        events[4].payload.work_package_scope.pop();
        return events;
      },
    },
    {
      name: "incomplete work-package event",
      events() {
        const events = approvedG0Events();
        delete events[3].payload.evidenceHashes;
        return events;
      },
    },
  ];

  for (const item of cases) {
    await t.test(item.name, async () => {
      const response = await (await createProjectedGet(item.events()))(
        requestFor(PRODUCT_OWNER),
      );
      assert.equal(response.status, 503);
      assert.deepEqual(await response.json(), {
        schemaVersion: "g0-stale-audit-error.v1",
        code: "G0_STALE_AUDIT_UNAVAILABLE",
        error: "线上 G0 stale 审计暂时不可用。",
      });
    });
  }
});

test("a valid replacement Submission reports supersession without reviving the old Decision", async () => {
  const events = approvedG0Events();
  const replacementHash = `sha256:${"9".repeat(64)}`;
  events.push(
    workPackageEvent("F04", 7, {
      evidenceRefs: ["git:evidence/f04-v2.json"],
      evidenceHashes: [replacementHash],
    }),
  );
  events.push({
    id: "g0-replacement-submission-event",
    revision: 8,
    type: "GATE_SUBMITTED",
    actorId: "external-product-owner",
    createdAt: createdAt(8),
    payload: {
      gate_id: "G0",
      submission_id: "g0-replacement-submission",
      package_hash: `sha256:${"c".repeat(64)}`,
      submitted_at: createdAt(8),
      submitted_by: "external-product-owner",
      source_revision: 7,
      work_package_scope: scopeFromPackageEvents(events),
      evidence_refs: ["git:evidence/g0-v2.json"],
      supersedes: "g0-submission",
    },
  });

  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.g0.status, "AWAITING_DECISION");
  assert.equal(body.scopeMatch, true);
  assert.equal(body.hasSupersession, true);
  assert.equal(
    body.latestSubmission.submissionId,
    "g0-replacement-submission",
  );
  assert.equal(body.latestDecision, null);
});

test("the audit accepts valid ledger values without inventing narrower ID, date-time or evidence limits", async () => {
  const events = approvedG0Events();
  const manyHashes = Array.from(
    { length: 33 },
    (_, index) =>
      `sha256:${index.toString(16).padStart(64, "0")}`,
  );
  const manyRefs = Array.from(
    { length: 129 },
    (_, index) => `git:evidence/f01-${index}.json`,
  );
  const longRef = `git:evidence/${"x".repeat(2_100)}`;
  events[0].id = "event id allowed by D1 TEXT";
  events[0].createdAt = "2026-07-28T20:20:01+01:00";
  events[0].payload.evidenceRefs = manyRefs;
  events[0].payload.evidenceHashes = manyHashes;
  events[4].id = "submission event allowed by D1 TEXT";
  events[4].createdAt = "2026-07-28T20:20:05+01:00";
  events[4].payload.submission_id = "G0 submission / 2026";
  events[4].payload.submitted_at = "2026-07-28T20:20:05+01:00";
  events[4].payload.work_package_scope = scopeFromPackageEvents(events);
  events[4].payload.evidence_refs = [longRef];
  events[5].id = "decision event allowed by D1 TEXT";
  events[5].createdAt = "2026-07-28T20:20:06+01:00";
  events[5].payload.decision_id = "G0 decision / 2026";
  events[5].payload.submission_id = "G0 submission / 2026";
  events[5].payload.decided_at = "2026-07-28T20:20:06+01:00";
  events[5].payload.evidence_refs = [longRef];

  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.latestSubmission.submissionId, "G0 submission / 2026");
  assert.equal(body.latestDecision.decisionId, "G0 decision / 2026");
  assert.equal(
    body.workPackages.F01.recordedAt,
    "2026-07-28T20:20:01+01:00",
  );
  assert.deepEqual(body.workPackages.F01.evidenceHashes, manyHashes);
  assert.ok(Number(response.headers.get("x-response-body-length")) < 16 * 1024);
});

test("an otherwise valid ledger that cannot fit the fixed response budget fails closed with a bounded response", async () => {
  const events = approvedG0Events();
  const manyHashes = Array.from(
    { length: 230 },
    (_, index) =>
      `sha256:${index.toString(16).padStart(64, "0")}`,
  );
  events[0].payload.evidenceHashes = manyHashes;
  events[4].payload.work_package_scope = scopeFromPackageEvents(events);

  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await assertByteBoundResponseEvidence(response);

  assert.equal(response.status, 503);
  assert.deepEqual(body, {
    schemaVersion: "g0-stale-audit-error.v1",
    code: "G0_STALE_AUDIT_UNAVAILABLE",
    error: "线上 G0 stale 审计暂时不可用。",
  });
});

test("the fixed progress-request window reports only correlatable governance revisions", async () => {
  const events = approvedG0Events();
  events.push({
    id: "plan-baseline-v5.1-386a5778",
    revision: 7,
    type: "PLAN_BASELINE_APPROVED",
    actorId: "external-product-owner",
    createdAt: "2026-07-28T19:26:27.404Z",
    payload: {
      note: "must never be returned",
    },
  });

  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(body.progressRequestGovernanceEventRevisions, [7]);
  assert.equal(body.governanceEventsWriteAssessment, "UNPROVABLE");
  assert.doesNotMatch(JSON.stringify(body), /must never be returned/i);
});

test("absence of a nearby event does not prove request-level write causality", async () => {
  const response = await (await createProjectedGet(approvedG0Events()))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.deepEqual(body.progressRequestGovernanceEventRevisions, []);
  assert.equal(body.governanceEventsWriteAssessment, "UNPROVABLE");
});

test("the historical and current F04 evidence hashes appear as an exact field-level diff", async () => {
  const historicalF04 =
    "sha256:851851fcec6d961efaf17f6a0ced172c12dad2dced6746c9c9b805a205c95f62";
  const currentF04 =
    "sha256:4791558978f34a3ccd15de80f05efc8beb13660227c11a4a308380ac9d100f35";
  const events = approvedG0Events();
  events[3].payload.evidenceHashes = [historicalF04];
  events[4].payload.work_package_scope[3].evidence_hashes = [historicalF04];
  events.push(
    workPackageEvent("F04", 7, {
      evidenceHashes: [currentF04],
    }),
  );

  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(body.scopeDiff[0].fields.evidenceHashes, {
    submitted: [historicalF04],
    current: [currentF04],
  });
});

test("the production route is a GET-only D1 composition root with no write or seed path", async () => {
  const source = await readFile(
    new URL(
      "../app/api/governance/g0-stale-audit/route.ts",
      import.meta.url,
    ),
    "utf8",
  );

  assert.match(source, /createD1GovernanceJournal/);
  assert.match(source, /createProjectControl/);
  assert.match(source, /createG0StaleAuditGet/);
  assert.match(source, /export const GET/);
  assert.doesNotMatch(
    source,
    /ensureDatabase|seedIfNeeded|control\.execute|journal\.append|governance-events\.v1\.json|README|docs\/plans/,
  );
  assert.doesNotMatch(
    source,
    /export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)|export const (?:POST|PUT|PATCH|DELETE)/,
  );
  assert.doesNotMatch(
    source,
    /SUBMIT_GATE|DECIDE_GATE|RECORD_WORK_PACKAGE|APPROVE_P2_ACCEPTANCE_PROFILE|AUTHORIZE_P2_WORK_PACKAGE_START/,
  );
});

test("an invalid server clock fails closed without leaking its value", async () => {
  const response = await createGet({
    loadAuditInput: async () => {
      const manifest = await loadManifest();
      const journal = {
        async load() {
          return { revision: 0, events: [] };
        },
        async append() {
          throw new Error("read only");
        },
      };
      const control = createProjectControl({ manifest, journal });
      return {
        journalState: { revision: 0, events: [] },
        snapshot: await control.snapshot(),
      };
    },
    clock: () => "secret token product-owner@example.test",
  })(requestFor(PRODUCT_OWNER));
  const text = await response.text();

  assert.equal(response.status, 503);
  assert.doesNotMatch(text, /secret|token|product-owner@example\.test/i);
});

test("GET reads one captured ledger projection and never appends", async () => {
  const counters = { load: 0, append: 0 };
  const response = await (await createProjectedGet(approvedG0Events(), counters))(
    requestFor(PRODUCT_OWNER),
  );

  assert.equal(response.status, 200);
  assert.equal(counters.load, 1);
  assert.equal(counters.append, 0);
});

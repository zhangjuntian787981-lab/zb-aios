import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import p0Catalog from "../implementation/governance/p0-frozen-evidence-index.v1.json" with { type: "json" };
import p1Catalog from "../implementation/governance/p1-d1-evidence-bindings.revision-64.v1.json" with { type: "json" };
import manifest from "../implementation/governance/work-package-manifest.v1.json" with { type: "json" };
import {
  G0_DECISION_BINDING,
  createG0DecisionHandlers,
} from "../lib/g0-decision.mjs";
import { P2_V2_CANDIDATE_START_POLICY } from "../lib/p2-start-authorization.mjs";
import {
  createMemoryJournal,
  createProjectControl,
} from "../lib/project-control.mjs";

const PRODUCT_OWNER = "product-owner@example.test";
const ROUTE_ORIGIN = "https://example.test";
const FIXED_NOW = "2026-07-29T06:00:00.000Z";
const OLD_SUBMISSION_ID = "06531499-9cc4-4b09-b0c4-1f6d18e36fd6";
const OLD_PACKAGE_HASH =
  "sha256:77d8707a602a83729b557c028bd6cf87c5a0e5d921145b9dc3a5a1e79bf32a07";
const REMEDIATION_SUBMIT_IDEMPOTENCY_KEY =
  "g0-remediation-20260729-001:05-G0-SUBMIT";
const REMEDIATION_SUBMIT_COMMAND_HASH =
  "sha256:06bcc209cb6b23597f71970a017324d17b2b1b60cfb530eb499cb981beec2ab5";
const G1_SUBMISSION_ID = "approved-g1-submission";
const G1_PACKAGE_HASH = `sha256:${"1".repeat(64)}`;
const ROUTE_URL = new URL(
  "../app/api/governance/g0-decision/route.ts",
  import.meta.url,
);
const MODULE_URL = new URL("../lib/g0-decision.mjs", import.meta.url);
const PROGRESS_ROUTE_URL = new URL(
  "../app/api/progress/route.ts",
  import.meta.url,
);

function createdAt(revision) {
  return new Date(
    Date.parse("2026-07-29T04:00:00.000Z") + revision * 1_000,
  ).toISOString();
}

function catalogRecord(workPackageId) {
  return [...p0Catalog.records, ...p1Catalog.records].find(
    (record) => record.workPackageId === workPackageId,
  );
}

function scopeForPhase(phase) {
  return manifest.work_packages
    .filter((item) => item.phase === phase)
    .map((item) => {
      const record = catalogRecord(item.id);
      return {
        work_package_id: item.id,
        applicability: item.applicability,
        implementation_status: "IMPLEMENTED",
        verification_status: "VERIFIED",
        evidence_refs: [...record.evidenceRefs],
        evidence_hashes: [...record.evidenceHashes],
      };
    });
}

function decisionReadyEvents() {
  const events = [];
  function push(type, payload, extra = {}) {
    const revision = events.length + 1;
    events.push({
      id: `event-${revision}`,
      revision,
      type,
      actorId: "external_product_owner",
      createdAt: createdAt(revision),
      payload,
      ...extra,
    });
  }

  for (const item of scopeForPhase("P0")) {
    push("WORK_PACKAGE_RECORDED", {
      workPackageId: item.work_package_id,
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
      evidenceRefs: item.evidence_refs,
      evidenceHashes: item.evidence_hashes,
      note: "Synthetic test fixture.",
    });
  }
  push("GATE_SUBMITTED", {
    gate_id: "G0",
    submission_id: OLD_SUBMISSION_ID,
    package_hash: OLD_PACKAGE_HASH,
    submitted_at: createdAt(5),
    submitted_by: "external_product_owner",
    source_revision: 4,
    work_package_scope: scopeForPhase("P0"),
    evidence_refs: ["git:test:g0-old"],
    supersedes: null,
  });
  push("GATE_DECIDED", {
    decision_id: "historical-g0-decision",
    submission_id: OLD_SUBMISSION_ID,
    package_hash: OLD_PACKAGE_HASH,
    decision: "APPROVE",
    decided_by: "external_product_owner",
    decided_at: createdAt(6),
    accepted_exclusions: [],
    evidence_refs: ["product-owner-decision:test:g0-old"],
  });
  for (const item of scopeForPhase("P1")) {
    push("WORK_PACKAGE_RECORDED", {
      workPackageId: item.work_package_id,
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
      evidenceRefs: item.evidence_refs,
      evidenceHashes: item.evidence_hashes,
      note: "Synthetic test fixture.",
    });
  }
  push("GATE_SUBMITTED", {
    gate_id: "G1",
    submission_id: G1_SUBMISSION_ID,
    package_hash: G1_PACKAGE_HASH,
    submitted_at: createdAt(26),
    submitted_by: "external_product_owner",
    source_revision: 25,
    work_package_scope: scopeForPhase("P1"),
    evidence_refs: ["git:test:g1"],
    supersedes: null,
  });
  push("GATE_DECIDED", {
    decision_id: "approved-g1-decision",
    submission_id: G1_SUBMISSION_ID,
    package_hash: G1_PACKAGE_HASH,
    decision: "APPROVE",
    decided_by: "external_product_owner",
    decided_at: createdAt(27),
    accepted_exclusions: [],
    evidence_refs: ["product-owner-decision:test:g1"],
  });
  while (events.length < 64) {
    const revision = events.length + 1;
    push("PLAN_BASELINE_APPROVED", {
      baseline: `unrelated-${revision}`,
    });
  }
  for (const item of scopeForPhase("P0")) {
    push("WORK_PACKAGE_RECORDED", {
      workPackageId: item.work_package_id,
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
      evidenceRefs: item.evidence_refs,
      evidenceHashes: item.evidence_hashes,
      note: "G0 remediation test fixture.",
    });
  }
  push(
    "GATE_SUBMITTED",
    {
      gate_id: "G0",
      submission_id: G0_DECISION_BINDING.submissionId,
      package_hash: G0_DECISION_BINDING.packageHash,
      submitted_at: createdAt(69),
      submitted_by: "external_product_owner",
      source_revision: 68,
      work_package_scope: scopeForPhase("P0"),
      evidence_refs: p0Catalog.records.flatMap(
        (record) => record.evidenceRefs,
      ),
      supersedes: OLD_SUBMISSION_ID,
    },
    {
      idempotencyKey: REMEDIATION_SUBMIT_IDEMPOTENCY_KEY,
      commandHash: REMEDIATION_SUBMIT_COMMAND_HASH,
    },
  );
  return events;
}

function createRuntimeHarness({
  events = decisionReadyEvents(),
  beforeAppend = null,
  beforeSnapshot = null,
  verifyFrozenEvidence = async () => true,
} = {}) {
  const memory = createMemoryJournal(events);
  const counts = {
    createRuntime: 0,
    load: 0,
    append: 0,
    snapshot: 0,
    execute: 0,
  };
  const journal = {
    async load(...args) {
      counts.load += 1;
      return memory.load(...args);
    },
    async append(...args) {
      counts.append += 1;
      if (beforeAppend) {
        await beforeAppend({ appendNumber: counts.append });
      }
      return memory.append(...args);
    },
  };
  const baseControl = createProjectControl({
    manifest,
    journal,
    verifyFrozenEvidence,
    p2StartPolicy: P2_V2_CANDIDATE_START_POLICY,
    clock: (() => {
      let tick = 0;
      return () =>
        new Date(
          Date.parse("2026-07-29T06:01:00.000Z") + tick++,
        ).toISOString();
    })(),
    idFactory: (() => {
      let next = 0;
      return () => `g0-decision-server-id-${++next}`;
    })(),
  });
  const control = {
    async snapshot(...args) {
      counts.snapshot += 1;
      if (beforeSnapshot) {
        await beforeSnapshot({ snapshotNumber: counts.snapshot });
      }
      return baseControl.snapshot(...args);
    },
    execute(...args) {
      counts.execute += 1;
      return baseControl.execute(...args);
    },
  };
  return {
    counts,
    memory,
    createRuntime() {
      counts.createRuntime += 1;
      return { control };
    },
  };
}

function createTwoPartyBarrier(timeoutMilliseconds = 5_000) {
  let arrivals = 0;
  let timer;
  let release;
  let reject;
  const released = new Promise((resolve, rejectPromise) => {
    release = resolve;
    reject = rejectPromise;
  });
  return {
    async wait() {
      arrivals += 1;
      if (arrivals === 1) {
        timer = setTimeout(() => {
          reject(
            new Error(
              `Concurrent decision barrier timed out at ${arrivals}/2.`,
            ),
          );
        }, timeoutMilliseconds);
      }
      if (arrivals > 2) {
        throw new Error("Concurrent decision barrier received too many arrivals.");
      }
      if (arrivals === 2) {
        clearTimeout(timer);
        release();
      }
      await released;
    },
    get arrivals() {
      return arrivals;
    },
  };
}

function createHold() {
  let enteredResolve;
  let releaseResolve;
  const entered = new Promise((resolve) => {
    enteredResolve = resolve;
  });
  const released = new Promise((resolve) => {
    releaseResolve = resolve;
  });
  return {
    entered,
    async wait() {
      enteredResolve();
      await released;
    },
    release() {
      releaseResolve();
    },
  };
}

function createHandlers(overrides = {}) {
  return createG0DecisionHandlers({
    configuredProductOwner: () => PRODUCT_OWNER,
    isProductOwner: (actor, owner) =>
      actor.trim().toLowerCase() === owner.trim().toLowerCase(),
    createRuntime: () => {
      throw new Error("D1 must not be read before authorization.");
    },
    clock: () => FIXED_NOW,
    ...overrides,
  });
}

function mutationGuardProbe({
  origin = ROUTE_ORIGIN,
  secFetchSite = "same-origin",
  contentType = "application/json",
  contentLength,
  text = JSON.stringify(validPostBody()),
} = {}) {
  const counts = {
    bodyRead: 0,
    createRuntime: 0,
    journalLoad: 0,
    journalAppend: 0,
    controlExecute: 0,
  };
  const headers = new Headers({
    "oai-authenticated-user-email": PRODUCT_OWNER,
  });
  if (origin !== null) headers.set("origin", origin);
  if (secFetchSite !== null) {
    headers.set("sec-fetch-site", secFetchSite);
  }
  if (contentType !== null) headers.set("content-type", contentType);
  if (contentLength !== undefined) {
    headers.set("content-length", contentLength);
  }
  const trackedRequest = {
    url: `${ROUTE_ORIGIN}/api/governance/g0-decision`,
    headers,
    async text() {
      counts.bodyRead += 1;
      return text;
    },
  };
  const createRuntime = () => {
    counts.createRuntime += 1;
    return {
      control: {
        async snapshot() {
          counts.journalLoad += 1;
          throw new Error("Mutation guard reached control.snapshot.");
        },
        async execute() {
          counts.controlExecute += 1;
          throw new Error("Mutation guard reached control.execute.");
        },
      },
      journal: {
        async append() {
          counts.journalAppend += 1;
          throw new Error("Mutation guard reached journal.append.");
        },
      },
    };
  };
  return { request: trackedRequest, counts, createRuntime };
}

function request(method = "GET", actor = PRODUCT_OWNER, body, headers = {}) {
  const requestHeaders = new Headers();
  if (actor) {
    requestHeaders.set("oai-authenticated-user-email", actor);
  }
  if (body !== undefined) {
    requestHeaders.set("content-type", "application/json");
    requestHeaders.set("origin", ROUTE_ORIGIN);
    requestHeaders.set("sec-fetch-site", "same-origin");
  }
  for (const [name, value] of Object.entries(headers)) {
    if (value === null) requestHeaders.delete(name);
    else requestHeaders.set(name, value);
  }
  return new Request(`${ROUTE_ORIGIN}/api/governance/g0-decision`, {
    method,
    headers: requestHeaders,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function validPostBody(overrides = {}) {
  return {
    expectedRevision: G0_DECISION_BINDING.expectedRevision,
    submissionId: G0_DECISION_BINDING.submissionId,
    packageHash: G0_DECISION_BINDING.packageHash,
    decision: G0_DECISION_BINDING.decision,
    idempotencyKey: G0_DECISION_BINDING.idempotencyKey,
    confirmation: G0_DECISION_BINDING.confirmation,
    ...overrides,
  };
}

async function responseEvidence(response) {
  const bytes = Buffer.from(await response.clone().arrayBuffer());
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const base64 = Buffer.from(sha256, "hex").toString("base64");
  assert.equal(
    response.headers.get("x-response-body-length"),
    String(bytes.byteLength),
  );
  assert.equal(
    response.headers.get("x-response-body-sha256"),
    `sha256:${sha256}`,
  );
  assert.equal(
    response.headers.get("content-digest"),
    `sha-256=:${base64}:`,
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

test("GET previews the exact revision-69 G0 decision without executing or appending", async () => {
  const runtime = createRuntimeHarness();
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });

  const response = await handlers.GET(request());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(body, {
    schemaVersion: "g0-decision-preview.v1",
    source: "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER",
    revision: 69,
    g0Status: "AWAITING_DECISION",
    latestSubmission: {
      submissionId: G0_DECISION_BINDING.submissionId,
      packageHash: G0_DECISION_BINDING.packageHash,
      revision: 69,
    },
    latestDecisionExists: false,
    allP0Verified: true,
    g1Status: "APPROVED",
    phaseEntryP2: false,
    approveImpact: {
      decision: "APPROVE",
      resultRevision: 70,
      g0Status: "APPROVED",
      phaseEntryP2: true,
      profileApprovalChanges: 0,
      workPackageStatusChanges: 0,
      startAuthorizationChanges: 0,
    },
    canDecide: true,
    blockers: [],
    serverTime: FIXED_NOW,
  });
  assert.equal(runtime.counts.execute, 0);
  assert.equal(runtime.counts.append, 0);
});

test("GET accepts the Git-frozen revision-64 dotted event ID", async () => {
  const events = decisionReadyEvents();
  events[63].id = "plan-baseline-v5.1-386a5778";
  const runtime = createRuntimeHarness({ events });
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });

  const response = await handlers.GET(request());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.revision, 69);
  assert.equal(body.canDecide, true);
  assert.equal(runtime.counts.execute, 0);
  assert.equal(runtime.counts.append, 0);
});

test("POST appends exactly one GATE_DECIDED and immediately reads back the P2 entry effect", async () => {
  const runtime = createRuntimeHarness();
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });

  const response = await handlers.POST(
    request("POST", PRODUCT_OWNER, validPostBody()),
  );
  const body = await response.json();
  const state = await runtime.memory.load(manifest.project_id);
  const appended = state.events.slice(69);

  assert.equal(response.status, 200);
  assert.deepEqual(body, {
    schemaVersion: "g0-decision-execution.v1",
    source: "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER",
    status: "COMPLETED",
    revision: 70,
    decisionEvent: {
      eventId: "g0-decision-server-id-1",
      revision: 70,
      decisionId: "g0-decision-server-id-2",
      submissionId: G0_DECISION_BINDING.submissionId,
      packageHash: G0_DECISION_BINDING.packageHash,
      decision: "APPROVE",
    },
    duplicate: false,
    g0Status: "APPROVED",
    phaseEntryP2: true,
    profileApproval: null,
    workPackages: {
      O02: {
        startAuthorizationStatus: "NOT_AUTHORIZED",
        allowedToStart: false,
      },
      O03: {
        startAuthorizationStatus: "NOT_AUTHORIZED",
        allowedToStart: false,
      },
    },
    serverTime: FIXED_NOW,
  });
  assert.equal(state.revision, 70);
  assert.equal(appended.length, 1);
  assert.equal(appended[0].type, "GATE_DECIDED");
  assert.equal(
    appended[0].payload.submission_id,
    G0_DECISION_BINDING.submissionId,
  );
  assert.equal(
    appended[0].payload.package_hash,
    G0_DECISION_BINDING.packageHash,
  );
  assert.equal(appended[0].payload.decision, "APPROVE");
  assert.deepEqual(appended[0].payload.accepted_exclusions, []);
  assert.equal(appended[0].actorId, "external_product_owner");
  assert.equal(
    appended[0].payload.decided_by,
    "external_product_owner",
  );
  assert.deepEqual(appended[0].payload.evidence_refs, [
    `product-owner-decision:${G0_DECISION_BINDING.submissionId}:${G0_DECISION_BINDING.packageHash}:APPROVE`,
  ]);
  assert.equal(runtime.counts.execute, 1);
  assert.equal(runtime.counts.append, 1);
  assert.ok(runtime.counts.load >= 3);
});

test("POST safely converges when the exact fixed idempotency key is replayed", async () => {
  const runtime = createRuntimeHarness();
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });
  const postRequest = () =>
    request("POST", PRODUCT_OWNER, validPostBody());

  const first = await handlers.POST(postRequest());
  const second = await handlers.POST(postRequest());
  const firstBody = await first.json();
  const secondBody = await second.json();
  const state = await runtime.memory.load(manifest.project_id);
  const decisions = state.events.filter(
    ({ type, payload }) =>
      type === "GATE_DECIDED" &&
      payload.submission_id === G0_DECISION_BINDING.submissionId,
  );

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(firstBody.duplicate, false);
  assert.equal(secondBody.duplicate, true);
  assert.deepEqual(secondBody.decisionEvent, firstBody.decisionEvent);
  assert.equal(state.revision, 70);
  assert.equal(decisions.length, 1);
  assert.equal(runtime.counts.execute, 2);
  assert.equal(runtime.counts.append, 1);
});

test("same-key replay fails closed if the completed revision-69 Submission provenance no longer matches", async () => {
  const runtime = createRuntimeHarness();
  const initialHandlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });
  const initialResponse = await initialHandlers.POST(
    request("POST", PRODUCT_OWNER, validPostBody()),
  );
  const executeCountAfterInitial = runtime.counts.execute;
  const live = runtime.createRuntime();
  const replayHandlers = createHandlers({
    createRuntime: () => ({
      control: {
        async snapshot(...args) {
          const snapshot = await live.control.snapshot(...args);
          snapshot.events[68].commandHash = `sha256:${"f".repeat(64)}`;
          return snapshot;
        },
        execute: (...args) => live.control.execute(...args),
      },
    }),
  });

  const replayResponse = await replayHandlers.POST(
    request("POST", PRODUCT_OWNER, validPostBody()),
  );
  const { body } = await responseEvidence(replayResponse);
  const state = await runtime.memory.load(manifest.project_id);

  assert.equal(initialResponse.status, 200);
  assert.equal(replayResponse.status, 409);
  assert.equal(body.code, "G0_DECISION_NOT_ALLOWED");
  assert.equal(runtime.counts.execute, executeCountAfterInitial);
  assert.equal(runtime.counts.append, 1);
  assert.equal(state.revision, 70);
});

test("GET and POST fail closed for missing, unconfigured, and non-owner identities", async () => {
  const scenarios = [
    {
      name: "missing identity",
      actor: null,
      configuredProductOwner: () => PRODUCT_OWNER,
      status: 401,
      code: "AUTHENTICATION_REQUIRED",
    },
    {
      name: "unconfigured Product Owner",
      actor: PRODUCT_OWNER,
      configuredProductOwner: () => "",
      status: 503,
      code: "PRODUCT_OWNER_NOT_CONFIGURED",
    },
    {
      name: "non-owner identity",
      actor: "not-the-owner@example.test",
      configuredProductOwner: () => PRODUCT_OWNER,
      status: 403,
      code: "PRODUCT_OWNER_REQUIRED",
    },
  ];
  for (const scenario of scenarios) {
    let createRuntimeCount = 0;
    const handlers = createHandlers({
      configuredProductOwner: scenario.configuredProductOwner,
      createRuntime() {
        createRuntimeCount += 1;
        throw new Error("Unauthorized request reached D1.");
      },
    });
    for (const method of ["GET", "POST"]) {
      const response = await handlers[method](
        request(
          method,
          scenario.actor,
          method === "POST" ? validPostBody() : undefined,
        ),
      );
      const { body } = await responseEvidence(response);
      assert.equal(
        response.status,
        scenario.status,
        `${scenario.name}:${method}`,
      );
      assert.deepEqual(Object.keys(body).sort(), [
        "code",
        "error",
        "schemaVersion",
      ]);
      assert.equal(body.code, scenario.code);
    }
    assert.equal(createRuntimeCount, 0);
  }
});

test("successful preview and execution responses bind their exact returned UTF-8 bytes", async () => {
  const runtime = createRuntimeHarness();
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });

  const previewResponse = await handlers.GET(request());
  const previewResult = await responseEvidence(previewResponse);
  const executionResponse = await handlers.POST(
    request("POST", PRODUCT_OWNER, validPostBody()),
  );
  const executionResult = await responseEvidence(executionResponse);
  const publicText = `${previewResult.bytes.toString("utf8")}\n${executionResult.bytes.toString("utf8")}`;

  assert.equal(previewResponse.status, 200);
  assert.equal(executionResponse.status, 200);
  assert.doesNotMatch(
    publicText,
    /product-owner@example\.test|cookie|token|secret|credential|evidence_refs|evidenceRefs|actorId|idempotencyKey|"authorization"\s*:/i,
  );
});

test("POST rejects every non-same-origin mutation before reading the body or touching D1", async () => {
  const attacks = [
    { origin: null },
    { origin: "not-an-origin" },
    { origin: "https://attacker.test" },
    { origin: `${ROUTE_ORIGIN}/` },
    { origin: "HTTPS://example.test" },
    { origin: `${ROUTE_ORIGIN} ${ROUTE_ORIGIN}` },
    { secFetchSite: null },
    { secFetchSite: "cross-site" },
    { secFetchSite: "same-site" },
    { secFetchSite: "none" },
    { secFetchSite: "SAME-ORIGIN" },
    { secFetchSite: "unknown" },
  ];
  for (const attack of attacks) {
    const probe = mutationGuardProbe(attack);
    const handlers = createHandlers({
      createRuntime: probe.createRuntime,
    });

    const response = await handlers.POST(probe.request);
    const { body } = await responseEvidence(response);

    assert.equal(response.status, 403);
    assert.equal(body.code, "CROSS_SITE_REQUEST_FORBIDDEN");
    assert.deepEqual(probe.counts, {
      bodyRead: 0,
      createRuntime: 0,
      journalLoad: 0,
      journalAppend: 0,
      controlExecute: 0,
    });
  }
});

test("POST accepts only the two exact UTF-8 JSON media types", async () => {
  const rejected = [
    null,
    "application/jsonp",
    "application/json-patch+json",
    "application/problem+json",
    "application/json; charset=utf-16",
    "application/json; charset=\"utf-8\"",
    "application/json; charset=utf-8; charset=utf-8",
    "application/json;",
    "application/json; profile=test",
    "text/plain",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
  ];
  for (const contentType of rejected) {
    const probe = mutationGuardProbe({ contentType });
    const handlers = createHandlers({
      createRuntime: probe.createRuntime,
    });

    const response = await handlers.POST(probe.request);
    const { body } = await responseEvidence(response);

    assert.equal(response.status, 400);
    assert.equal(body.code, "INVALID_REQUEST");
    assert.equal(probe.counts.bodyRead, 0);
    assert.equal(probe.counts.createRuntime, 0);
    assert.equal(probe.counts.journalLoad, 0);
    assert.equal(probe.counts.journalAppend, 0);
    assert.equal(probe.counts.controlExecute, 0);
  }

  for (const contentType of [
    "application/json",
    "application/json; charset=utf-8",
    "Application/JSON ; Charset = UTF-8",
  ]) {
    const runtime = createRuntimeHarness();
    const handlers = createHandlers({
      createRuntime: runtime.createRuntime,
    });
    const response = await handlers.POST(
      request(
        "POST",
        PRODUCT_OWNER,
        validPostBody(),
        { "content-type": contentType },
      ),
    );
    assert.equal(response.status, 200, contentType);
  }
});

test("POST rejects malformed and oversized bodies before creating a runtime", async () => {
  const preReadRejected = [
    { contentLength: "4097" },
    { contentLength: "-1" },
    { contentLength: "1.5" },
    { contentLength: "not-a-number" },
    { contentLength: "01" },
  ];
  for (const input of preReadRejected) {
    const probe = mutationGuardProbe(input);
    const handlers = createHandlers({
      createRuntime: probe.createRuntime,
    });
    const response = await handlers.POST(probe.request);
    assert.equal(response.status, 400);
    assert.equal(probe.counts.bodyRead, 0);
    assert.equal(probe.counts.createRuntime, 0);
  }

  for (const text of [
    "{",
    "x".repeat(4 * 1024 + 1),
    `"${"汉".repeat(1_400)}"`,
  ]) {
    const probe = mutationGuardProbe({ text });
    const handlers = createHandlers({
      createRuntime: probe.createRuntime,
    });
    const response = await handlers.POST(probe.request);
    assert.equal(response.status, 400);
    assert.equal(probe.counts.bodyRead, 1);
    assert.equal(probe.counts.createRuntime, 0);
  }
});

test("POST closes its request fields and rejects every caller-controlled governance value before D1", async () => {
  const invalidBodies = [
    null,
    [],
    {},
    { ...validPostBody(), actor: "external_product_owner" },
    { ...validPostBody(), evidenceRefs: ["caller-controlled"] },
    { ...validPostBody(), command: { kind: "DECIDE_GATE" } },
    { ...validPostBody(), status: "APPROVED" },
    validPostBody({ expectedRevision: 70 }),
    validPostBody({ submissionId: "another-submission" }),
    validPostBody({ packageHash: `sha256:${"f".repeat(64)}` }),
    validPostBody({ decision: "RETURN" }),
    validPostBody({ idempotencyKey: "another-key" }),
    validPostBody({ confirmation: "CONFIRM_SOMETHING_ELSE" }),
  ];
  let createRuntimeCount = 0;
  const handlers = createHandlers({
    createRuntime() {
      createRuntimeCount += 1;
      throw new Error("Invalid request reached D1.");
    },
  });

  for (const body of invalidBodies) {
    const response = await handlers.POST(
      request("POST", PRODUCT_OWNER, body),
    );
    assert.ok([400, 409].includes(response.status));
  }
  assert.equal(createRuntimeCount, 0);
});

test(
  "two truly overlapping POSTs with the fixed idempotency key converge on one decision",
  { timeout: 10_000 },
  async () => {
    const barrier = createTwoPartyBarrier();
    const runtime = createRuntimeHarness({
      beforeAppend: ({ appendNumber }) =>
        appendNumber <= 2 ? barrier.wait() : undefined,
    });
    const handlers = createHandlers({
      createRuntime: runtime.createRuntime,
    });

    const responses = await Promise.all([
      handlers.POST(
        request("POST", PRODUCT_OWNER, validPostBody()),
      ),
      handlers.POST(
        request("POST", PRODUCT_OWNER, validPostBody()),
      ),
    ]);
    const bodies = await Promise.all(
      responses.map(async (response) => (await responseEvidence(response)).body),
    );
    const state = await runtime.memory.load(manifest.project_id);
    const decisions = state.events.filter(
      ({ type, payload }) =>
        type === "GATE_DECIDED" &&
        payload.submission_id === G0_DECISION_BINDING.submissionId,
    );

    assert.equal(barrier.arrivals, 2);
    assert.deepEqual(
      responses.map(({ status }) => status),
      [200, 200],
    );
    assert.deepEqual(
      bodies.map(({ duplicate }) => duplicate).sort(),
      [false, true],
    );
    assert.deepEqual(bodies[0].decisionEvent, bodies[1].decisionEvent);
    assert.equal(state.revision, 70);
    assert.equal(decisions.length, 1);
    assert.equal(runtime.counts.append, 2);
  },
);

test("a different-key POST fails closed while the fixed request is in flight", async () => {
  const hold = createHold();
  const runtime = createRuntimeHarness({
    beforeSnapshot: ({ snapshotNumber }) =>
      snapshotNumber === 1 ? hold.wait() : undefined,
  });
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });
  const approvedRequest = handlers.POST(
    request("POST", PRODUCT_OWNER, validPostBody()),
  );
  await hold.entered;

  const rejected = await handlers.POST(
    request(
      "POST",
      PRODUCT_OWNER,
      validPostBody({ idempotencyKey: "different-concurrent-key" }),
    ),
  );
  hold.release();
  const approved = await approvedRequest;
  const state = await runtime.memory.load(manifest.project_id);
  const decisions = state.events.filter(
    ({ type, payload }) =>
      type === "GATE_DECIDED" &&
      payload.submission_id === G0_DECISION_BINDING.submissionId,
  );

  assert.equal(rejected.status, 400);
  assert.equal(
    (await rejected.json()).code,
    "IDEMPOTENCY_KEY_MISMATCH",
  );
  assert.equal(approved.status, 200);
  assert.equal(state.revision, 70);
  assert.equal(decisions.length, 1);
  assert.equal(runtime.counts.createRuntime, 1);
  assert.equal(runtime.counts.execute, 1);
  assert.equal(runtime.counts.append, 1);
});

test("GET fails closed on revision gaps, duplicate event IDs, and a decision before its submission", async () => {
  const invalidLedgers = [
    (() => {
      const events = decisionReadyEvents();
      events[10].revision = 99;
      return events;
    })(),
    (() => {
      const events = decisionReadyEvents();
      events[10].id = events[9].id;
      return events;
    })(),
    (() => {
      const events = decisionReadyEvents();
      events[60] = {
        id: "future-caused-g0-decision",
        revision: 61,
        type: "GATE_DECIDED",
        actorId: "external_product_owner",
        createdAt: createdAt(61),
        payload: {
          decision_id: "future-caused-g0-decision-id",
          submission_id: G0_DECISION_BINDING.submissionId,
          package_hash: G0_DECISION_BINDING.packageHash,
          decision: "APPROVE",
          decided_by: "external_product_owner",
          decided_at: createdAt(61),
          accepted_exclusions: [],
          evidence_refs: ["invalid:test-only"],
        },
      };
      return events;
    })(),
  ];

  for (const events of invalidLedgers) {
    const runtime = createRuntimeHarness({ events });
    const handlers = createHandlers({
      createRuntime: runtime.createRuntime,
    });
    const response = await handlers.GET(request());
    const { body } = await responseEvidence(response);

    assert.equal(response.status, 503);
    assert.equal(body.code, "ONLINE_D1_INVALID");
    assert.equal(runtime.counts.execute, 0);
    assert.equal(runtime.counts.append, 0);
  }
});

test("GET fails closed instead of reflecting a sensitive Submission identifier", async () => {
  const events = decisionReadyEvents();
  events[68].payload.submission_id = "product-owner@example.test";
  const runtime = createRuntimeHarness({ events });
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });

  const response = await handlers.GET(request());
  const { bytes, body } = await responseEvidence(response);

  assert.equal(response.status, 503);
  assert.equal(body.code, "ONLINE_D1_INVALID");
  assert.doesNotMatch(bytes.toString("utf8"), /product-owner@example\.test/i);
  assert.equal(runtime.counts.execute, 0);
  assert.equal(runtime.counts.append, 0);
});

test("unfrozen P0 evidence blocks preview and POST before control.execute", async () => {
  const runtime = createRuntimeHarness({
    verifyFrozenEvidence: async ({ workPackageId }) =>
      workPackageId !== "F04",
  });
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });

  const previewResponse = await handlers.GET(request());
  const previewBody = await previewResponse.json();
  const postResponse = await handlers.POST(
    request("POST", PRODUCT_OWNER, validPostBody()),
  );
  const postBody = await postResponse.json();

  assert.equal(previewResponse.status, 200);
  assert.equal(previewBody.canDecide, false);
  assert.ok(previewBody.blockers.includes("P0_EVIDENCE_NOT_FROZEN"));
  assert.equal(postResponse.status, 409);
  assert.equal(postBody.code, "G0_DECISION_NOT_ALLOWED");
  assert.equal(runtime.counts.execute, 0);
  assert.equal(runtime.counts.append, 0);
});

test("an empty D1 projection does not inherit work-package or Gate state from the Manifest", async () => {
  const runtime = createRuntimeHarness({ events: [] });
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });

  const response = await handlers.GET(request());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.revision, 0);
  assert.equal(body.g0Status, "NOT_READY");
  assert.equal(body.latestSubmission, null);
  assert.equal(body.latestDecisionExists, false);
  assert.equal(body.allP0Verified, false);
  assert.equal(body.g1Status, "NOT_READY");
  assert.equal(body.canDecide, false);
  assert.ok(body.blockers.includes("REVISION_MISMATCH"));
  assert.equal(runtime.counts.execute, 0);
  assert.equal(runtime.counts.append, 0);
});

test("a decision already written under another idempotency key blocks before execute", async () => {
  const events = decisionReadyEvents();
  events.push({
    id: "other-channel-decision-event",
    revision: 70,
    type: "GATE_DECIDED",
    actorId: "external_product_owner",
    idempotencyKey: "other-decision-key",
    commandHash: `sha256:${"2".repeat(64)}`,
    createdAt: createdAt(70),
    payload: {
      decision_id: "other-channel-decision-id",
      submission_id: G0_DECISION_BINDING.submissionId,
      package_hash: G0_DECISION_BINDING.packageHash,
      decision: "APPROVE",
      decided_by: "external_product_owner",
      decided_at: createdAt(70),
      accepted_exclusions: [],
      evidence_refs: ["other-channel:test-only"],
    },
  });
  const runtime = createRuntimeHarness({ events });
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });

  const response = await handlers.POST(
    request("POST", PRODUCT_OWNER, validPostBody()),
  );
  const body = await response.json();
  const state = await runtime.memory.load(manifest.project_id);

  assert.equal(response.status, 409);
  assert.equal(body.code, "G0_DECISION_NOT_ALLOWED");
  assert.equal(state.revision, 70);
  assert.equal(runtime.counts.execute, 0);
  assert.equal(runtime.counts.append, 0);
});

test("G1 or P0 state drift blocks the fixed decision without executing it", async () => {
  const variants = [
    (() => {
      const events = decisionReadyEvents();
      events[67].payload.verificationStatus = "NOT_VERIFIED";
      return events;
    })(),
    (() => {
      const events = decisionReadyEvents();
      events[26] = {
        id: "g1-decision-removed",
        revision: 27,
        type: "PLAN_BASELINE_APPROVED",
        actorId: "external_product_owner",
        createdAt: createdAt(27),
        payload: { baseline: "g1-decision-removed" },
      };
      return events;
    })(),
  ];
  for (const events of variants) {
    const runtime = createRuntimeHarness({ events });
    const handlers = createHandlers({
      createRuntime: runtime.createRuntime,
    });
    const response = await handlers.POST(
      request("POST", PRODUCT_OWNER, validPostBody()),
    );

    assert.equal(response.status, 409);
    assert.equal(runtime.counts.execute, 0);
    assert.equal(runtime.counts.append, 0);
  }
});

test("unexpected Profile or O02 authorization events block before the Gate decision write", async () => {
  const variants = [
    {
      type: "P2_ACCEPTANCE_PROFILE_APPROVED",
      payload: { profile_approval_id: "unexpected-profile" },
    },
    {
      type: "P2_WORK_PACKAGE_START_AUTHORIZED",
      payload: {
        work_package_id: "O02",
        authorization_status: "AUTHORIZED",
      },
    },
    {
      type: "P2_WORK_PACKAGE_START_AUTHORIZED",
      payload: {
        work_package_id: "O03",
        authorization_status: "AUTHORIZED",
      },
    },
  ];
  for (const replacement of variants) {
    const events = decisionReadyEvents();
    events[59] = {
      id: `unexpected-${replacement.type.toLowerCase()}`,
      revision: 60,
      type: replacement.type,
      actorId: "external_product_owner",
      createdAt: createdAt(60),
      payload: replacement.payload,
    };
    const runtime = createRuntimeHarness({ events });
    const handlers = createHandlers({
      createRuntime: runtime.createRuntime,
    });

    const response = await handlers.POST(
      request("POST", PRODUCT_OWNER, validPostBody()),
    );

    assert.equal(response.status, 409);
    assert.equal(runtime.counts.execute, 0);
    assert.equal(runtime.counts.append, 0);
    assert.equal(
      (await runtime.memory.load(manifest.project_id)).revision,
      69,
    );
  }
});

test("D1 read failures return a bounded 503 and never attempt a write", async () => {
  let executeCount = 0;
  const handlers = createHandlers({
    createRuntime: () => ({
      control: {
        async snapshot() {
          throw new Error("Synthetic D1 read failure.");
        },
        async execute() {
          executeCount += 1;
          throw new Error("Unexpected execute.");
        },
      },
    }),
  });

  for (const method of ["GET", "POST"]) {
    const response = await handlers[method](
      request(
        method,
        PRODUCT_OWNER,
        method === "POST" ? validPostBody() : undefined,
      ),
    );
    const { body } = await responseEvidence(response);
    assert.equal(response.status, 503);
    assert.equal(body.code, "G0_DECISION_UNAVAILABLE");
  }
  assert.equal(executeCount, 0);
});

test("authorization dependency failures return a fixed bounded 503 without touching D1", async () => {
  const handlersByFailure = [
    createHandlers({
      configuredProductOwner() {
        throw new Error("secret-token=owner-config-failure");
      },
    }),
    createHandlers({
      isProductOwner() {
        throw new Error("secret-token=owner-check-failure");
      },
    }),
  ];
  for (const handlers of handlersByFailure) {
    for (const method of ["GET", "POST"]) {
      const response = await handlers[method](
        request(
          method,
          PRODUCT_OWNER,
          method === "POST" ? validPostBody() : undefined,
        ),
      );
      const { bytes, body } = await responseEvidence(response);
      assert.equal(response.status, 503);
      assert.deepEqual(body, {
        schemaVersion: "g0-decision-error.v1",
        code: "G0_DECISION_UNAVAILABLE",
        error: "线上 G0 Decision 通道暂时不可用。",
      });
      assert.doesNotMatch(bytes.toString("utf8"), /secret-token/i);
    }
  }
});

test("status-bearing and oversized dependency errors are never reflected", async () => {
  const dependencyErrors = [
    Object.assign(new Error("secret-token=dependency-failure"), {
      code: "DEPENDENCY_FAILURE",
      status: 503,
    }),
    Object.assign(new Error(`secret-token=${"x".repeat(20_000)}`), {
      code: "OVERSIZED_DEPENDENCY_FAILURE",
      status: 503,
    }),
  ];
  for (const dependencyError of dependencyErrors) {
    const handlers = createHandlers({
      createRuntime: () => ({
        control: {
          async snapshot() {
            throw dependencyError;
          },
          async execute() {
            throw new Error("Unexpected execute.");
          },
        },
      }),
    });
    const response = await handlers.GET(request());
    const { bytes, body } = await responseEvidence(response);

    assert.equal(response.status, 503);
    assert.deepEqual(body, {
      schemaVersion: "g0-decision-error.v1",
      code: "G0_DECISION_UNAVAILABLE",
      error: "线上 G0 Decision 通道暂时不可用。",
    });
    assert.doesNotMatch(bytes.toString("utf8"), /secret-token/i);
  }
});

test("POST rejects a successful-looking receipt when the immediate D1 readback did not persist it", async () => {
  const runtime = createRuntimeHarness();
  const live = runtime.createRuntime();
  let fakeExecuteCount = 0;
  const handlers = createHandlers({
    createRuntime: () => ({
      control: {
        snapshot: (...args) => live.control.snapshot(...args),
        async execute() {
          fakeExecuteCount += 1;
          return {
            revision: 70,
            eventId: "phantom-event",
            duplicate: false,
            output: {
              decision: {
                submission_id: G0_DECISION_BINDING.submissionId,
                package_hash: G0_DECISION_BINDING.packageHash,
                decision: "APPROVE",
              },
            },
          };
        },
      },
    }),
  });

  const response = await handlers.POST(
    request("POST", PRODUCT_OWNER, validPostBody()),
  );
  const { body } = await responseEvidence(response);
  const state = await runtime.memory.load(manifest.project_id);

  assert.equal(response.status, 503);
  assert.equal(body.code, "READBACK_MISMATCH");
  assert.equal(fakeExecuteCount, 1);
  assert.equal(state.revision, 69);
  assert.equal(runtime.counts.append, 0);
});

test("the fixed revision 69 submission provenance must match the completed remediation plan", async () => {
  const variants = [
    {
      name: "source revision",
      mutate(event) {
        event.payload.source_revision = 67;
      },
    },
    {
      name: "supersedes",
      mutate(event) {
        event.payload.supersedes = "another-submission";
      },
    },
    {
      name: "submitted by",
      mutate(event) {
        event.payload.submitted_by = "another-actor";
      },
    },
    {
      name: "evidence refs",
      mutate(event) {
        event.payload.evidence_refs = ["caller-controlled"];
      },
    },
    {
      name: "idempotency key",
      mutate(event) {
        event.idempotencyKey = "another-remediation:05-G0-SUBMIT";
      },
    },
    {
      name: "command hash",
      mutate(event) {
        event.commandHash = `sha256:${"f".repeat(64)}`;
      },
    },
  ];

  for (const variant of variants) {
    const events = decisionReadyEvents();
    variant.mutate(events[68]);
    const runtime = createRuntimeHarness({ events });
    const handlers = createHandlers({
      createRuntime: runtime.createRuntime,
    });

    const previewResponse = await handlers.GET(request());
    const previewBody = await previewResponse.json();
    const postResponse = await handlers.POST(
      request("POST", PRODUCT_OWNER, validPostBody()),
    );

    assert.equal(previewResponse.status, 200, variant.name);
    assert.equal(previewBody.canDecide, false, variant.name);
    assert.ok(
      previewBody.blockers.includes("SUBMISSION_PROVENANCE_MISMATCH"),
      variant.name,
    );
    assert.equal(postResponse.status, 409, variant.name);
    assert.equal(runtime.counts.execute, 0, variant.name);
    assert.equal(runtime.counts.append, 0, variant.name);
  }
});

test("POST rejects a receipt whose revision or event identity does not match the immediate D1 readback", async () => {
  const variants = [
    {
      name: "event identity",
      mutate(receipt) {
        return { ...receipt, eventId: "phantom-event" };
      },
    },
    {
      name: "result revision",
      mutate(receipt) {
        return { ...receipt, revision: 999 };
      },
    },
    {
      name: "output",
      mutate(receipt) {
        return {
          ...receipt,
          output: {
            decision: {
              ...receipt.output.decision,
              decision: "RETURN",
            },
          },
        };
      },
    },
  ];

  for (const variant of variants) {
    const runtime = createRuntimeHarness();
    const live = runtime.createRuntime();
    const handlers = createHandlers({
      createRuntime: () => ({
        control: {
          snapshot: (...args) => live.control.snapshot(...args),
          async execute(...args) {
            return variant.mutate(await live.control.execute(...args));
          },
        },
      }),
    });

    const response = await handlers.POST(
      request("POST", PRODUCT_OWNER, validPostBody()),
    );
    const { body } = await responseEvidence(response);
    const state = await runtime.memory.load(manifest.project_id);

    assert.equal(response.status, 503, variant.name);
    assert.equal(body.code, "READBACK_MISMATCH", variant.name);
    assert.equal(state.revision, 70, variant.name);
    assert.equal(
      state.events.filter(
        ({ type, payload }) =>
          type === "GATE_DECIDED" &&
          payload.submission_id === G0_DECISION_BINDING.submissionId,
      ).length,
      1,
      variant.name,
    );
  }
});

test("POST rejects an immediate readback with an extra or conflicting Decision", async () => {
  const runtime = createRuntimeHarness();
  const live = runtime.createRuntime();
  let snapshotNumber = 0;
  const handlers = createHandlers({
    createRuntime: () => ({
      control: {
        async snapshot(...args) {
          snapshotNumber += 1;
          const snapshot = await live.control.snapshot(...args);
          if (snapshotNumber === 1) return snapshot;
          snapshot.events.push({
            id: "conflicting-decision-event",
            revision: 71,
            type: "GATE_DECIDED",
            actorId: "external_product_owner",
            createdAt: createdAt(71),
            idempotencyKey: "conflicting-decision-key",
            commandHash: `sha256:${"f".repeat(64)}`,
            payload: {
              decision_id: "conflicting-decision",
              submission_id: G0_DECISION_BINDING.submissionId,
              package_hash: G0_DECISION_BINDING.packageHash,
              decision: "RETURN",
              decided_by: "external_product_owner",
              decided_at: createdAt(71),
              accepted_exclusions: [],
              evidence_refs: ["conflicting-decision"],
            },
          });
          snapshot.revision = 71;
          return snapshot;
        },
        execute: (...args) => live.control.execute(...args),
      },
    }),
  });

  const response = await handlers.POST(
    request("POST", PRODUCT_OWNER, validPostBody()),
  );
  const { body } = await responseEvidence(response);
  const state = await runtime.memory.load(manifest.project_id);

  assert.equal(response.status, 503);
  assert.equal(body.code, "ONLINE_D1_INVALID");
  assert.equal(state.revision, 70);
  assert.equal(runtime.counts.append, 1);
});

test("POST rejects Decision execution metadata altered in the immediate D1 readback", async () => {
  const variants = [
    {
      name: "idempotency key",
      mutate(event) {
        event.idempotencyKey = "another-decision-key";
      },
    },
    {
      name: "command hash",
      mutate(event) {
        event.commandHash = `sha256:${"f".repeat(64)}`;
      },
    },
    {
      name: "actor",
      mutate(event) {
        event.actorId = "another-actor";
      },
    },
    {
      name: "evidence",
      mutate(event) {
        event.payload.evidence_refs = ["another-decision-evidence"];
      },
    },
  ];

  for (const variant of variants) {
    const runtime = createRuntimeHarness();
    const live = runtime.createRuntime();
    let snapshotNumber = 0;
    const handlers = createHandlers({
      createRuntime: () => ({
        control: {
          async snapshot(...args) {
            snapshotNumber += 1;
            const snapshot = await live.control.snapshot(...args);
            if (snapshotNumber > 1) {
              variant.mutate(snapshot.events[69]);
            }
            return snapshot;
          },
          execute: (...args) => live.control.execute(...args),
        },
      }),
    });

    const response = await handlers.POST(
      request("POST", PRODUCT_OWNER, validPostBody()),
    );
    const { body } = await responseEvidence(response);
    const state = await runtime.memory.load(manifest.project_id);

    assert.equal(response.status, 503, variant.name);
    assert.equal(body.code, "READBACK_MISMATCH", variant.name);
    assert.equal(state.revision, 70, variant.name);
  }
});

test("the dedicated composition root is GET/POST-only and does not expand progress actions", async () => {
  const [routeSource, moduleSource, progressSource] = await Promise.all([
    readFile(ROUTE_URL, "utf8"),
    readFile(MODULE_URL, "utf8"),
    readFile(PROGRESS_ROUTE_URL, "utf8"),
  ]);
  const routeMethods = [
    ...routeSource.matchAll(
      /export (?:async function|const) (GET|POST|PUT|PATCH|DELETE)\b/g,
    ),
  ].map((match) => match[1]);
  const progressActions = [
    ...progressSource.matchAll(/payload\.action === "([^"]+)"/g),
  ]
    .map((match) => match[1])
    .sort();

  assert.deepEqual(routeMethods.sort(), ["GET", "POST"]);
  assert.match(routeSource, /createD1GovernanceJournal/);
  assert.match(routeSource, /createProjectControl/);
  assert.doesNotMatch(
    `${routeSource}\n${moduleSource}`,
    /ensureDatabase|seedIfNeeded|APPROVE_P2_ACCEPTANCE_PROFILE|AUTHORIZE_P2_WORK_PACKAGE_START|REVOKE_P2_WORK_PACKAGE_START_AUTHORIZATION/,
  );
  assert.doesNotMatch(moduleSource, /journal\.append\s*\(/);
  assert.deepEqual(progressActions, [
    "decide_gate",
    "submit_gate",
    "update_connector",
    "update_task",
    "validate_human_baseline",
  ]);
});

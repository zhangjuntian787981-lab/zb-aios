import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import {
  readFile,
  readdir,
} from "node:fs/promises";
import { join, relative } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import catalog from "../implementation/governance/p0-frozen-evidence-index.v1.json" with { type: "json" };
import manifest from "../implementation/governance/work-package-manifest.v1.json" with { type: "json" };
import {
  G0_REMEDIATION_BUILD_BINDING,
  G0_REMEDIATION_CONFIRMATION,
  createG0RemediationHandlers,
  verifyG0RemediationFrozenCatalog,
} from "../lib/g0-remediation.mjs";
import { createFrozenEvidenceVerifier } from "../lib/frozen-evidence.mjs";
import {
  createMemoryJournal,
  createProjectControl,
  sha256ProjectValue,
} from "../lib/project-control.mjs";

const PRODUCT_OWNER = "product-owner@example.test";
const ROUTE_ORIGIN = "https://example.test";
const REPOSITORY_ROOT = new URL("../", import.meta.url).pathname;
const ROUTE_URL = new URL(
  "../app/api/governance/g0-remediation/route.ts",
  import.meta.url,
);
const PROGRESS_ROUTE_URL = new URL(
  "../app/api/progress/route.ts",
  import.meta.url,
);
const READINESS_ROUTE_URL = new URL(
  "../app/api/governance/p2-readiness/route.ts",
  import.meta.url,
);
const OLD_SUBMISSION_ID = "06531499-9cc4-4b09-b0c4-1f6d18e36fd6";
const OLD_PACKAGE_HASH =
  "sha256:77d8707a602a83729b557c028bd6cf87c5a0e5d921145b9dc3a5a1e79bf32a07";
const EXPECTED_SCOPE_DIGEST =
  "sha256:e3cb5c88f21492200d30841010be4b738eca952309dbafdc66c96100b1e80b0f";
const EXPECTED_PACKAGE_HASH =
  "sha256:d4e449a305a6f496e24fb777d1d883d8c02f0d7e3165d00fc90561c1d14421b0";
const EXPECTED_PLAN_DIGEST =
  "sha256:fd41d6344169ca4c7a4904dae9a33d38cbc5546b501c2abd244678461a57da1c";
const OLD_F04_ENGINEERING_HASH =
  "sha256:851851fcec6d961efaf17f6a0ced172c12dad2dced6746c9c9b805a205c95f62";
const HUMAN_F04_HASH =
  "sha256:1ac738d40ed6fb0bdaadb876c92b4f3cbde0d722142093bb786447365c9c5de0";
const FIXED_NOW = "2026-07-29T02:00:00.000Z";
const execFileAsync = promisify(execFile);
const SYNTHETIC_REFERENCE_REVIEW_POLICY = Object.freeze({
  schemaVersion: "reference-review-policy.v1",
  profileBinding: Object.freeze({
    profileSha256: `sha256:${"d".repeat(64)}`,
    sourceCommit: "8".repeat(40),
    executionBaselineDigest: `sha256:${"8".repeat(64)}`,
  }),
});
const verifySyntheticP0ReferenceReview = async (binding) =>
  binding?.boundary === "IMPLEMENTATION_CONFORMANCE" &&
  ["F01", "F02", "F03", "F04"].includes(binding.workPackageId) &&
  binding.profileSha256 ===
    SYNTHETIC_REFERENCE_REVIEW_POLICY.profileBinding.profileSha256 &&
  binding.sourceCommit ===
    SYNTHETIC_REFERENCE_REVIEW_POLICY.profileBinding.sourceCommit &&
  binding.executionBaselineDigest ===
    SYNTHETIC_REFERENCE_REVIEW_POLICY.profileBinding
      .executionBaselineDigest;

function request(
  method = "GET",
  actor = null,
  body = undefined,
  suffix = "",
  headerOverrides = {},
) {
  const headers = new Headers();
  if (actor) headers.set("oai-authenticated-user-email", actor);
  if (body !== undefined) {
    headers.set("content-type", "application/json");
    headers.set("origin", ROUTE_ORIGIN);
    headers.set("sec-fetch-site", "same-origin");
  }
  for (const [name, value] of Object.entries(headerOverrides)) {
    if (value === null) {
      headers.delete(name);
    } else {
      headers.set(name, value);
    }
  }
  return new Request(
    `${ROUTE_ORIGIN}/api/governance/g0-remediation${suffix}`,
    {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    },
  );
}

function mutationGuardProbeRequest({
  origin = ROUTE_ORIGIN,
  secFetchSite = "same-origin",
  contentType = "application/json",
} = {}) {
  const counts = {
    bodyRead: 0,
    jsonRead: 0,
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
  const trackedRequest = {
    url: `${ROUTE_ORIGIN}/api/governance/g0-remediation`,
    headers,
    async text() {
      counts.bodyRead += 1;
      return JSON.stringify(
        validPostBody({ planDigest: EXPECTED_PLAN_DIGEST }),
      );
    },
    async json() {
      counts.jsonRead += 1;
      return validPostBody({ planDigest: EXPECTED_PLAN_DIGEST });
    },
  };
  const createRuntime = () => {
    counts.createRuntime += 1;
    return {
      journal: {
        async load() {
          counts.journalLoad += 1;
          throw new Error("Mutation guard probe reached journal.load.");
        },
        async append() {
          counts.journalAppend += 1;
          throw new Error("Mutation guard probe reached journal.append.");
        },
      },
      control: {
        async snapshot() {
          throw new Error("Mutation guard probe reached control.snapshot.");
        },
        async execute() {
          counts.controlExecute += 1;
          throw new Error("Mutation guard probe reached control.execute.");
        },
      },
    };
  };
  return { request: trackedRequest, counts, createRuntime };
}

function createHandlers(overrides = {}) {
  return createG0RemediationHandlers({
    configuredProductOwner: () => PRODUCT_OWNER,
    isProductOwner: (actor, configured) =>
      actor.trim().toLowerCase() === configured.trim().toLowerCase(),
    createRuntime: () => {
      throw new Error("D1 must not be read before authentication.");
    },
    manifest,
    catalog,
    buildBinding: G0_REMEDIATION_BUILD_BINDING,
    clock: () => FIXED_NOW,
    ...overrides,
  });
}

function createTrustedSyntheticHandlers(overrides = {}) {
  return createHandlers({
    referenceReviewPolicy: SYNTHETIC_REFERENCE_REVIEW_POLICY,
    verifyReferenceReviewReadiness:
      verifySyntheticP0ReferenceReview,
    ...overrides,
  });
}

function createdAt(revision) {
  return new Date(
    Date.UTC(2026, 6, 28, 18, 0, revision),
  ).toISOString();
}

function recordFor(workPackageId) {
  return catalog.records.find(
    (record) => record.workPackageId === workPackageId,
  );
}

function oldScope() {
  return ["F01", "F02", "F03", "F04"].map((workPackageId) => {
    const record = recordFor(workPackageId);
    return {
      work_package_id: workPackageId,
      applicability: "REQUIRED",
      implementation_status: "IMPLEMENTED",
      verification_status: "VERIFIED",
      evidence_refs: [...record.evidenceRefs],
      evidence_hashes:
        workPackageId === "F04"
          ? [OLD_F04_ENGINEERING_HASH, HUMAN_F04_HASH]
          : [...record.evidenceHashes],
    };
  });
}

function baseEvents() {
  const f04 = recordFor("F04");
  const events = [
    {
      id: "historical-f04-authoritative-human-validation",
      revision: 1,
      type: "WORK_PACKAGE_RECORDED",
      actorId: "external_product_owner",
      idempotencyKey: "historical-f04-authority",
      commandHash:
        "sha256:c44c90ae815c5710cf4a08e42fac4a907e0f513b566800ffa00945a1dacc6f63",
      createdAt: createdAt(1),
      payload: {
        workPackageId: "F04",
        implementationStatus: "IMPLEMENTED",
        verificationStatus: "VERIFIED",
        evidenceRefs: [...f04.evidenceRefs],
        evidenceHashes: [OLD_F04_ENGINEERING_HASH, HUMAN_F04_HASH],
        note:
          `外部产品所有者确认十项 F04 人工基线：${HUMAN_F04_HASH}`,
      },
    },
    {
      id: "historical-g0-submission",
      revision: 2,
      type: "GATE_SUBMITTED",
      actorId: "external_product_owner",
      idempotencyKey: "historical-g0-submission-key",
      commandHash:
        "sha256:33b12d1bb8ec888d6281990f5e7074a01e63c8184476327575b41a55e0c73fed",
      createdAt: createdAt(2),
      payload: {
        gate_id: "G0",
        submission_id: OLD_SUBMISSION_ID,
        package_hash: OLD_PACKAGE_HASH,
        submitted_at: createdAt(2),
        submitted_by: "external_product_owner",
        source_revision: 1,
        work_package_scope: oldScope(),
        evidence_refs: catalog.records.flatMap(
          (record) => record.evidenceRefs,
        ),
        supersedes: null,
      },
    },
    {
      id: "historical-g0-decision",
      revision: 3,
      type: "GATE_DECIDED",
      actorId: "external_product_owner",
      idempotencyKey: "historical-g0-decision-key",
      commandHash:
        "sha256:1bb673053a42acc87a336e1b0f5c4d2091bc5e8f0381712ad2cdc5808db7cf33",
      createdAt: createdAt(3),
      payload: {
        decision_id: "historical-g0-decision-id",
        submission_id: OLD_SUBMISSION_ID,
        package_hash: OLD_PACKAGE_HASH,
        decision: "APPROVE",
        decided_by: "external_product_owner",
        decided_at: createdAt(3),
        accepted_exclusions: [],
        evidence_refs: [
          `product-owner-decision:${OLD_SUBMISSION_ID}:${OLD_PACKAGE_HASH}`,
        ],
      },
    },
  ];
  for (let revision = 4; revision <= 64; revision += 1) {
    events.push({
      id: `unrelated-governance-event-${revision}`,
      revision,
      type: "PLAN_BASELINE_APPROVED",
      actorId: "external_product_owner",
      createdAt: createdAt(revision),
      payload: {
        baseline: `unrelated-${revision}`,
      },
    });
  }
  return events;
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
              `Concurrent POST barrier timed out at ${arrivals}/2 arrivals.`,
            ),
          );
        }, timeoutMilliseconds);
      }
      if (arrivals > 2) {
        throw new Error("Concurrent POST barrier received too many arrivals.");
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

function createRuntimeHarness({
  events = baseEvents(),
  failAppendAt = null,
  verifier = createFrozenEvidenceVerifier(catalog),
  forceG0NotReadyAtRevision68 = false,
  beforeAppend = null,
} = {}) {
  const memory = createMemoryJournal(events);
  const counts = {
    createRuntime: 0,
    load: 0,
    append: 0,
    readback: 0,
  };
  let failAt = failAppendAt;
  const journal = {
    async load(...arguments_) {
      counts.load += 1;
      return memory.load(...arguments_);
    },
    async append(...arguments_) {
      counts.append += 1;
      if (beforeAppend) {
        await beforeAppend({ appendNumber: counts.append });
      }
      if (counts.append === failAt) {
        failAt = null;
        throw Object.assign(new Error("Synthetic append interruption."), {
          code: "STORE_UNAVAILABLE",
        });
      }
      return memory.append(...arguments_);
    },
  };
  const baseControl = createProjectControl({
    manifest,
    journal,
    verifyFrozenEvidence: verifier,
    referenceReviewPolicy: SYNTHETIC_REFERENCE_REVIEW_POLICY,
    verifyReferenceReviewReadiness:
      verifySyntheticP0ReferenceReview,
    clock: (() => {
      let tick = 0;
      return () =>
        new Date(
          Date.parse("2026-07-29T02:10:00.000Z") + tick++,
        ).toISOString();
    })(),
    idFactory: (() => {
      let id = 0;
      return () => `server-generated-id-${++id}`;
    })(),
  });
  const control = {
    execute: (...arguments_) => baseControl.execute(...arguments_),
    async snapshot() {
      const snapshot = await baseControl.snapshot();
      if (
        forceG0NotReadyAtRevision68 &&
        snapshot.revision === 68
      ) {
        snapshot.gates.find(({ id }) => id === "G0").status =
          "STALE_SUBMISSION";
      }
      return snapshot;
    },
  };
  return {
    counts,
    journal,
    memory,
    createRuntime() {
      counts.createRuntime += 1;
      return { journal, control };
    },
    markReadback() {
      counts.readback += 1;
    },
  };
}

function validPostBody(overrides = {}) {
  return {
    expectedRevision: 64,
    planDigest: overrides.planDigest ?? "",
    idempotencyKey: "g0-remediation-20260729-001",
    confirmation: G0_REMEDIATION_CONFIRMATION,
    ...overrides,
  };
}

async function responseBytes(response) {
  return Buffer.from(await response.clone().arrayBuffer());
}

async function assertResponseEvidence(response) {
  const bytes = await responseBytes(response);
  const sha256Hex = createHash("sha256").update(bytes).digest("hex");
  const sha256Base64 = createHash("sha256").update(bytes).digest("base64");
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
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.ok(bytes.byteLength < 16 * 1024);
  return JSON.parse(bytes.toString("utf8"));
}

async function preview(handlers) {
  const response = await handlers.GET(request("GET", PRODUCT_OWNER));
  assert.equal(
    response.status,
    200,
    JSON.stringify(await response.clone().json()),
  );
  return {
    response,
    body: await assertResponseEvidence(response),
  };
}

test("G0 remediation requires an authenticated Product Owner", async () => {
  let runtimeCalls = 0;
  const { GET } = createHandlers({
    createRuntime: () => {
      runtimeCalls += 1;
      throw new Error("D1 must not be read before authentication.");
    },
  });

  const response = await GET(request());

  assert.equal(response.status, 401);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(runtimeCalls, 0);
  assert.deepEqual(await response.json(), {
    schemaVersion: "g0-remediation-error.v1",
    code: "AUTHENTICATION_REQUIRED",
    error: "需要先通过工作区身份验证。",
  });
});

test("G0 remediation fails closed when the Product Owner is not configured", async () => {
  let runtimeCalls = 0;
  const { GET } = createHandlers({
    configuredProductOwner: () => undefined,
    createRuntime: () => {
      runtimeCalls += 1;
    },
  });

  const response = await GET(request("GET", PRODUCT_OWNER));

  assert.equal(response.status, 503);
  assert.equal(runtimeCalls, 0);
  assert.deepEqual(await response.json(), {
    schemaVersion: "g0-remediation-error.v1",
    code: "PRODUCT_OWNER_NOT_CONFIGURED",
    error: "产品所有者身份尚未配置。",
  });
});

test("G0 remediation rejects a non-Product Owner", async () => {
  let runtimeCalls = 0;
  const { GET } = createHandlers({
    createRuntime: () => {
      runtimeCalls += 1;
    },
  });

  const response = await GET(
    request("GET", "another-user@example.test"),
  );

  assert.equal(response.status, 403);
  assert.equal(runtimeCalls, 0);
  assert.deepEqual(await response.json(), {
    schemaVersion: "g0-remediation-error.v1",
    code: "PRODUCT_OWNER_REQUIRED",
    error: "只有外部产品所有者可以使用 G0 整改通道。",
  });
});

test("POST rejects every non-same-origin mutation before reading the body or governance state", async (t) => {
  const cases = [
    {
      name: "missing Origin",
      options: { origin: null },
    },
    {
      name: "invalid Origin",
      options: { origin: "not a valid origin" },
    },
    {
      name: "mismatched Origin",
      options: { origin: "https://attacker.example" },
    },
    {
      name: "non-exact Origin with a trailing slash",
      options: { origin: `${ROUTE_ORIGIN}/` },
    },
    {
      name: "missing Sec-Fetch-Site",
      options: { secFetchSite: null },
    },
    {
      name: "cross-site",
      options: { secFetchSite: "cross-site" },
    },
    {
      name: "same-site",
      options: { secFetchSite: "same-site" },
    },
    {
      name: "none",
      options: { secFetchSite: "none" },
    },
    {
      name: "unknown fetch site",
      options: { secFetchSite: "unexpected" },
    },
    {
      name: "case-variant fetch site",
      options: { secFetchSite: "Same-Origin" },
    },
  ];

  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      const probe = mutationGuardProbeRequest(testCase.options);
      const handlers = createHandlers({
        createRuntime: probe.createRuntime,
      });

      const response = await handlers.POST(probe.request);
      const body = await assertResponseEvidence(response);

      assert.equal(response.status, 403);
      assert.deepEqual(body, {
        schemaVersion: "g0-remediation-error.v1",
        code: "CROSS_SITE_REQUEST_FORBIDDEN",
        error: "POST 必须来自当前应用的同源页面。",
      });
      assert.deepEqual(probe.counts, {
        bodyRead: 0,
        jsonRead: 0,
        createRuntime: 0,
        journalLoad: 0,
        journalAppend: 0,
        controlExecute: 0,
      });
    });
  }
});

test("POST rejects every unsupported JSON media type before reading the body or governance state", async (t) => {
  const cases = [
    { name: "missing Content-Type", contentType: null },
    { name: "JSONP", contentType: "application/jsonp" },
    {
      name: "JSON Patch",
      contentType: "application/json-patch+json",
    },
    { name: "plain text", contentType: "text/plain" },
    {
      name: "form",
      contentType: "application/x-www-form-urlencoded",
    },
    {
      name: "multipart",
      contentType: "multipart/form-data; boundary=example",
    },
    {
      name: "non-UTF-8 charset",
      contentType: "application/json; charset=iso-8859-1",
    },
    {
      name: "duplicate charset",
      contentType:
        "application/json; charset=utf-8; charset=utf-8",
    },
    {
      name: "malformed charset",
      contentType: "application/json; charset",
    },
    {
      name: "empty charset",
      contentType: "application/json; charset=",
    },
    {
      name: "quoted charset",
      contentType: 'application/json; charset="utf-8"',
    },
    {
      name: "trailing separator",
      contentType: "application/json; charset=utf-8;",
    },
    {
      name: "combined duplicate header value",
      contentType:
        "application/json; charset=utf-8, application/json",
    },
    {
      name: "unknown parameter",
      contentType: "application/json; profile=example",
    },
  ];

  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      const probe = mutationGuardProbeRequest({
        contentType: testCase.contentType,
      });
      const handlers = createHandlers({
        createRuntime: probe.createRuntime,
      });

      const response = await handlers.POST(probe.request);
      const body = await assertResponseEvidence(response);

      assert.equal(response.status, 400);
      assert.equal(body.code, "INVALID_REQUEST");
      assert.deepEqual(probe.counts, {
        bodyRead: 0,
        jsonRead: 0,
        createRuntime: 0,
        journalLoad: 0,
        journalAppend: 0,
        controlExecute: 0,
      });
    });
  }
});

test("POST accepts exact JSON media types with HTTP case normalization", async (t) => {
  for (const contentType of [
    "application/json",
    "application/json; charset=utf-8",
    "Application/JSON; Charset=UTF-8",
  ]) {
    await t.test(contentType, async () => {
      const runtime = createRuntimeHarness();
      const handlers = createTrustedSyntheticHandlers({
        createRuntime: runtime.createRuntime,
      });
      const { body: plan } = await preview(handlers);

      const response = await handlers.POST(
        request(
          "POST",
          PRODUCT_OWNER,
          validPostBody({ planDigest: plan.planDigest }),
          "",
          { "content-type": contentType },
        ),
      );

      assert.equal(response.status, 200);
      assert.equal((await response.json()).status, "COMPLETED");
    });
  }
});

test("GET rejects every query parameter before reading D1", async () => {
  const runtime = createRuntimeHarness();
  const { GET } = createHandlers({
    createRuntime: runtime.createRuntime,
  });

  const response = await GET(
    request("GET", PRODUCT_OWNER, undefined, "?revision=64"),
  );

  assert.equal(response.status, 400);
  assert.equal(runtime.counts.createRuntime, 0);
  assert.equal(runtime.counts.append, 0);
  assert.equal((await response.json()).code, "QUERY_PARAMETERS_FORBIDDEN");
});

test("GET returns the fixed revision-64 remediation plan without writing D1", async () => {
  const runtime = createRuntimeHarness();
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });

  const { body } = await preview(handlers);

  assert.deepEqual(
    Object.keys(body).sort(),
    [
      "blockers",
      "canExecute",
      "frozenEvidenceIndexSha256",
      "g0Status",
      "packageHash",
      "planDigest",
      "revision",
      "schemaVersion",
      "scopeDigest",
      "serverTime",
      "source",
      "sourceCommit",
      "steps",
      "tree",
      "workPackages",
    ].sort(),
  );
  assert.equal(body.schemaVersion, "g0-remediation-preview.v1");
  assert.equal(
    body.source,
    "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER",
  );
  assert.equal(body.revision, 64);
  assert.equal(body.g0Status, "STALE_SUBMISSION");
  assert.equal(body.scopeDigest, EXPECTED_SCOPE_DIGEST);
  assert.equal(body.packageHash, EXPECTED_PACKAGE_HASH);
  assert.equal(body.planDigest, EXPECTED_PLAN_DIGEST);
  assert.equal(
    body.sourceCommit,
    "4e9867875f00eb7c35efa8fbe7c76a0146deeda7",
  );
  assert.equal(
    body.tree,
    "288172a3e49636c4f45ec999114dcc6d35126de7",
  );
  assert.equal(
    body.frozenEvidenceIndexSha256,
    "sha256:9d7c7d37279d2c24ff97f9bbea42ff2adc935dbd10be30ea504552c53c8b9aa8",
  );
  assert.equal(body.canExecute, true);
  assert.deepEqual(body.blockers, []);
  assert.deepEqual(
    body.steps.map(
      ({ position, kind, workPackageId, gateId, expectedRevision, resultRevision }) => ({
        position,
        kind,
        workPackageId,
        gateId,
        expectedRevision,
        resultRevision,
      }),
    ),
    [
      {
        position: 1,
        kind: "RECORD_WORK_PACKAGE",
        workPackageId: "F01",
        gateId: null,
        expectedRevision: 64,
        resultRevision: 65,
      },
      {
        position: 2,
        kind: "RECORD_WORK_PACKAGE",
        workPackageId: "F02",
        gateId: null,
        expectedRevision: 65,
        resultRevision: 66,
      },
      {
        position: 3,
        kind: "RECORD_WORK_PACKAGE",
        workPackageId: "F03",
        gateId: null,
        expectedRevision: 66,
        resultRevision: 67,
      },
      {
        position: 4,
        kind: "RECORD_WORK_PACKAGE",
        workPackageId: "F04",
        gateId: null,
        expectedRevision: 67,
        resultRevision: 68,
      },
      {
        position: 5,
        kind: "SUBMIT_GATE",
        workPackageId: null,
        gateId: "G0",
        expectedRevision: 68,
        resultRevision: 69,
      },
    ],
  );
  assert.deepEqual(body.workPackages, {
    F01: {
      implementationStatus: "NOT_STARTED",
      verificationStatus: "NOT_VERIFIED",
    },
    F02: {
      implementationStatus: "NOT_STARTED",
      verificationStatus: "NOT_VERIFIED",
    },
    F03: {
      implementationStatus: "NOT_STARTED",
      verificationStatus: "NOT_VERIFIED",
    },
    F04: {
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
    },
  });
  assert.equal(runtime.counts.append, 0);
});

test("GET fails closed when the frozen catalog binding is changed", async () => {
  const runtime = createRuntimeHarness();
  const changedCatalog = structuredClone(catalog);
  changedCatalog.records[0].evidenceHashes[0] =
    `sha256:${"f".repeat(64)}`;
  const handlers = createHandlers({
    catalog: changedCatalog,
    createRuntime: runtime.createRuntime,
  });

  const response = await handlers.GET(request("GET", PRODUCT_OWNER));

  assert.equal(response.status, 503);
  assert.equal((await response.json()).code, "FROZEN_CATALOG_MISMATCH");
  assert.equal(runtime.counts.append, 0);
});

test("GET keeps planDigest deterministic across server time changes", async () => {
  const runtime = createRuntimeHarness();
  const first = createHandlers({
    createRuntime: runtime.createRuntime,
    clock: () => "2026-07-29T02:00:00.000Z",
  });
  const second = createHandlers({
    createRuntime: runtime.createRuntime,
    clock: () => "2026-07-29T03:00:00.000Z",
  });

  const firstBody = (await preview(first)).body;
  const secondBody = (await preview(second)).body;

  assert.equal(firstBody.planDigest, EXPECTED_PLAN_DIGEST);
  assert.equal(secondBody.planDigest, EXPECTED_PLAN_DIGEST);
  assert.notEqual(firstBody.serverTime, secondBody.serverTime);
});

test("GET fails closed unless F04 human authority is the exact revision-1 D1 record", async () => {
  for (const mutate of [
    (events) => {
      events[0].type = "PLAN_BASELINE_APPROVED";
    },
    (events) => {
      events[0].payload.verificationStatus = "NOT_VERIFIED";
    },
    (events) => {
      events[0].payload.evidenceHashes = [OLD_F04_ENGINEERING_HASH];
    },
    (events) => {
      events[0].actorId = "untrusted_actor";
    },
    (events) => {
      events[0].commandHash = `sha256:${"f".repeat(64)}`;
    },
  ]) {
    const events = baseEvents();
    mutate(events);
    const runtime = createRuntimeHarness({ events });
    const handlers = createHandlers({
      createRuntime: runtime.createRuntime,
    });

    const response = await handlers.GET(request("GET", PRODUCT_OWNER));

    assert.equal(response.status, 503);
    assert.equal(
      (await response.json()).code,
      "F04_HUMAN_AUTHORITY_UNPROVEN",
    );
    assert.equal(runtime.counts.append, 0);
  }
});

test("GET preserves the historical G0 base-scope error for a later duplicate F04 event", async () => {
  const events = baseEvents();
  const duplicate = structuredClone(events[0]);
  duplicate.id = "later-duplicate-f04-authority";
  duplicate.revision = 4;
  duplicate.idempotencyKey = "later-duplicate-f04-authority";
  duplicate.createdAt = createdAt(4);
  duplicate.commandHash = await sha256ProjectValue({
    actorId: duplicate.actorId,
    command: {
      kind: "RECORD_WORK_PACKAGE",
      workPackageId: "F04",
      implementationStatus: duplicate.payload.implementationStatus,
      verificationStatus: duplicate.payload.verificationStatus,
      evidenceRefs: duplicate.payload.evidenceRefs,
      evidenceHashes: duplicate.payload.evidenceHashes,
      note: duplicate.payload.note,
      expectedRevision: 3,
      idempotencyKey: duplicate.idempotencyKey,
    },
  });
  events[3] = duplicate;
  const runtime = createRuntimeHarness({ events });
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });

  const response = await handlers.GET(request("GET", PRODUCT_OWNER));

  assert.equal(response.status, 409);
  assert.equal((await response.json()).code, "G0_BASE_SCOPE_MISMATCH");
  assert.equal(runtime.counts.append, 0);
});

test("GET preserves the historical G0 base-scope error for a later duplicate old G0 Submission", async () => {
  const events = baseEvents();
  const duplicate = structuredClone(events[1]);
  duplicate.id = "later-duplicate-old-g0-submission";
  duplicate.revision = 4;
  duplicate.idempotencyKey = "later-duplicate-old-g0-submission";
  duplicate.createdAt = createdAt(4);
  events[3] = duplicate;
  const runtime = createRuntimeHarness({ events });
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });

  const response = await handlers.GET(request("GET", PRODUCT_OWNER));

  assert.equal(response.status, 409);
  assert.equal((await response.json()).code, "G0_BASE_SCOPE_MISMATCH");
  assert.equal(runtime.counts.append, 0);
});

test("D1 failures return a bounded 503 without exposing storage details", async () => {
  const handlers = createHandlers({
    createRuntime: () => {
      throw Object.assign(
        new Error("secret database table governance_events failed"),
        { code: "D1_INTERNAL_ERROR" },
      );
    },
  });

  const response = await handlers.GET(request("GET", PRODUCT_OWNER));
  const text = await response.text();

  assert.equal(response.status, 503);
  assert.doesNotMatch(text, /secret|database|governance_events/i);
  assert.match(text, /G0_REMEDIATION_UNAVAILABLE/);
});

test("POST rejects query parameters and unknown or caller-owned governance fields", async () => {
  const runtime = createRuntimeHarness();
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });
  const { body: plan } = await preview(handlers);
  const forbiddenFields = [
    "evidenceRefs",
    "evidenceHashes",
    "implementationStatus",
    "verificationStatus",
    "packageHash",
    "workPackageScope",
    "actorId",
    "command",
    "event",
    "decision",
    "tenant",
    "profile",
    "workPackageStatus",
    "ready",
    "referenceCatalog",
    "referencePolicy",
    "referenceReceipt",
    "referenceReviewBundle",
    "referenceReviewHash",
  ];

  const queryResponse = await handlers.POST(
    request(
      "POST",
      PRODUCT_OWNER,
      validPostBody({ planDigest: plan.planDigest }),
      "?gate=G0",
    ),
  );
  assert.equal(queryResponse.status, 400);
  assert.equal(
    (await queryResponse.json()).code,
    "QUERY_PARAMETERS_FORBIDDEN",
  );

  for (const field of forbiddenFields) {
    const response = await handlers.POST(
      request(
        "POST",
        PRODUCT_OWNER,
        validPostBody({
          planDigest: plan.planDigest,
          [field]: "caller-controlled",
        }),
      ),
    );
    assert.equal(response.status, 400, field);
    assert.equal((await response.json()).code, "INVALID_REQUEST", field);
  }
  assert.equal(runtime.counts.append, 0);
});

test("POST rejects revision, plan digest, scope, catalog, and package drift before the first write", async () => {
  const baseRuntime = createRuntimeHarness();
  const baseHandlers = createHandlers({
    createRuntime: baseRuntime.createRuntime,
  });
  const { body: plan } = await preview(baseHandlers);

  const driftCases = [
    {
      name: "revision",
      body: validPostBody({
        expectedRevision: 63,
        planDigest: plan.planDigest,
      }),
      expectedCode: "EXPECTED_REVISION_MISMATCH",
    },
    {
      name: "plan",
      body: validPostBody({
        planDigest: `sha256:${"0".repeat(64)}`,
      }),
      expectedCode: "PLAN_DIGEST_MISMATCH",
    },
  ];
  for (const item of driftCases) {
    const runtime = createRuntimeHarness();
    const handlers = createHandlers({
      createRuntime: runtime.createRuntime,
    });
    const response = await handlers.POST(
      request("POST", PRODUCT_OWNER, item.body),
    );
    assert.equal(response.status, 409, item.name);
    assert.equal((await response.json()).code, item.expectedCode, item.name);
    assert.equal(runtime.counts.append, 0, item.name);
  }

  for (const [name, mutate] of [
    [
      "scope",
      (changedManifest) => {
        changedManifest.work_packages.find(
          ({ id }) => id === "F01",
        ).applicability = "OPTIONAL";
      },
    ],
    [
      "package",
      (changedManifest) => {
        changedManifest.manifest_version = "1.0.1";
      },
    ],
  ]) {
    const changedManifest = structuredClone(manifest);
    mutate(changedManifest);
    const runtime = createRuntimeHarness();
    const handlers = createHandlers({
      manifest: changedManifest,
      createRuntime: runtime.createRuntime,
    });
    const response = await handlers.POST(
      request(
        "POST",
        PRODUCT_OWNER,
        validPostBody({ planDigest: plan.planDigest }),
      ),
    );
    assert.equal(response.status, 503, name);
    assert.match(
      (await response.json()).code,
      /SCOPE_MISMATCH|PACKAGE_HASH_MISMATCH|MANIFEST_MISMATCH/,
      name,
    );
    assert.equal(runtime.counts.append, 0, name);
  }
});

test("POST fails closed before the first write without server-owned Reference Review prerequisites", async () => {
  const runtime = createRuntimeHarness();
  const handlers = createHandlers({
    createRuntime: runtime.createRuntime,
  });
  const { body: plan } = await preview(handlers);

  const response = await handlers.POST(
    request(
      "POST",
      PRODUCT_OWNER,
      validPostBody({ planDigest: plan.planDigest }),
    ),
  );
  const body = await assertResponseEvidence(response);

  assert.equal(response.status, 409);
  assert.equal(body.code, "REFERENCE_REVIEW_NOT_PROVED");
  assert.equal(runtime.counts.append, 0);
  assert.equal((await runtime.memory.load(manifest.project_id)).revision, 64);
});

test("POST performs exactly four work-package records and one G0 submission with readback after every append", async () => {
  const runtime = createRuntimeHarness();
  const handlers = createTrustedSyntheticHandlers({
    createRuntime: runtime.createRuntime,
    onReadback: runtime.markReadback,
  });
  const { body: plan } = await preview(handlers);

  const response = await handlers.POST(
    request(
      "POST",
      PRODUCT_OWNER,
      validPostBody({ planDigest: plan.planDigest }),
    ),
  );
  const body = await assertResponseEvidence(response);
  const state = await runtime.memory.load(manifest.project_id);
  const appended = state.events.slice(64);

  assert.equal(response.status, 200, JSON.stringify(body));
  assert.equal(body.status, "COMPLETED");
  assert.equal(body.revision, 69);
  assert.equal(body.appendedCount, 5);
  assert.equal(body.duplicateCount, 0);
  assert.deepEqual(
    appended.map(({ type }) => type),
    [
      "WORK_PACKAGE_RECORDED",
      "WORK_PACKAGE_RECORDED",
      "WORK_PACKAGE_RECORDED",
      "WORK_PACKAGE_RECORDED",
      "GATE_SUBMITTED",
    ],
  );
  assert.deepEqual(
    appended.slice(0, 4).map(({ payload }) => payload.workPackageId),
    ["F01", "F02", "F03", "F04"],
  );
  assert.match(
    appended[3].payload.note,
    /online D1 revision 1/,
  );
  assert.match(
    appended[3].payload.note,
    new RegExp(HUMAN_F04_HASH),
  );
  assert.equal(
    appended.some(({ type }) => type === "GATE_DECIDED"),
    false,
  );
  assert.equal(runtime.counts.append, 5);
  assert.equal(runtime.counts.readback, 5);
  const submission = appended[4];
  assert.equal(submission.payload.gate_id, "G0");
  assert.equal(submission.payload.source_revision, 68);
  assert.equal(submission.payload.package_hash, EXPECTED_PACKAGE_HASH);
  assert.equal(submission.payload.supersedes, OLD_SUBMISSION_ID);
});

test("POST cannot submit G0 before the projection becomes READY_TO_SUBMIT", async () => {
  const runtime = createRuntimeHarness({
    forceG0NotReadyAtRevision68: true,
  });
  const handlers = createTrustedSyntheticHandlers({
    createRuntime: runtime.createRuntime,
  });
  const { body: plan } = await preview(handlers);

  const response = await handlers.POST(
    request(
      "POST",
      PRODUCT_OWNER,
      validPostBody({ planDigest: plan.planDigest }),
    ),
  );

  assert.equal(response.status, 409);
  assert.equal((await response.json()).code, "G0_NOT_READY_TO_SUBMIT");
  const state = await runtime.memory.load(manifest.project_id);
  assert.equal(state.revision, 68);
  assert.equal(
    state.events.some(
      ({ type, revision }) =>
        type === "GATE_SUBMITTED" && revision > 64,
    ),
    false,
  );
});

test("an interrupted execution safely resumes the exact completed prefix without rollback or duplicate events", async () => {
  const runtime = createRuntimeHarness({ failAppendAt: 3 });
  const handlers = createTrustedSyntheticHandlers({
    createRuntime: runtime.createRuntime,
    onReadback: runtime.markReadback,
  });
  const { body: plan } = await preview(handlers);
  const postRequest = () =>
    request(
      "POST",
      PRODUCT_OWNER,
      validPostBody({ planDigest: plan.planDigest }),
    );

  const interrupted = await handlers.POST(postRequest());
  assert.equal(interrupted.status, 503);
  assert.equal((await interrupted.json()).code, "EXECUTION_INTERRUPTED");
  let state = await runtime.memory.load(manifest.project_id);
  assert.equal(state.revision, 66);
  assert.deepEqual(
    state.events.slice(64).map(({ payload }) => payload.workPackageId),
    ["F01", "F02"],
  );

  const resumed = await handlers.POST(postRequest());
  const body = await assertResponseEvidence(resumed);
  state = await runtime.memory.load(manifest.project_id);

  assert.equal(resumed.status, 200);
  assert.equal(body.status, "COMPLETED");
  assert.equal(body.revision, 69);
  assert.equal(body.appendedCount, 3);
  assert.equal(body.duplicateCount, 2);
  assert.equal(state.events.length, 69);
  assert.deepEqual(
    state.events.slice(64).map(({ revision }) => revision),
    [65, 66, 67, 68, 69],
  );
  assert.equal(
    state.events.some(({ type }) => type === "ROLLBACK"),
    false,
  );

  const repeated = await handlers.POST(postRequest());
  const repeatedBody = await assertResponseEvidence(repeated);
  state = await runtime.memory.load(manifest.project_id);

  assert.equal(repeated.status, 200);
  assert.equal(repeatedBody.appendedCount, 0);
  assert.equal(repeatedBody.duplicateCount, 5);
  assert.equal(state.revision, 69);
});

test("a changed idempotency key cannot claim or overwrite an existing remediation prefix", async () => {
  const runtime = createRuntimeHarness({ failAppendAt: 2 });
  const handlers = createTrustedSyntheticHandlers({
    createRuntime: runtime.createRuntime,
  });
  const { body: plan } = await preview(handlers);

  await handlers.POST(
    request(
      "POST",
      PRODUCT_OWNER,
      validPostBody({ planDigest: plan.planDigest }),
    ),
  );
  const response = await handlers.POST(
    request(
      "POST",
      PRODUCT_OWNER,
      validPostBody({
        planDigest: plan.planDigest,
        idempotencyKey: "g0-remediation-20260729-different",
      }),
    ),
  );

  assert.equal(response.status, 409);
  assert.equal((await response.json()).code, "REMEDIATION_PREFIX_MISMATCH");
  const state = await runtime.memory.load(manifest.project_id);
  assert.equal(state.revision, 65);
});

test(
  "two truly overlapping POSTs with the same idempotency key converge on one five-event plan",
  { timeout: 10_000 },
  async () => {
    const barrier = createTwoPartyBarrier();
    const runtime = createRuntimeHarness({
      beforeAppend: ({ appendNumber }) =>
        appendNumber <= 2 ? barrier.wait() : undefined,
    });
    const handlers = createTrustedSyntheticHandlers({
      createRuntime: runtime.createRuntime,
    });
    const { body: plan } = await preview(handlers);
    const postBody = validPostBody({ planDigest: plan.planDigest });

    const responses = await Promise.all([
      handlers.POST(request("POST", PRODUCT_OWNER, postBody)),
      handlers.POST(request("POST", PRODUCT_OWNER, postBody)),
    ]);
    const bodies = await Promise.all(
      responses.map((response) => assertResponseEvidence(response)),
    );
    const state = await runtime.memory.load(manifest.project_id);
    const appended = state.events.slice(64);

    assert.equal(barrier.arrivals, 2);
    assert.deepEqual(
      responses.map(({ status }) => status),
      [200, 200],
    );
    assert.deepEqual(
      bodies.map(({ status }) => status),
      ["COMPLETED", "COMPLETED"],
    );
    assert.deepEqual(
      bodies.map(({ revision }) => revision),
      [69, 69],
    );
    for (const body of bodies) {
      assert.equal(body.appendedCount + body.duplicateCount, 5);
    }
    assert.equal(
      bodies.reduce((sum, body) => sum + body.appendedCount, 0),
      5,
    );
    assert.equal(
      bodies.reduce((sum, body) => sum + body.duplicateCount, 0),
      5,
    );
    assert.equal(bodies[0].submissionId, bodies[1].submissionId);
    assert.equal(state.revision, 69);
    assert.deepEqual(
      appended.map(({ revision }) => revision),
      [65, 66, 67, 68, 69],
    );
    assert.deepEqual(
      appended.map(({ type }) => type),
      [
        "WORK_PACKAGE_RECORDED",
        "WORK_PACKAGE_RECORDED",
        "WORK_PACKAGE_RECORDED",
        "WORK_PACKAGE_RECORDED",
        "GATE_SUBMITTED",
      ],
    );
    assert.deepEqual(
      appended.slice(0, 4).map(({ payload }) => payload.workPackageId),
      ["F01", "F02", "F03", "F04"],
    );
    assert.equal(
      appended.filter(({ type }) => type === "GATE_SUBMITTED").length,
      1,
    );
    assert.equal(
      appended.some(({ type }) => type === "ROLLBACK"),
      false,
    );
  },
);

test(
  "two truly overlapping POSTs with different idempotency keys allow only one five-event plan",
  { timeout: 10_000 },
  async () => {
    const barrier = createTwoPartyBarrier();
    const runtime = createRuntimeHarness({
      beforeAppend: ({ appendNumber }) =>
        appendNumber <= 2 ? barrier.wait() : undefined,
    });
    const handlers = createTrustedSyntheticHandlers({
      createRuntime: runtime.createRuntime,
    });
    const { body: plan } = await preview(handlers);
    const firstKey = "g0-remediation-20260729-concurrent-a";
    const secondKey = "g0-remediation-20260729-concurrent-b";

    const responses = await Promise.all([
      handlers.POST(
        request(
          "POST",
          PRODUCT_OWNER,
          validPostBody({
            planDigest: plan.planDigest,
            idempotencyKey: firstKey,
          }),
        ),
      ),
      handlers.POST(
        request(
          "POST",
          PRODUCT_OWNER,
          validPostBody({
            planDigest: plan.planDigest,
            idempotencyKey: secondKey,
          }),
        ),
      ),
    ]);
    const bodies = await Promise.all(
      responses.map((response) => assertResponseEvidence(response)),
    );
    const state = await runtime.memory.load(manifest.project_id);
    const appended = state.events.slice(64);
    const successIndex = responses.findIndex(
      ({ status }) => status === 200,
    );
    const failureIndex = responses.findIndex(
      ({ status }) => status !== 200,
    );

    assert.equal(barrier.arrivals, 2);
    assert.notEqual(successIndex, -1);
    assert.notEqual(failureIndex, -1);
    assert.equal(
      responses.filter(({ status }) => status === 200).length,
      1,
    );
    assert.equal(responses[failureIndex].status, 503);
    assert.equal(bodies[successIndex].status, "COMPLETED");
    assert.equal(
      bodies[failureIndex].code,
      "EXECUTION_OUTCOME_UNKNOWN",
    );
    assert.doesNotMatch(
      JSON.stringify(bodies[failureIndex]),
      /rollback|回滚|撤销/i,
    );
    assert.equal(state.revision, 69);
    assert.deepEqual(
      appended.map(({ revision }) => revision),
      [65, 66, 67, 68, 69],
    );
    assert.deepEqual(
      appended.map(({ type }) => type),
      [
        "WORK_PACKAGE_RECORDED",
        "WORK_PACKAGE_RECORDED",
        "WORK_PACKAGE_RECORDED",
        "WORK_PACKAGE_RECORDED",
        "GATE_SUBMITTED",
      ],
    );
    assert.deepEqual(
      appended.slice(0, 4).map(({ payload }) => payload.workPackageId),
      ["F01", "F02", "F03", "F04"],
    );
    assert.equal(
      appended.filter(({ type }) => type === "GATE_SUBMITTED").length,
      1,
    );
    const winningRoot = appended[0].idempotencyKey.replace(/:01-F01$/u, "");
    assert.ok([firstKey, secondKey].includes(winningRoot));
    assert.ok(
      appended.every(({ idempotencyKey }) =>
        idempotencyKey.startsWith(`${winningRoot}:`),
      ),
    );
    assert.equal(
      appended.some(({ type }) => type === "ROLLBACK"),
      false,
    );
  },
);

test("a completed plan is no longer current after later P0 scope drift", async () => {
  const runtime = createRuntimeHarness();
  const handlers = createTrustedSyntheticHandlers({
    createRuntime: runtime.createRuntime,
  });
  const { body: plan } = await preview(handlers);
  const body = validPostBody({ planDigest: plan.planDigest });

  const completed = await handlers.POST(
    request("POST", PRODUCT_OWNER, body),
  );
  assert.equal(completed.status, 200);
  const f01 = recordFor("F01");
  await runtime.memory.append({
    expectedRevision: 69,
    idempotencyKey: "later-authorized-p0-scope-change",
    commandHash: `sha256:${"a".repeat(64)}`,
    event: {
      id: "later-f01-scope-change",
      type: "WORK_PACKAGE_RECORDED",
      actorId: "external_product_owner",
      createdAt: "2026-07-29T04:00:00.000Z",
      payload: {
        workPackageId: "F01",
        implementationStatus: "IMPLEMENTED",
        verificationStatus: "VERIFIED",
        evidenceRefs: [...f01.evidenceRefs],
        evidenceHashes: [`sha256:${"e".repeat(64)}`],
        note: "Later governed evidence revision.",
      },
    },
  });

  const response = await handlers.POST(
    request("POST", PRODUCT_OWNER, body),
  );

  assert.equal(response.status, 409);
  assert.equal(
    (await response.json()).code,
    "COMPLETED_PLAN_NOT_CURRENT",
  );
  const state = await runtime.memory.load(manifest.project_id);
  assert.equal(state.revision, 70);
});

test("a later human G0 decision does not replay the completed remediation plan", async () => {
  const runtime = createRuntimeHarness();
  const handlers = createTrustedSyntheticHandlers({
    createRuntime: runtime.createRuntime,
  });
  const { body: plan } = await preview(handlers);
  const body = validPostBody({ planDigest: plan.planDigest });
  const completed = await handlers.POST(
    request("POST", PRODUCT_OWNER, body),
  );
  const completedBody = await completed.json();
  const live = runtime.createRuntime();

  assert.equal(completed.status, 200);
  await live.control.execute(
    {
      actorId: "external_product_owner",
      roles: ["PRODUCT_OWNER"],
    },
    {
      kind: "DECIDE_GATE",
      submissionId: completedBody.submissionId,
      expectedPackageHash: EXPECTED_PACKAGE_HASH,
      decision: "APPROVE",
      acceptedExclusions: [],
      evidenceRefs: ["product-owner-decision:test-only"],
      expectedRevision: 69,
      idempotencyKey: "human-g0-decision-after-remediation",
    },
  );
  const appendCountBeforeRetry = runtime.counts.append;

  const repeated = await handlers.POST(
    request("POST", PRODUCT_OWNER, body),
  );
  const repeatedBody = await assertResponseEvidence(repeated);
  const state = await runtime.memory.load(manifest.project_id);

  assert.equal(repeated.status, 200);
  assert.equal(repeatedBody.appendedCount, 0);
  assert.equal(repeatedBody.duplicateCount, 5);
  assert.equal(state.revision, 70);
  assert.equal(runtime.counts.append, appendCountBeforeRetry);
  assert.equal(
    state.events.filter(({ type }) => type === "GATE_DECIDED").length,
    2,
  );
});

test("the execution response is bounded and omits identity, credentials, evidence refs, and event bodies", async () => {
  const runtime = createRuntimeHarness();
  const handlers = createTrustedSyntheticHandlers({
    createRuntime: runtime.createRuntime,
  });
  const { body: plan } = await preview(handlers);

  const response = await handlers.POST(
    request(
      "POST",
      PRODUCT_OWNER,
      validPostBody({ planDigest: plan.planDigest }),
    ),
  );
  const bytes = await responseBytes(response);
  const text = bytes.toString("utf8");

  assert.ok(bytes.byteLength < 16 * 1024);
  assert.doesNotMatch(
    text,
    /product-owner@example\.test|cookie|authorization|token|secret|credential|evidenceRefs|actorId|commandHash|idempotencyKey/i,
  );
});

test("the frozen catalog verifier is bound to the exact approved parent commit and tree", async () => {
  assert.equal(
    await verifyG0RemediationFrozenCatalog({
      catalog,
      binding: G0_REMEDIATION_BUILD_BINDING,
    }),
    true,
  );
  const { stdout: objectType } = await execFileAsync(
    "git",
    ["cat-file", "-t", G0_REMEDIATION_BUILD_BINDING.sourceCommit],
    { cwd: REPOSITORY_ROOT },
  );
  const { stdout: tree } = await execFileAsync(
    "git",
    [
      "rev-parse",
      `${G0_REMEDIATION_BUILD_BINDING.sourceCommit}^{tree}`,
    ],
    { cwd: REPOSITORY_ROOT },
  );
  const { stdout: catalogBytes } = await execFileAsync(
    "git",
    [
      "show",
      `${G0_REMEDIATION_BUILD_BINDING.sourceCommit}:${G0_REMEDIATION_BUILD_BINDING.frozenEvidenceIndexPath}`,
    ],
    {
      cwd: REPOSITORY_ROOT,
      encoding: "buffer",
      maxBuffer: 1024 * 1024,
    },
  );

  assert.equal(objectType.trim(), "commit");
  assert.equal(tree.trim(), G0_REMEDIATION_BUILD_BINDING.tree);
  assert.equal(
    `sha256:${createHash("sha256").update(catalogBytes).digest("hex")}`,
    G0_REMEDIATION_BUILD_BINDING.frozenEvidenceIndexSha256,
  );
  for (const record of catalog.records) {
    for (const object of record.hashedObjects) {
      const { stdout: objectBytes } = await execFileAsync(
        "git",
        [
          "show",
          `${G0_REMEDIATION_BUILD_BINDING.sourceCommit}:${object.path}`,
        ],
        {
          cwd: REPOSITORY_ROOT,
          encoding: "buffer",
          maxBuffer: 4 * 1024 * 1024,
        },
      );
      assert.equal(
        `sha256:${createHash("sha256").update(objectBytes).digest("hex")}`,
        object.sha256,
        `${record.workPackageId}:${object.path}`,
      );
    }
  }
});

async function collectJavaScript(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      result.push(...(await collectJavaScript(path)));
    } else if (entry.isFile() && /\.(?:cjs|js|mjs)$/u.test(entry.name)) {
      result.push({
        path: relative(REPOSITORY_ROOT, path),
        contents: await readFile(path, "utf8"),
      });
    }
  }
  return result;
}

test("the production bundle keeps the frozen G0 catalog and verifier server-only without runtime Git", async () => {
  const serverFiles = await collectJavaScript(
    join(REPOSITORY_ROOT, "dist/server"),
  );
  const clientFiles = await collectJavaScript(
    join(REPOSITORY_ROOT, "dist/client"),
  );
  const server = serverFiles.map(({ contents }) => contents).join("\n");
  const client = clientFiles.map(({ contents }) => contents).join("\n");
  const markers = [
    "verifyG0RemediationFrozenCatalog",
    "g0-remediation-build-binding.v1",
    G0_REMEDIATION_BUILD_BINDING.sourceCommit,
    G0_REMEDIATION_BUILD_BINDING.tree,
    G0_REMEDIATION_BUILD_BINDING.frozenEvidenceIndexSha256,
    EXPECTED_PACKAGE_HASH,
  ];

  for (const marker of markers) {
    assert.match(server, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.doesNotMatch(client, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  for (const marker of [
    "/usr/bin/git",
    "node:child_process",
    "api.github.com",
    "raw.githubusercontent.com",
    "GITHUB_TOKEN",
    "GH_TOKEN",
  ]) {
    assert.doesNotMatch(server, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("the new route is GET/POST-only and existing governance HTTP surfaces remain unchanged", async () => {
  const [route, progress, readiness] = await Promise.all([
    readFile(ROUTE_URL, "utf8"),
    readFile(PROGRESS_ROUTE_URL, "utf8"),
    readFile(READINESS_ROUTE_URL, "utf8"),
  ]);
  const routeMethods = [
    ...route.matchAll(
      /export (?:async function|const) (GET|POST|PUT|PATCH|DELETE)\b/g,
    ),
  ].map((match) => match[1]);
  const progressActions = [
    ...progress.matchAll(/payload\.action === "([^"]+)"/g),
  ]
    .map((match) => match[1])
    .sort();
  const readinessMethods = [
    ...readiness.matchAll(
      /export (?:async function|const) (GET|POST|PUT|PATCH|DELETE)\b/g,
    ),
  ].map((match) => match[1]);

  assert.deepEqual(routeMethods.sort(), ["GET", "POST"]);
  assert.deepEqual(progressActions, [
    "decide_gate",
    "submit_gate",
    "update_connector",
    "update_task",
    "validate_human_baseline",
  ]);
  assert.deepEqual(readinessMethods, ["GET"]);
  assert.doesNotMatch(
    `${route}\n${progress}\n${readiness}`,
    /APPROVE_P2_ACCEPTANCE_PROFILE|AUTHORIZE_P2_WORK_PACKAGE_START|REVOKE_P2_WORK_PACKAGE_START_AUTHORIZATION/,
  );
  assert.doesNotMatch(
    route,
    /ensureDatabase|seedIfNeeded|GATE_DECIDED|DECIDE_GATE/,
  );
});

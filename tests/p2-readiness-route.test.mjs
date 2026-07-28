import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createP2ReadinessGet } from "../lib/p2-readiness-projection.mjs";
import { P2_V2_CANDIDATE_START_POLICY } from "../lib/p2-start-authorization.mjs";
import { createProjectControl } from "../lib/project-control.mjs";

const PRODUCT_OWNER = "product-owner@example.test";
const SOURCE_COMMIT = "48a4e4eac1f2fc2404d21ca5ab9a2d014a0e20e5";
const EXECUTION_BASELINE_DIGEST =
  "sha256:e6282c301d6eb05cace8361f5974143897db59c3770d4c8856211f0635599bee";

function requestFor(actor = null) {
  const headers = new Headers();
  if (actor) headers.set("oai-authenticated-user-email", actor);
  return new Request(
    "https://example.test/api/governance/p2-readiness",
    { headers },
  );
}

function createGet(overrides = {}) {
  return createP2ReadinessGet({
    configuredProductOwner: () => PRODUCT_OWNER,
    isProductOwner: (actor, configured) =>
      actor.trim().toLowerCase() === configured.trim().toLowerCase(),
    loadSnapshot: async () => {
      throw new Error("The ledger must not be read before authentication.");
    },
    clock: () => "2026-07-28T06:00:00.000Z",
    ...overrides,
  });
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

async function createProjectedGet(initialEvents = [], appendCounter = null) {
  const manifest = await loadManifest();
  const events = initialEvents.map((event, index) => ({
    ...structuredClone(event),
    revision: event.revision ?? index + 1,
  }));
  const journal = {
    async load() {
      return {
        revision: events.at(-1)?.revision ?? 0,
        events: structuredClone(events),
      };
    },
    async append() {
      if (appendCounter) appendCounter.count += 1;
      throw new Error("GET must never append a governance event.");
    },
  };
  const control = createProjectControl({
    manifest,
    journal,
    p2StartPolicy: P2_V2_CANDIDATE_START_POLICY,
  });
  return createGet({
    loadSnapshot: () => control.snapshot(),
  });
}

function verifiedPackageEvent(item, ordinal) {
  return {
    id: `verified-${item.id.toLowerCase()}`,
    type: "WORK_PACKAGE_RECORDED",
    actorId: "external_product_owner",
    createdAt: new Date(Date.UTC(2026, 6, 28, 6, 0, ordinal)).toISOString(),
    payload: {
      workPackageId: item.id,
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
      evidenceRefs: [],
      evidenceHashes: [],
      note: `${item.id} frozen evidence`,
    },
  };
}

function gateApprovalEvents(manifest, gateId, ordinal) {
  const gate = manifest.gates.find(({ id }) => id === gateId);
  const scope = manifest.work_packages
    .filter(({ phase }) => phase === gate.phase)
    .map((item) => ({
      work_package_id: item.id,
      applicability: item.applicability,
      implementation_status: "IMPLEMENTED",
      verification_status: "VERIFIED",
      evidence_refs: [],
      evidence_hashes: [],
    }));
  const submissionId = `${gateId.toLowerCase()}-submission`;
  return [
    {
      id: `${gateId.toLowerCase()}-submission-event`,
      type: "GATE_SUBMITTED",
      actorId: "external_product_owner",
      createdAt: new Date(Date.UTC(2026, 6, 28, 6, 1, ordinal)).toISOString(),
      payload: {
        gate_id: gateId,
        submission_id: submissionId,
        package_hash: `sha256:${
          gateId === "G0" ? "a".repeat(64) : "b".repeat(64)
        }`,
        submitted_at: new Date(
          Date.UTC(2026, 6, 28, 6, 1, ordinal),
        ).toISOString(),
        submitted_by: "external_product_owner",
        source_revision: 0,
        work_package_scope: scope,
        evidence_refs: [],
        supersedes: null,
      },
    },
    {
      id: `${gateId.toLowerCase()}-decision-event`,
      type: "GATE_DECIDED",
      actorId: "external_product_owner",
      createdAt: new Date(Date.UTC(2026, 6, 28, 6, 2, ordinal)).toISOString(),
      payload: {
        decision_id: `${gateId.toLowerCase()}-decision`,
        submission_id: submissionId,
        package_hash: `sha256:${
          gateId === "G0" ? "a".repeat(64) : "b".repeat(64)
        }`,
        decision: "APPROVE",
        decided_by: "external_product_owner",
        decided_at: new Date(
          Date.UTC(2026, 6, 28, 6, 2, ordinal),
        ).toISOString(),
        accepted_exclusions: [],
        evidence_refs: [],
      },
    },
  ];
}

async function p2PhaseEntryEvents() {
  const manifest = await loadManifest();
  return [
    ...manifest.work_packages
      .filter(({ phase }) => phase === "P0")
      .map(verifiedPackageEvent),
    ...gateApprovalEvents(manifest, "G0", 0),
    ...manifest.work_packages
      .filter(({ phase }) => phase === "P1")
      .map((item, index) => verifiedPackageEvent(item, index + 10)),
    ...gateApprovalEvents(manifest, "G1", 1),
  ];
}

function profileApprovalEvent() {
  const createdAt = "2026-07-28T06:03:00.000Z";
  return {
    id: "p2-profile-approval-event",
    type: "P2_ACCEPTANCE_PROFILE_APPROVED",
    actorId: "external_product_owner",
    createdAt,
    payload: {
      profile_approval_id: "p2pa_candidate_profile_0001",
      profile_path: P2_V2_CANDIDATE_START_POLICY.profile.path,
      profile_sha256: P2_V2_CANDIDATE_START_POLICY.profile.sha256,
      profile_schema_version:
        P2_V2_CANDIDATE_START_POLICY.profile.schemaVersion,
      receipt_schema_path:
        P2_V2_CANDIDATE_START_POLICY.receiptSchema.path,
      receipt_schema_sha256:
        P2_V2_CANDIDATE_START_POLICY.receiptSchema.sha256,
      receipt_schema_version:
        P2_V2_CANDIDATE_START_POLICY.receiptSchema.version,
      validator_path: P2_V2_CANDIDATE_START_POLICY.validator.path,
      validator_sha256: P2_V2_CANDIDATE_START_POLICY.validator.sha256,
      validator_version: P2_V2_CANDIDATE_START_POLICY.validator.version,
      execution_baseline_digest: EXECUTION_BASELINE_DIGEST,
      source_commit: SOURCE_COMMIT,
      approved_by: "external_product_owner",
      approved_at: createdAt,
      source_revision: 27,
      supersedes: null,
    },
  };
}

function startAuthorizationEvent(workPackageId, sourceRevision) {
  const suffix = workPackageId.toLowerCase();
  const createdAt = "2026-07-28T06:04:00.000Z";
  return {
    id: `${suffix}-start-authorization-event`,
    type: "P2_WORK_PACKAGE_START_AUTHORIZED",
    actorId: "external_product_owner",
    createdAt,
    payload: {
      authorization_id: `p2wpa_${suffix}_authorization_0001`,
      work_package_id: workPackageId,
      profile_approval_id: "p2pa_candidate_profile_0001",
      profile_sha256: P2_V2_CANDIDATE_START_POLICY.profile.sha256,
      execution_baseline_digest: EXECUTION_BASELINE_DIGEST,
      authorization_status: "AUTHORIZED",
      revokes_authorization_id: null,
      recorded_by: "external_product_owner",
      recorded_at: createdAt,
      source_revision: sourceRevision,
    },
  };
}

test("P2 readiness requires an authenticated Product Owner identity", async () => {
  const response = await createGet()(requestFor());

  assert.equal(response.status, 401);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), {
    schemaVersion: "p2-readiness-error.v1",
    code: "AUTHENTICATION_REQUIRED",
    error: "需要先通过工作区身份验证。",
  });
});

test("P2 readiness fails closed when the Product Owner is not configured", async () => {
  const response = await createGet({
    configuredProductOwner: () => undefined,
  })(requestFor(PRODUCT_OWNER));

  assert.equal(response.status, 503);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), {
    schemaVersion: "p2-readiness-error.v1",
    code: "PRODUCT_OWNER_NOT_CONFIGURED",
    error: "产品所有者身份尚未配置。",
  });
});

test("P2 readiness rejects a non-Product Owner identity", async () => {
  const response = await createGet()(requestFor("another-user@example.test"));

  assert.equal(response.status, 403);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), {
    schemaVersion: "p2-readiness-error.v1",
    code: "PRODUCT_OWNER_REQUIRED",
    error: "只有外部产品所有者可以读取 P2 准备度。",
  });
});

test("an empty online ledger does not inherit work-package status from the Manifest", async () => {
  const response = await (await createProjectedGet())(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(Object.keys(body), [
    "schemaVersion",
    "source",
    "revision",
    "phaseEntryP2",
    "gates",
    "profileApproval",
    "workPackages",
    "serverTime",
  ]);
  assert.equal(body.schemaVersion, "p2-readiness-projection.v1");
  assert.equal(body.source, "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER");
  assert.equal(body.revision, 0);
  assert.equal(body.phaseEntryP2, false);
  assert.deepEqual(body.gates, {
    G0: { status: "NOT_READY", decision: null, submissionId: null },
    G1: { status: "NOT_READY", decision: null, submissionId: null },
  });
  assert.equal(body.profileApproval, null);
  assert.equal(body.workPackages.O02.implementationStatus, "NOT_STARTED");
  assert.equal(body.workPackages.O02.verificationStatus, "NOT_VERIFIED");
  assert.equal(body.workPackages.O03.implementationStatus, "NOT_STARTED");
  assert.equal(body.workPackages.O03.verificationStatus, "NOT_VERIFIED");
  assert.equal(body.workPackages.O02.allowedToStart, false);
  assert.equal(body.workPackages.O03.allowedToStart, false);
});

test("revision and G0/G1 decisions come from the journal-backed Project Control projection", async () => {
  const events = await p2PhaseEntryEvents();
  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.revision, 27);
  assert.equal(body.phaseEntryP2, true);
  assert.deepEqual(body.gates, {
    G0: {
      status: "APPROVED",
      decision: "APPROVE",
      submissionId: "g0-submission",
    },
    G1: {
      status: "APPROVED",
      decision: "APPROVE",
      submissionId: "g1-submission",
    },
  });
});

test("a valid Profile event and O02 authorization expose only their fixed summaries", async () => {
  const events = [
    ...(await p2PhaseEntryEvents()),
    profileApprovalEvent(),
    startAuthorizationEvent("O02", 28),
  ];
  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(body.profileApproval, {
    eventId: "p2-profile-approval-event",
    revision: 28,
    profileApprovalId: "p2pa_candidate_profile_0001",
    profileSha256: P2_V2_CANDIDATE_START_POLICY.profile.sha256,
    executionBaselineDigest: EXECUTION_BASELINE_DIGEST,
    sourceCommit: SOURCE_COMMIT,
  });
  assert.deepEqual(Object.keys(body.profileApproval), [
    "eventId",
    "revision",
    "profileApprovalId",
    "profileSha256",
    "executionBaselineDigest",
    "sourceCommit",
  ]);
  assert.deepEqual(Object.keys(body.gates.G0), [
    "status",
    "decision",
    "submissionId",
  ]);
  assert.deepEqual(Object.keys(body.workPackages.O02), [
    "implementationStatus",
    "verificationStatus",
    "structuralReady",
    "allowedToStart",
    "startAuthorizationStatus",
    "authorizationId",
    "blockers",
  ]);
  assert.equal(body.workPackages.O02.startAuthorizationStatus, "AUTHORIZED");
  assert.equal(
    body.workPackages.O02.authorizationId,
    "p2wpa_o02_authorization_0001",
  );
  assert.equal(body.workPackages.O02.allowedToStart, true);
  assert.equal(
    body.workPackages.O03.startAuthorizationStatus,
    "NOT_AUTHORIZED",
  );
  assert.equal(body.workPackages.O03.authorizationId, null);
  assert.equal(body.workPackages.O03.allowedToStart, false);
});

test("Profile Approval is visible without implying either work-package start authorization", async () => {
  const events = [
    ...(await p2PhaseEntryEvents()),
    profileApprovalEvent(),
  ];
  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(
    body.profileApproval.profileApprovalId,
    "p2pa_candidate_profile_0001",
  );
  assert.equal(body.workPackages.O02.startAuthorizationStatus, "NOT_AUTHORIZED");
  assert.equal(body.workPackages.O03.startAuthorizationStatus, "NOT_AUTHORIZED");
  assert.equal(body.workPackages.O02.allowedToStart, false);
  assert.equal(body.workPackages.O03.allowedToStart, false);
});

test("a D1 read failure returns one stable fail-closed response", async () => {
  const response = await createGet({
    loadSnapshot: async () => {
      throw new Error(
        "database secret token credential product-owner@example.test",
      );
    },
  })(requestFor(PRODUCT_OWNER));

  assert.equal(response.status, 503);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), {
    schemaVersion: "p2-readiness-error.v1",
    code: "P2_READINESS_UNAVAILABLE",
    error: "线上 P2 治理投影暂时不可用。",
  });
});

test("GET never calls journal.append", async () => {
  const appendCounter = { count: 0 };
  const response = await (await createProjectedGet([], appendCounter))(
    requestFor(PRODUCT_OWNER),
  );

  assert.equal(response.status, 200);
  assert.equal(appendCounter.count, 0);
});

test("O03 authorization cannot impersonate O02 authorization", async () => {
  const events = [
    ...(await p2PhaseEntryEvents()),
    profileApprovalEvent(),
    startAuthorizationEvent("O03", 28),
  ];
  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();

  assert.equal(body.workPackages.O02.startAuthorizationStatus, "NOT_AUTHORIZED");
  assert.equal(body.workPackages.O02.authorizationId, null);
  assert.equal(body.workPackages.O02.allowedToStart, false);
  assert.equal(body.workPackages.O03.startAuthorizationStatus, "AUTHORIZED");
  assert.equal(
    body.workPackages.O03.authorizationId,
    "p2wpa_o03_authorization_0001",
  );
  assert.equal(
    body.workPackages.O03.allowedToStart,
    false,
    "O03 remains structurally blocked by unverified O02.",
  );
});

test("the fixed projection excludes sensitive ledger content and user email", async () => {
  const events = [
    ...(await p2PhaseEntryEvents()),
    profileApprovalEvent(),
    startAuthorizationEvent("O02", 28),
  ];
  events[0].actorId = PRODUCT_OWNER;
  events[0].payload.note =
    "secret token credential product-owner@example.test";
  events[0].payload.evidenceRefs = [
    `evidence:${"private-content-".repeat(2000)}`,
  ];
  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();
  const serialized = JSON.stringify(body);

  assert.deepEqual(Object.keys(body.gates), ["G0", "G1"]);
  assert.deepEqual(Object.keys(body.workPackages), ["O02", "O03"]);
  assert.doesNotMatch(
    serialized,
    /secret|token|credential|evidence|product-owner@example\.test/i,
  );
});

test("the serialized projection remains below 16 KiB for an oversized ledger identifier", async () => {
  const events = await p2PhaseEntryEvents();
  const oversizedSubmissionId = "submission-".repeat(3000);
  const g0Submission = events.find(
    ({ type, payload }) =>
      type === "GATE_SUBMITTED" && payload.gate_id === "G0",
  );
  const g0Decision = events.find(
    ({ type, payload }) =>
      type === "GATE_DECIDED" &&
      payload.submission_id === g0Submission.payload.submission_id,
  );
  g0Submission.payload.submission_id = oversizedSubmissionId;
  g0Decision.payload.submission_id = oversizedSubmissionId;
  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const body = await response.json();
  const serialized = JSON.stringify(body);

  assert.equal(body.gates.G0.submissionId, null);
  assert.equal(body.gates.G0.decision, "APPROVE");
  assert.ok(Buffer.byteLength(serialized, "utf8") < 16 * 1024);
});

test("an invalid unbounded Gate decision fails closed without leaking ledger content", async () => {
  const events = await p2PhaseEntryEvents();
  const decision = events.find(
    ({ type, payload }) =>
      type === "GATE_DECIDED" &&
      payload.submission_id === "g0-submission",
  );
  decision.payload.decision =
    "secret-token-credential-product-owner@example.test-".repeat(2000);
  const response = await (await createProjectedGet(events))(
    requestFor(PRODUCT_OWNER),
  );
  const serialized = await response.text();

  assert.equal(response.status, 503);
  assert.ok(Buffer.byteLength(serialized, "utf8") < 16 * 1024);
  assert.doesNotMatch(
    serialized,
    /secret|token|credential|evidence|product-owner@example\.test/i,
  );
});

test("an invalid unbounded work-package status fails closed without leaking ledger content", async () => {
  const oversizedStatus =
    "secret-token-credential-product-owner@example.test-".repeat(2000);
  const response = await (await createProjectedGet([
    {
      id: "invalid-o02-status-event",
      type: "WORK_PACKAGE_RECORDED",
      actorId: PRODUCT_OWNER,
      createdAt: "2026-07-28T06:00:00.000Z",
      payload: {
        workPackageId: "O02",
        implementationStatus: oversizedStatus,
        verificationStatus: oversizedStatus,
        evidenceRefs: [oversizedStatus],
        evidenceHashes: [],
      },
    },
  ]))(requestFor(PRODUCT_OWNER));
  const serialized = await response.text();

  assert.equal(response.status, 503);
  assert.ok(Buffer.byteLength(serialized, "utf8") < 16 * 1024);
  assert.doesNotMatch(
    serialized,
    /secret|token|credential|evidence|product-owner@example\.test/i,
  );
});

test("caller query fields cannot override the online ledger projection", async () => {
  const request = requestFor(PRODUCT_OWNER);
  const injectedRequest = new Request(
    `${request.url}?tenant=forged&revision=999&profile=approved&gate=G1&workPackage=O02`,
    { headers: request.headers },
  );
  const response = await (await createProjectedGet())(injectedRequest);
  const body = await response.json();

  assert.equal(body.revision, 0);
  assert.equal(body.phaseEntryP2, false);
  assert.equal(body.profileApproval, null);
  assert.equal(body.gates.G1.status, "NOT_READY");
  assert.equal(body.workPackages.O02.implementationStatus, "NOT_STARTED");
});

test("the production route exposes only the read-only D1-backed GET", async () => {
  const source = await readFile(
    new URL(
      "../app/api/governance/p2-readiness/route.ts",
      import.meta.url,
    ),
    "utf8",
  );

  assert.match(source, /createD1GovernanceJournal/);
  assert.match(source, /createProjectControl/);
  assert.match(source, /createP2ReadinessGet/);
  assert.match(source, /P2_V2_CANDIDATE_START_POLICY/);
  assert.match(source, /export const GET/);
  assert.doesNotMatch(source, /seedIfNeeded|ensureDatabase/);
  assert.doesNotMatch(source, /governance-events\.v1\.json/);
  assert.doesNotMatch(
    source,
    /export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)|export const (?:POST|PUT|PATCH|DELETE)/,
  );
  assert.doesNotMatch(
    source,
    /APPROVE_P2_ACCEPTANCE_PROFILE|AUTHORIZE_P2_WORK_PACKAGE_START|REVOKE_P2_WORK_PACKAGE_START_AUTHORIZATION/,
  );
});

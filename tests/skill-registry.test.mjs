import assert from "node:assert/strict";
import test from "node:test";
import {
  canonicalSkillManifestSha256,
  createMemorySkillRegistryStore,
  createSkillRegistry,
  validateSkillManifest,
} from "../lib/skill-registry.mjs";

const MANIFEST_V1 = Object.freeze({
  schemaVersion: "1.0.0",
  name: "analyze-synthetic-order",
  version: "1.0.0",
  description:
    "Analyze a fictitious order with cited synthetic evidence.",
  instructions:
    "Use only the supplied Synthetic evidence. Return a concise finding and cite each source.",
  allowedTools: Object.freeze(["catalog.read"]),
  executionMode: "INSTRUCTIONS_ONLY",
});
const MANIFEST_V2 = Object.freeze({
  ...MANIFEST_V1,
  version: "1.1.0",
  instructions:
    "Use only supplied Synthetic evidence. Return cited findings and state uncertainty.",
});
const TENANT_A = "stn_01984910-5000-7000-8000-000000000001";
const TENANT_B = "stn_01984910-5000-7000-8000-000000000002";
const HUMAN = "prn_01984910-5000-7000-8000-000000000011";
const WORKLOAD = "prn_01984910-5000-7000-8000-000000000012";
const DELEGATION = "dlg_01984910-5000-7000-8000-000000000013";
const HASH_V1 =
  "sha256:10bbe25c69f3b5cfaaf43c8a935e02802605b4da34501fd967394c8936b72e07";
const SOURCE_HASH =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SUITE_HASH =
  "sha256:628503bc3001d50d8eb30d89ce4f45e184918c63ba4fc0e8d3f6594d345a3259";

function fixture({
  store = createMemorySkillRegistryStore(),
  evaluationStatus = "PASS",
} = {}) {
  let nextId = 0;
  const identity = {
    tenantId: TENANT_A,
    tenantKind: "SYNTHETIC",
    trustSource: "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
    authorizationStatus: "NOT_EVALUATED",
    humanSubject: { principalId: HUMAN, securityEpoch: 1 },
    workloadActor: { principalId: WORKLOAD, securityEpoch: 1 },
    purposeRef: "synthetic://c13/skill-governance",
    delegationChain: [{ delegationId: DELEGATION }],
  };
  const catalog = {
    authorizationResources(tenantId) {
      return {
        readResourceId: `c13_${tenantId.slice(-4)}_read`,
        manageResourceId: `c13_${tenantId.slice(-4)}_manage`,
      };
    },
    verifySource({ manifest, contentSha256, sourceReviewRef, sourceReviewSha256 }) {
      assert.equal(contentSha256, canonicalSkillManifestSha256(manifest));
      assert.equal(sourceReviewRef, "fixture://c13/review/analyze-order");
      assert.equal(sourceReviewSha256, SOURCE_HASH);
      return true;
    },
    evaluate({ contentSha256, suiteId, suiteSha256 }) {
      assert.match(contentSha256, /^sha256:[a-f0-9]{64}$/);
      assert.equal(suiteId, "f04-frozen-evaluation-suite-v1");
      assert.equal(suiteSha256, SUITE_HASH);
      return {
        status: evaluationStatus,
        caseCount: 10,
        failureCount: evaluationStatus === "PASS" ? 0 : 1,
        zeroToleranceViolationCount:
          evaluationStatus === "PASS" ? 0 : 1,
        reportRef: "evidence://c13/evaluation/pass",
        reportSha256:
          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      };
    },
  };
  const registry = createSkillRegistry({
    tenantRegistry: {
      async admitNewRequest({ tenantId }) {
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          trustSource: "VERIFIED_SERVER_CONTEXT",
          lifecycleVersion: 2,
        };
      },
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity(_context, { expectedTenantId }) {
        return { ...structuredClone(identity), tenantId: expectedTenantId };
      },
    },
    authorizer: {
      async enforce(serverContext, request, descriptor) {
        return {
          trustSource: "C06_BOUND_DECISION_EVIDENCE",
          decisionId: `decision-${descriptor.surface.toLowerCase()}`,
          evidenceRef: `evidence://c06/${descriptor.surface.toLowerCase()}`,
          policyVersion: "c06-synthetic-v1",
          tenantId: serverContext.tenantId,
          surface: descriptor.surface,
          resourceId: request.resourceId,
          humanPrincipalId: HUMAN,
          humanSecurityEpoch: 1,
          workloadActorPrincipalId: WORKLOAD,
          workloadActorSecurityEpoch: 1,
          leafDelegationId: DELEGATION,
          delegationChainSha256:
            "sha256:b0cd84756c7844755aef220eb7aa31bfa33ec17901c3d64184e22e2985b4d5d4",
          purposeRef: "synthetic://c13/skill-governance",
        };
      },
    },
    store,
    catalog,
    idFactory() {
      nextId += 1;
      return `01984910-5000-7000-8000-${String(nextId).padStart(12, "0")}`;
    },
    clock: (() => {
      let tick = 0;
      return () =>
        new Date(Date.UTC(2026, 6, 26, 15, 0, tick++)).toISOString();
    })(),
  });
  return { registry, store };
}

function context(tenantId = TENANT_A) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: WORKLOAD,
  };
}

function request(kind, command, suffix = kind.toLowerCase()) {
  return {
    sessionToken: "synthetic-session",
    delegationId: DELEGATION,
    idempotencyKey: `c13-${suffix}`,
    correlationId: `c13-correlation-${suffix}`,
    command: { kind, ...command },
  };
}

async function execute(
  registry,
  kind,
  command,
  suffix = kind.toLowerCase(),
  tenantId = TENANT_A,
) {
  return registry.execute(
    context(tenantId),
    request(kind, command, suffix),
  );
}

async function submit(registry, manifest, suffix = manifest.version) {
  return execute(
    registry,
    "SUBMIT_RELEASE",
    {
      skillId: null,
      expectedLatestSequence: 0,
      manifest,
      contentSha256: canonicalSkillManifestSha256(manifest),
      sourceReviewRef: "fixture://c13/review/analyze-order",
      sourceReviewSha256: SOURCE_HASH,
    },
    `submit-${suffix}`,
  );
}

async function approve(registry, submitted, manifest, suffix = manifest.version) {
  const staticResult = await execute(
    registry,
    "RUN_STATIC_CHECK",
    {
      releaseId: submitted.releaseId,
      expectedReleaseVersion: 1,
    },
    `static-${suffix}`,
  );
  const evaluated = await execute(
    registry,
    "RUN_SYNTHETIC_EVALUATION",
    {
      releaseId: submitted.releaseId,
      expectedReleaseVersion: staticResult.releaseVersion,
      suiteId: "f04-frozen-evaluation-suite-v1",
      suiteSha256: SUITE_HASH,
    },
    `eval-${suffix}`,
  );
  return execute(
    registry,
    "APPROVE_RELEASE",
    {
      releaseId: submitted.releaseId,
      expectedReleaseVersion: evaluated.releaseVersion,
      approvedContentSha256: canonicalSkillManifestSha256(manifest),
    },
    `approve-${suffix}`,
  );
}

test("a minimal instructions-only Skill Manifest has one canonical SHA-256", () => {
  assert.deepEqual(validateSkillManifest(MANIFEST_V1), MANIFEST_V1);
  assert.equal(
    canonicalSkillManifestSha256(MANIFEST_V1),
    "sha256:10bbe25c69f3b5cfaaf43c8a935e02802605b4da34501fd967394c8936b72e07",
  );

  const reordered = {
    instructions: MANIFEST_V1.instructions,
    schemaVersion: MANIFEST_V1.schemaVersion,
    allowedTools: [...MANIFEST_V1.allowedTools],
    version: MANIFEST_V1.version,
    executionMode: MANIFEST_V1.executionMode,
    name: MANIFEST_V1.name,
    description: MANIFEST_V1.description,
  };
  assert.equal(
    canonicalSkillManifestSha256(reordered),
    canonicalSkillManifestSha256(MANIFEST_V1),
  );
});

test("Skill scripts and authority-bearing allowed-tools declarations are closed", () => {
  assert.throws(
    () =>
      validateSkillManifest({
        ...MANIFEST_V1,
        scripts: ["node synthetic.js"],
      }),
    { code: "INVALID_SKILL_MANIFEST" },
  );
  assert.throws(
    () =>
      validateSkillManifest({
        ...MANIFEST_V1,
        executionMode: "SCRIPT",
      }),
    { code: "SCRIPT_EXECUTION_DISABLED" },
  );
  assert.throws(
    () =>
      validateSkillManifest({
        ...MANIFEST_V1,
        allowedTools: ["*"],
      }),
    { code: "INVALID_SKILL_MANIFEST" },
  );
});

test("a release moves through static check, frozen evaluation, approval, pilot and stable", async () => {
  const { registry, store } = fixture();
  const submitted = await submit(registry, MANIFEST_V1);

  await assert.rejects(
    registry.resolveForRun(context(), {
      sessionToken: "synthetic-session",
      delegationId: DELEGATION,
      correlationId: "c13-resolve-untested",
      skillId: submitted.skillId,
      version: MANIFEST_V1.version,
      contentSha256: HASH_V1,
      channel: "PILOT",
    }),
    { code: "SKILL_NOT_AVAILABLE" },
  );

  const approved = await approve(registry, submitted, MANIFEST_V1);
  assert.equal(approved.lifecycleState, "APPROVED");
  const pilot = await execute(
    registry,
    "PUBLISH_RELEASE",
    {
      releaseId: submitted.releaseId,
      expectedReleaseVersion: approved.releaseVersion,
      channel: "PILOT",
      expectedChannelGeneration: 0,
      expectedCurrentReleaseId: null,
    },
    "publish-pilot-v1",
  );
  const stable = await execute(
    registry,
    "PUBLISH_RELEASE",
    {
      releaseId: submitted.releaseId,
      expectedReleaseVersion: pilot.releaseVersion,
      channel: "STABLE",
      expectedChannelGeneration: 0,
      expectedCurrentReleaseId: null,
    },
    "publish-stable-v1",
  );
  assert.equal(stable.channelGeneration, 1);

  const resolved = await registry.resolveForRun(context(), {
    sessionToken: "synthetic-session",
    delegationId: DELEGATION,
    correlationId: "c13-resolve-stable",
    skillId: submitted.skillId,
    version: MANIFEST_V1.version,
    contentSha256: HASH_V1,
    channel: "STABLE",
  });
  assert.deepEqual(resolved.manifest, MANIFEST_V1);
  assert.equal(resolved.contentSha256, HASH_V1);
  assert.equal(resolved.scriptsEnabled, false);
  assert.equal(resolved.allowedToolsGrantAuthorization, false);

  const snapshot = await store.readTenantSnapshot({
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: TENANT_A,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId: "snapshot",
    decisionId: "snapshot",
    evidenceRef: "evidence://snapshot",
    policyVersion: "snapshot",
  });
  assert.deepEqual(snapshot.counts, {
    releases: 1,
    channels: 2,
    events: 6,
    receipts: 6,
  });
});

test("hash mismatch and withdrawn release cannot resolve for a new Run", async () => {
  const { registry } = fixture();
  const submitted = await submit(registry, MANIFEST_V1);
  const approved = await approve(registry, submitted, MANIFEST_V1);
  const pilot = await execute(
    registry,
    "PUBLISH_RELEASE",
    {
      releaseId: submitted.releaseId,
      expectedReleaseVersion: approved.releaseVersion,
      channel: "PILOT",
      expectedChannelGeneration: 0,
      expectedCurrentReleaseId: null,
    },
    "withdraw-pilot",
  );
  await assert.rejects(
    registry.resolveForRun(context(), {
      sessionToken: "synthetic-session",
      delegationId: DELEGATION,
      correlationId: "c13-resolve-hash-mismatch",
      skillId: submitted.skillId,
      version: MANIFEST_V1.version,
      contentSha256:
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      channel: "PILOT",
    }),
    { code: "SKILL_HASH_MISMATCH" },
  );
  await execute(
    registry,
    "WITHDRAW_RELEASE",
    {
      releaseId: submitted.releaseId,
      expectedReleaseVersion: pilot.releaseVersion,
      reasonRef: "synthetic://c13/withdraw/superseded",
    },
    "withdraw-v1",
  );
  await assert.rejects(
    registry.resolveForRun(context(), {
      sessionToken: "synthetic-session",
      delegationId: DELEGATION,
      correlationId: "c13-resolve-withdrawn",
      skillId: submitted.skillId,
      version: MANIFEST_V1.version,
      contentSha256: HASH_V1,
      channel: "PILOT",
    }),
    { code: "SKILL_NOT_AVAILABLE" },
  );
});

test("rollback accepts only a previously published, approved, non-withdrawn release", async () => {
  const { registry } = fixture();
  const first = await submit(registry, MANIFEST_V1);
  const firstApproved = await approve(registry, first, MANIFEST_V1);
  const firstPilot = await execute(
    registry,
    "PUBLISH_RELEASE",
    {
      releaseId: first.releaseId,
      expectedReleaseVersion: firstApproved.releaseVersion,
      channel: "PILOT",
      expectedChannelGeneration: 0,
      expectedCurrentReleaseId: null,
    },
    "rollback-pilot-v1",
  );
  await execute(
    registry,
    "PUBLISH_RELEASE",
    {
      releaseId: first.releaseId,
      expectedReleaseVersion: firstPilot.releaseVersion,
      channel: "STABLE",
      expectedChannelGeneration: 0,
      expectedCurrentReleaseId: null,
    },
    "rollback-stable-v1",
  );
  const second = await execute(
    registry,
    "SUBMIT_RELEASE",
    {
      skillId: first.skillId,
      expectedLatestSequence: 1,
      manifest: MANIFEST_V2,
      contentSha256: canonicalSkillManifestSha256(MANIFEST_V2),
      sourceReviewRef: "fixture://c13/review/analyze-order",
      sourceReviewSha256: SOURCE_HASH,
    },
    "rollback-submit-v2",
  );
  const secondApproved = await approve(
    registry,
    second,
    MANIFEST_V2,
    "rollback-v2",
  );
  const secondPilot = await execute(
    registry,
    "PUBLISH_RELEASE",
    {
      releaseId: second.releaseId,
      expectedReleaseVersion: secondApproved.releaseVersion,
      channel: "PILOT",
      expectedChannelGeneration: 1,
      expectedCurrentReleaseId: first.releaseId,
    },
    "rollback-pilot-v2",
  );
  const secondStable = await execute(
    registry,
    "PUBLISH_RELEASE",
    {
      releaseId: second.releaseId,
      expectedReleaseVersion: secondPilot.releaseVersion,
      channel: "STABLE",
      expectedChannelGeneration: 1,
      expectedCurrentReleaseId: first.releaseId,
    },
    "rollback-stable-v2",
  );
  const rolledBack = await execute(
    registry,
    "ROLLBACK_CHANNEL",
    {
      skillId: first.skillId,
      channel: "STABLE",
      targetReleaseId: first.releaseId,
      expectedChannelGeneration: secondStable.channelGeneration,
      expectedCurrentReleaseId: second.releaseId,
      reasonRef: "synthetic://c13/rollback/v1",
    },
    "rollback-to-v1",
  );
  assert.equal(rolledBack.releaseId, first.releaseId);
  assert.equal(rolledBack.channelGeneration, 3);
});

test("tenant scope, idempotency, and concurrent channel CAS fail closed", async () => {
  const { registry } = fixture();
  const submitted = await submit(registry, MANIFEST_V1);
  const duplicateRequest = request(
    "RUN_STATIC_CHECK",
    { releaseId: submitted.releaseId, expectedReleaseVersion: 1 },
    "duplicate-static",
  );
  const duplicates = await Promise.all(
    Array.from({ length: 32 }, () =>
      registry.execute(context(), duplicateRequest),
    ),
  );
  assert.equal(new Set(duplicates.map((item) => item.eventId)).size, 1);
  assert.equal(duplicates.filter((item) => item.duplicate).length, 31);

  await assert.rejects(
    registry.execute(context(TENANT_B), duplicateRequest),
    { code: "RELEASE_NOT_FOUND" },
  );
  const evaluated = await execute(
    registry,
    "RUN_SYNTHETIC_EVALUATION",
    {
      releaseId: submitted.releaseId,
      expectedReleaseVersion: 2,
      suiteId: "f04-frozen-evaluation-suite-v1",
      suiteSha256: SUITE_HASH,
    },
    "cas-eval",
  );
  const approved = await execute(
    registry,
    "APPROVE_RELEASE",
    {
      releaseId: submitted.releaseId,
      expectedReleaseVersion: evaluated.releaseVersion,
      approvedContentSha256: HASH_V1,
    },
    "cas-approve",
  );
  const publish = (suffix) =>
    execute(
      registry,
      "PUBLISH_RELEASE",
      {
        releaseId: submitted.releaseId,
        expectedReleaseVersion: approved.releaseVersion,
        channel: "PILOT",
        expectedChannelGeneration: 0,
        expectedCurrentReleaseId: null,
      },
      suffix,
    );
  const settled = await Promise.allSettled([
    publish("cas-publish-a"),
    publish("cas-publish-b"),
  ]);
  assert.equal(
    settled.filter((item) => item.status === "fulfilled").length,
    1,
  );
  assert.equal(
    settled.find((item) => item.status === "rejected").reason.code,
    "VERSION_CONFLICT",
  );
});

test("untested, unevaluated and failed-evaluation releases cannot be approved or published", async () => {
  const passing = fixture();
  const submitted = await submit(passing.registry, MANIFEST_V1);
  await assert.rejects(
    execute(
      passing.registry,
      "PUBLISH_RELEASE",
      {
        releaseId: submitted.releaseId,
        expectedReleaseVersion: 1,
        channel: "PILOT",
        expectedChannelGeneration: 0,
        expectedCurrentReleaseId: null,
      },
      "publish-untested",
    ),
    { code: "SKILL_NOT_APPROVED" },
  );
  await assert.rejects(
    execute(
      passing.registry,
      "APPROVE_RELEASE",
      {
        releaseId: submitted.releaseId,
        expectedReleaseVersion: 1,
        approvedContentSha256: HASH_V1,
      },
      "approve-untested",
    ),
    { code: "INVALID_TRANSITION" },
  );

  const failing = fixture({ evaluationStatus: "FAIL" });
  const failedSubmission = await submit(
    failing.registry,
    MANIFEST_V1,
    "failed-evaluation",
  );
  const staticResult = await execute(
    failing.registry,
    "RUN_STATIC_CHECK",
    {
      releaseId: failedSubmission.releaseId,
      expectedReleaseVersion: 1,
    },
    "failed-evaluation-static",
  );
  const evaluated = await execute(
    failing.registry,
    "RUN_SYNTHETIC_EVALUATION",
    {
      releaseId: failedSubmission.releaseId,
      expectedReleaseVersion: staticResult.releaseVersion,
      suiteId: "f04-frozen-evaluation-suite-v1",
      suiteSha256: SUITE_HASH,
    },
    "failed-evaluation-run",
  );
  assert.equal(evaluated.lifecycleState, "EVALUATION_FAILED");
  await assert.rejects(
    execute(
      failing.registry,
      "APPROVE_RELEASE",
      {
        releaseId: failedSubmission.releaseId,
        expectedReleaseVersion: evaluated.releaseVersion,
        approvedContentSha256: HASH_V1,
      },
      "approve-failed-evaluation",
    ),
    { code: "INVALID_TRANSITION" },
  );
});

test("a blocked F04 report cannot be approved", async () => {
  const { registry } = fixture({ evaluationStatus: "BLOCKED" });
  const submitted = await submit(
    registry,
    MANIFEST_V1,
    "blocked-f04-submit",
  );
  const checked = await execute(
    registry,
    "RUN_STATIC_CHECK",
    {
      releaseId: submitted.releaseId,
      expectedReleaseVersion: submitted.releaseVersion,
    },
    "blocked-f04-static",
  );
  const evaluated = await execute(
    registry,
    "RUN_SYNTHETIC_EVALUATION",
    {
      releaseId: submitted.releaseId,
      expectedReleaseVersion: checked.releaseVersion,
      suiteId: "f04-frozen-evaluation-suite-v1",
      suiteSha256: SUITE_HASH,
    },
    "blocked-f04-evaluate",
  );
  assert.equal(evaluated.lifecycleState, "EVALUATION_FAILED");
  await assert.rejects(
    execute(
      registry,
      "APPROVE_RELEASE",
      {
        releaseId: submitted.releaseId,
        expectedReleaseVersion: evaluated.releaseVersion,
        approvedContentSha256: HASH_V1,
      },
      "blocked-f04-approve",
    ),
    { code: "INVALID_TRANSITION" },
  );
});

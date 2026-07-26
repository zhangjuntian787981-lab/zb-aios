import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  createC13SyntheticSkillCatalog,
} from "../../lib/c13-synthetic-skill-catalog.mjs";
import {
  createPostgresSkillRegistryStore,
} from "../../lib/postgres-skill-registry-store.mjs";
import {
  createSkillRegistry,
} from "../../lib/skill-registry.mjs";

const { Pool } = pg;
const migrations = await Promise.all(
  [
    "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
    "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
    "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
    "../../implementation/p1/c13/postgresql/0019_skill_registry.sql",
    "../../implementation/p1/c13/postgresql/0020_skill_registry_runtime_roles.sql",
  ].map((path) => readFile(new URL(path, import.meta.url), "utf8")),
);
const rawCatalog = JSON.parse(
  await readFile(
    new URL(
      "../../implementation/p1/c13/synthetic-skill-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const reportBundleBytes = await readFile(
  new URL(
    "../../implementation/p1/c13/synthetic-evaluation-reports.v1.json",
    import.meta.url,
  ),
);
const blockedCatalog = createC13SyntheticSkillCatalog(
  rawCatalog,
  reportBundleBytes,
);
const catalog = Object.freeze({
  authorizationResources:
    blockedCatalog.authorizationResources,
  verifySource: blockedCatalog.verifySource,
  evaluate(input) {
    const blocked = blockedCatalog.evaluate(input);
    assert.equal(blocked.status, "BLOCKED");
    return {
      ...blocked,
      evidenceClass: "TEST_ONLY",
      evaluationMode: "TEST_ONLY_VALIDATED_FIXTURE",
      status: "PASS",
      caseCount: 10,
      reportedCaseCount: 10,
      caseResults: Array.from({ length: 10 }, (_, index) => {
        const caseId = `F04-E${String(index + 1).padStart(3, "0")}`;
        return {
          caseId,
          outcome: "PASS",
          score: 1,
          evidenceRef: `test://c13/postgres/${caseId}`,
        };
      }),
      failureCount: 0,
      zeroToleranceViolationCount: 0,
      humanBaselineDecisionRef:
        "test://c13/postgres/human-baseline",
      humanBaselineDecisionSha256:
        "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      reportRef: "test://c13/validated-f04-lifecycle-fixture",
      reportSha256:
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      reasonCode: "TEST_ONLY_VALIDATED_F04_LIFECYCLE_FIXTURE",
    };
  },
});
const TENANTS = rawCatalog.tenants;
const HUMAN = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION = "dlg_018f0000-0000-7000-8000-000000000020";
const RUNTIME_LOGIN = "c13_test_runtime_login";
const SCOPE_LOGIN = "c13_test_scope_login";
const F04_SHA =
  "sha256:628503bc3001d50d8eb30d89ce4f45e184918c63ba4fc0e8d3f6594d345a3259";

function config(user = process.env.C13_TEST_PGUSER, max = 50) {
  if (process.env.C13_TEST_EPHEMERAL !== "1") {
    throw new Error("C13_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C13_TEST_PGHOST",
    "C13_TEST_PGPORT",
    "C13_TEST_PGDATABASE",
    "C13_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C13_TEST_PGHOST,
    port: Number(process.env.C13_TEST_PGPORT),
    database: process.env.C13_TEST_PGDATABASE,
    user,
    max,
  };
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(",")}}`;
}

function deterministicIds(start = 1000) {
  let value = start;
  return () => {
    value += 1;
    return `018f0000-0000-7000-8000-${String(value).padStart(12, "0")}`;
  };
}

async function seedTenant(adminPool, tenant, index) {
  const time = "2026-07-26T16:00:00.000Z";
  await adminPool.query(
    `INSERT INTO aios_core.tenant_registry (
       tenant_id,tenant_kind,state,lifecycle_version,generation,
       creation_key,origin_ref,origin_hash,config_refs,
       resource_namespace_id,operation_id,created_at,updated_at
     ) VALUES (
       $1,'SYNTHETIC','PROVISIONING',1,1,$2,$3,$4,'[]'::jsonb,
       $5,$6,$7,$7
     )`,
    [
      tenant.tenantId,
      `c13-create-${index}`,
      `fixture://c13/tenant/${index}`,
      digest(`c13-origin-${index}`),
      `sns_018f0000-0000-7000-8000-${String(index + 100).padStart(12, "0")}`,
      `op_018f0000-0000-7000-8000-${String(index + 200).padStart(12, "0")}`,
      time,
    ],
  );
  for (const projection of [
    "AUTHORIZATION",
    "IDENTITY",
    "KNOWLEDGE",
    "SECRET_REFS",
    "STORAGE",
  ]) {
    await adminPool.query(
      `INSERT INTO aios_core.tenant_projection (
         tenant_id,generation,projection,desired_action,status,
         attempt_count,source_event_id,updated_at
       ) VALUES ($1,1,$2,'PROVISION','READY',1,$3,$4)`,
      [tenant.tenantId, projection, `c13-${index}-${projection}`, time],
    );
  }
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state='ACTIVE',lifecycle_version=2,updated_at=$2
      WHERE tenant_id=$1`,
    [tenant.tenantId, "2026-07-26T16:01:00.000Z"],
  );
  await adminPool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id,tenant_kind,lifecycle_version,generation,operation_id,
       state,last_event_id,updated_at
     ) VALUES ($1,'SYNTHETIC',2,1,$2,'ACTIVE',$3,$4)`,
    [
      tenant.tenantId,
      `op_018f0000-0000-7000-8000-${String(index + 200).padStart(12, "0")}`,
      `c13-active-${index}`,
      "2026-07-26T16:01:00.000Z",
    ],
  );
}

function identity(tenantId) {
  const purposeRef = "synthetic://c13/skill-governance";
  return {
    tenantId,
    tenantKind: "SYNTHETIC",
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
    authorizationStatus: "NOT_EVALUATED",
    humanSubject: { principalId: HUMAN, securityEpoch: 1 },
    workloadActor: { principalId: ACTOR, securityEpoch: 1 },
    purposeRef,
    delegationChain: [
      {
        delegationId: DELEGATION,
        delegatorPrincipalId: HUMAN,
        delegatePrincipalId: ACTOR,
        purposeRef,
      },
    ],
  };
}

function scope(tenantId, suffix = "read") {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId: `c13-${suffix}`,
    decisionId: `decision-${suffix}`,
    evidenceRef: `evidence://c13/${suffix}`,
    policyVersion: "c13-synthetic-policy-v1",
    operationId: "C13_READ_TENANT_SNAPSHOT",
    storagePath: "skill-registry",
  };
}

function registry(store, idFactory = deterministicIds()) {
  return createSkillRegistry({
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
      async resolveActionIdentity(_context, request) {
        return identity(request.expectedTenantId);
      },
    },
    authorizer: {
      async enforce(serverContext, request, descriptor) {
        const value = identity(serverContext.tenantId);
        return {
          trustSource: "C06_BOUND_DECISION_EVIDENCE",
          operationId: descriptor.operationId,
          decisionId: `decision-${descriptor.surface.toLowerCase()}`,
          evidenceRef: `evidence://c06/${descriptor.surface.toLowerCase()}`,
          policyVersion: "c06-synthetic-v1",
          tenantId: serverContext.tenantId,
          surface: descriptor.surface,
          resourceId: request.resourceId,
          humanPrincipalId: HUMAN,
          humanSecurityEpoch: 1,
          workloadActorPrincipalId: ACTOR,
          workloadActorSecurityEpoch: 1,
          leafDelegationId: DELEGATION,
          delegationChainSha256: digest(
            canonicalize(value.delegationChain),
          ),
          purposeRef: value.purposeRef,
        };
      },
    },
    store,
    catalog,
    idFactory,
    clock: (() => {
      let tick = 0;
      return () =>
        new Date(Date.UTC(2026, 6, 26, 16, 10, tick++)).toISOString();
    })(),
  });
}

function context(tenantId) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: ACTOR,
  };
}

function request(kind, command, suffix) {
  return {
    sessionToken: "synthetic-session",
    delegationId: DELEGATION,
    idempotencyKey: `c13-${suffix}`,
    correlationId: `c13-${suffix}`,
    command: { kind, ...command },
  };
}

async function submit(service, tenant, suffix) {
  const release = tenant.releases[0];
  return service.execute(
    context(tenant.tenantId),
    request(
      "SUBMIT_RELEASE",
      {
        skillId: null,
        expectedLatestSequence: 0,
        manifest: release.manifest,
        contentSha256: release.contentSha256,
        sourceReviewRef: release.sourceReviewRef,
        sourceReviewSha256: release.sourceReviewSha256,
      },
      `submit-${suffix}`,
    ),
  );
}

async function approve(
  service,
  tenant,
  submitted,
  suffix,
  releaseIndex = 0,
) {
  const staticResult = await service.execute(
    context(tenant.tenantId),
    request(
      "RUN_STATIC_CHECK",
      {
        releaseId: submitted.releaseId,
        expectedReleaseVersion: 1,
      },
      `static-${suffix}`,
    ),
  );
  const evaluated = await service.execute(
    context(tenant.tenantId),
    request(
      "RUN_SYNTHETIC_EVALUATION",
      {
        releaseId: submitted.releaseId,
        expectedReleaseVersion: staticResult.releaseVersion,
        suiteId: "f04-frozen-evaluation-suite-v1",
        suiteSha256: F04_SHA,
      },
      `eval-${suffix}`,
    ),
  );
  return service.execute(
    context(tenant.tenantId),
    request(
      "APPROVE_RELEASE",
      {
        releaseId: submitted.releaseId,
        expectedReleaseVersion: evaluated.releaseVersion,
        approvedContentSha256:
          tenant.releases[releaseIndex].contentSha256,
        approvedEvaluationReportRef:
          "test://c13/validated-f04-lifecycle-fixture",
        approvedEvaluationReportSha256:
          "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        approvedHumanBaselineDecisionRef:
          "test://c13/postgres/human-baseline",
        approvedHumanBaselineDecisionSha256:
          "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      },
      `approve-${suffix}`,
    ),
  );
}

function commitAckLossPool(pool) {
  let failOnce = true;
  return {
    async connect() {
      const client = await pool.connect();
      return new Proxy(client, {
        get(target, property) {
          if (property === "query") {
            return async (...args) => {
              const result = await target.query(...args);
              if (args[0] === "COMMIT" && failOnce) {
                failOnce = false;
                const error = new Error("Synthetic commit acknowledgement loss.");
                error.code = "08006";
                throw error;
              }
              return result;
            };
          }
          const value = target[property];
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    },
  };
}

test("C13 PostgreSQL preserves lifecycle, isolation, concurrency and restart recovery", async (t) => {
  const adminPool = new Pool(config());
  const pools = [];
  const pool = (user, max = 50) => {
    const value = new Pool(config(user, max));
    pools.push(value);
    return value;
  };
  t.after(async () => {
    await Promise.all(pools.map((value) => value.end()));
    await adminPool.end();
  });
  const safety = await adminPool.query(
    `SELECT current_database() AS database,
            to_regnamespace('aios_skill') AS skill_schema`,
  );
  assert.match(safety.rows[0].database, /^c13_test_[0-9]+$/);
  assert.equal(safety.rows[0].skill_schema, null);
  for (const migration of migrations) await adminPool.query(migration);
  for (const [index, tenant] of TENANTS.entries()) {
    await seedTenant(adminPool, tenant, index + 1);
  }
  await adminPool.query(`CREATE ROLE ${RUNTIME_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${SCOPE_LOGIN} LOGIN`);
  await adminPool.query(
    `GRANT aios_c13_runtime TO ${RUNTIME_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};`,
  );
  const runtimePool = pool(RUNTIME_LOGIN);
  const scopePool = pool(SCOPE_LOGIN);
  const store = createPostgresSkillRegistryStore({
    runtimePool,
    scopePool,
  });
  const service = registry(store);

  const submitted = await submit(service, TENANTS[0], "northstar");
  const approved = await approve(
    service,
    TENANTS[0],
    submitted,
    "northstar",
  );
  for (const assignment of [
    `static_report = static_report || '{"tampered":true}'::jsonb`,
    `evaluation_suite_sha256 =
       'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'`,
    `evaluation_report =
       evaluation_report || '{"tampered":true}'::jsonb`,
  ]) {
    await assert.rejects(
      adminPool.query(
        `UPDATE aios_skill.skill_release
            SET ${assignment},
                state_version = state_version + 1
          WHERE tenant_id = $1 AND release_id = $2`,
        [TENANTS[0].tenantId, submitted.releaseId],
      ),
      (error) =>
        error.constraint === "skill_release_immutable_guard",
    );
  }
  const publish = (suffix) =>
    service.execute(
      context(TENANTS[0].tenantId),
      request(
        "PUBLISH_RELEASE",
        {
          releaseId: submitted.releaseId,
          expectedReleaseVersion: approved.releaseVersion,
          channel: "PILOT",
          expectedChannelGeneration: 0,
          expectedCurrentReleaseId: null,
        },
        suffix,
      ),
    );
  const race = await Promise.allSettled([
    publish("pilot-northstar-a"),
    publish("pilot-northstar-b"),
  ]);
  assert.equal(
    race.filter((item) => item.status === "fulfilled").length,
    1,
  );
  assert.equal(
    race.find((item) => item.status === "rejected").reason.code,
    "VERSION_CONFLICT",
  );
  const pilot = race.find((item) => item.status === "fulfilled").value;
  const stable = await service.execute(
    context(TENANTS[0].tenantId),
    request(
      "PUBLISH_RELEASE",
      {
        releaseId: submitted.releaseId,
        expectedReleaseVersion: pilot.releaseVersion,
        channel: "STABLE",
        expectedChannelGeneration: 0,
        expectedCurrentReleaseId: null,
      },
      "stable-northstar",
    ),
  );
  const eventAuthorization = await adminPool.query(
    `SELECT command_kind,
            event #>> '{data,authorization,operationId}' AS operation_id,
            event #>> '{data,authorization,resourceId}' AS resource_id,
            event #>> '{data,authorization,decisionId}' AS decision_id,
            event #>> '{data,authorization,evidenceRef}' AS evidence_ref,
            event #>> '{data,authorization,purposeRef}' AS purpose_ref,
            event #>> '{data,approvalEvidence,evaluationReportSha256}'
              AS approved_report_sha256,
            event #>> '{data,approvalEvidence,humanBaselineDecisionSha256}'
              AS approved_human_decision_sha256
       FROM aios_skill.skill_event
      WHERE tenant_id = $1
      ORDER BY created_at,event_id`,
    [TENANTS[0].tenantId],
  );
  assert.deepEqual(
    eventAuthorization.rows.map((row) => row.operation_id),
    [
      "C13_SUBMIT_RELEASE",
      "C13_RUN_STATIC_CHECK",
      "C13_RUN_SYNTHETIC_EVALUATION",
      "C13_APPROVE_RELEASE",
      "C13_PUBLISH_RELEASE",
      "C13_PUBLISH_RELEASE",
    ],
  );
  for (const row of eventAuthorization.rows) {
    assert.match(row.resource_id, /--skill-/);
    assert.match(row.decision_id, /^decision-/);
    assert.match(row.evidence_ref, /^evidence:\/\/c06\//);
    assert.equal(
      row.purpose_ref,
      "synthetic://c13/skill-governance",
    );
  }
  const approvalEvent = eventAuthorization.rows.find(
    ({ command_kind: commandKind }) =>
      commandKind === "APPROVE_RELEASE",
  );
  assert.equal(
    approvalEvent.approved_report_sha256,
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  );
  assert.equal(
    approvalEvent.approved_human_decision_sha256,
    "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
  );

  const restartedStore = createPostgresSkillRegistryStore({
    runtimePool,
    scopePool,
  });
  const restarted = registry(restartedStore, deterministicIds(5000));
  const resolved = await restarted.resolveForRun(
    context(TENANTS[0].tenantId),
    {
      sessionToken: "synthetic-session",
      delegationId: DELEGATION,
      correlationId: "c13-restart-resolve",
      skillId: submitted.skillId,
      version: TENANTS[0].releases[0].manifest.version,
      contentSha256: TENANTS[0].releases[0].contentSha256,
      channel: "STABLE",
    },
  );
  assert.equal(resolved.releaseId, submitted.releaseId);
  assert.equal(resolved.scriptsEnabled, false);
  assert.equal(resolved.allowedToolsGrantAuthorization, false);

  await restarted.execute(
    context(TENANTS[0].tenantId),
    request(
      "WITHDRAW_RELEASE",
      {
        releaseId: submitted.releaseId,
        expectedReleaseVersion: stable.releaseVersion,
        reasonRef: "synthetic://c13/postgres/withdraw/v1",
      },
      "withdraw-northstar-v1",
    ),
  );
  const nextRelease = TENANTS[0].releases[1];
  const nextSubmitted = await restarted.execute(
    context(TENANTS[0].tenantId),
    request(
      "SUBMIT_RELEASE",
      {
        skillId: submitted.skillId,
        expectedLatestSequence: 1,
        manifest: nextRelease.manifest,
        contentSha256: nextRelease.contentSha256,
        sourceReviewRef: nextRelease.sourceReviewRef,
        sourceReviewSha256: nextRelease.sourceReviewSha256,
      },
      "submit-northstar-v2-after-withdraw",
    ),
  );
  const nextApproved = await approve(
    restarted,
    TENANTS[0],
    nextSubmitted,
    "northstar-v2-after-withdraw",
    1,
  );
  const nextPilot = await restarted.execute(
    context(TENANTS[0].tenantId),
    request(
      "PUBLISH_RELEASE",
      {
        releaseId: nextSubmitted.releaseId,
        expectedReleaseVersion: nextApproved.releaseVersion,
        channel: "PILOT",
        expectedChannelGeneration: 2,
        expectedCurrentReleaseId: null,
      },
      "publish-northstar-v2-after-withdraw",
    ),
  );
  assert.equal(nextPilot.channelGeneration, 3);

  const cedarSubmitted = await submit(service, TENANTS[2], "cedar");
  const staticRequest = request(
    "RUN_STATIC_CHECK",
    {
      releaseId: cedarSubmitted.releaseId,
      expectedReleaseVersion: 1,
    },
    "cedar-static-duplicate",
  );
  const duplicates = await Promise.all(
    Array.from({ length: 32 }, () =>
      service.execute(context(TENANTS[2].tenantId), staticRequest),
    ),
  );
  assert.equal(new Set(duplicates.map((item) => item.eventId)).size, 1);
  assert.equal(duplicates.filter((item) => item.duplicate).length, 31);
  await assert.rejects(
    service.execute(context(TENANTS[1].tenantId), staticRequest),
    { code: "RELEASE_NOT_FOUND" },
  );

  const faultRuntimePool = commitAckLossPool(runtimePool);
  const faultStore = createPostgresSkillRegistryStore({
    runtimePool: faultRuntimePool,
    scopePool,
  });
  const faultService = registry(faultStore, deterministicIds(9000));
  const recovered = await submit(faultService, TENANTS[1], "blue-recovery");
  assert.equal(recovered.duplicate, true);
  const blueSnapshot = await store.readTenantSnapshot(
    scope(TENANTS[1].tenantId, "blue-snapshot"),
  );
  assert.deepEqual(blueSnapshot.counts, {
    releases: 1,
    channels: 0,
    events: 1,
    receipts: 1,
  });
});

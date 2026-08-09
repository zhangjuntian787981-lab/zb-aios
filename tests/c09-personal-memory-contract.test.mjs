import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

async function text(path) {
  return readFile(new URL(path, root), "utf8");
}

async function json(path) {
  return JSON.parse(await text(path));
}

test("C09 OpenAPI freezes the owner, consent, category and recall boundary", async () => {
  const api = await json(
    "implementation/p1/c09/personal-memory.openapi.v1.json",
  );
  const boundary = api["x-c09-boundary"];
  assert.equal(boundary.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(boundary.data_classification, "SYNTHETIC_ONLY");
  assert.equal(boundary.production_verification_status, "NOT_VERIFIED");
  assert.equal(boundary.enterprise_integration_status, "P3_REQUIRED");
  assert.equal(boundary.enterprise_connectors, "C0_DISABLED");
  assert.equal(
    boundary.owner_key,
    "TENANT_ID_PLUS_C05_STABLE_HUMAN_PRINCIPAL_ID",
  );
  assert.equal(boundary.session_is_owner_key, false);
  assert.equal(
    boundary.principal_scope_binding,
    "FINAL_C05_STABLE_HUMAN_PRINCIPAL_ID",
  );
  assert.equal(boundary.model_maximum_write_state, "CANDIDATE");
  assert.deepEqual(boundary.retention_worker.table_privileges, []);
  assert.equal(boundary.retention_worker.returns_plaintext, false);
  assert.equal(
    boundary.retention_worker.identity_stability,
    "C05_RECHECK_AFTER_C06",
  );
  assert.deepEqual(
    boundary.human_consent.persisted_evidence_fields,
    [
      "tenantId",
      "humanPrincipalId",
      "memoryId",
      "expectedVersion",
      "contentSha256",
      "expiresAt",
      "purpose",
      "tokenSha256",
      "consumedAt",
    ],
  );
  assert.equal(
    boundary.human_consent.reject_unknown_evidence_fields,
    true,
  );
  assert.equal(boundary.human_consent.persist_plaintext_token, false);
  assert.deepEqual(boundary.allowed_categories, [
    "PREFERENCE",
    "WORK_STATE",
  ]);
  assert.deepEqual(boundary.recall_filter_order, [
    "TENANT",
    "STABLE_PRINCIPAL",
    "CONFIRMED_STATE",
    "NOT_EXPIRED",
    "C06_ITEM_PRE_READ_AUTHORIZATION",
    "C05_ITEM_PRE_READ_IDENTITY_RECHECK",
    "READ_EXACT_CONTENT_VERSION",
    "CONTENT_BINDING_AND_SHA256_VERIFICATION",
    "C06_ITEM_POST_READ_AUTHORIZATION",
    "C05_ITEM_POST_READ_IDENTITY_RECHECK",
    "DELIVER_CONTENT",
  ]);
  assert.equal(
    boundary.postgres_pool_role_verification.membership,
    "RECURSIVE_EXACT_REQUIRED_AIOS_ROLE",
  );
  assert.equal(
    boundary.postgres_pool_role_verification
      .reject_unexpected_aios_roles,
    true,
  );
  assert.equal(
    api.paths["/internal/v1/personal-memory:recall"].post[
      "x-item-identity-recheck-after-authorization"
    ],
    true,
  );
  assert.equal(
    api.components.schemas.ConfirmCandidate.allOf[2].properties
      .humanConsentToken.$ref,
    "#/components/schemas/HumanConsentToken",
  );
  assert.equal(JSON.stringify(api).includes("explicitConfirmation"), false);
  assert.equal(
    api.components.schemas.MaterializeExpiry.allOf[2].properties.kind
      .const,
    "MATERIALIZE_EXPIRY",
  );
  assert.equal(
    api.paths["/internal/v1/personal-memory:recall"].post[
      "x-content-read-after-item-authorization"
    ],
    true,
  );
  assert.deepEqual(
    api.paths["/internal/v1/personal-memory/commands:execute"].post[
      "x-runtime-order"
    ].slice(0, 4),
    [
      "C05_RESOLVE_STABLE_HUMAN",
      "C06_ENFORCE_OPERATION",
      "C06_BIND_HUMAN_ACTOR_AND_DELEGATION",
      "C05_FINAL_IDENTITY_RECHECK",
    ],
  );
  const runtimeOrder =
    api.paths["/internal/v1/personal-memory/commands:execute"].post[
      "x-runtime-order"
    ];
  assert.notEqual(
    runtimeOrder.indexOf("COMMAND_RECEIPT_REPLAY_CHECK"),
    -1,
  );
  assert.ok(
    runtimeOrder.indexOf("COMMAND_RECEIPT_REPLAY_CHECK") <
      runtimeOrder.indexOf("HUMAN_CONSENT_VERIFY_AND_CONSUME"),
  );
});

test("C09 migration enforces allowed categories, terminal scrubbing and double-scope RLS", async () => {
  const schema = await text(
    "implementation/p1/c09/postgresql/0015_personal_memory.sql",
  );
  const roles = await text(
    "implementation/p1/c09/postgresql/0016_personal_memory_runtime_roles.sql",
  );
  const restoreRoles = await text(
    "implementation/p1/c09/postgresql/c09_restore_role_bootstrap.v1.sql",
  );
  const runner = await text(
    "scripts/run-c09-personal-memory-postgres-tests.sh",
  );
  assert.match(
    schema,
    /category IN \('PREFERENCE', 'WORK_STATE'\)/,
  );
  assert.match(
    schema,
    /state IN \('EXPIRED', 'DELETED'\)[\s\S]*content IS NULL/,
  );
  assert.match(schema, /human_consent_evidence jsonb/);
  assert.match(
    schema,
    /human_consent_evidence \?& ARRAY\[[\s\S]*'tokenSha256'[\s\S]*'consumedAt'/,
  );
  assert.match(
    schema,
    /human_consent_evidence - ARRAY\[[\s\S]*\] = '\{\}'::jsonb/,
  );
  assert.match(
    schema,
    /CREATE FUNCTION aios_personal_memory\.runtime_principal_allows/,
  );
  assert.match(
    schema,
    /aios_data\.runtime_scope_allows\(row_tenant_id, row_tenant_kind\)/,
  );
  assert.match(schema, /row_principal_id = scope\.principal_id/);
  assert.match(
    schema,
    /principal\.lifecycle_version =[\s\S]*scope_principal_lifecycle_version/,
  );
  assert.match(
    schema,
    /principal\.security_epoch = scope_principal_security_epoch/,
  );
  assert.equal(
    (
      schema.match(
        /ALTER TABLE aios_personal_memory\.[a-z_]+\s+FORCE ROW LEVEL SECURITY;/g,
      ) ?? []
    ).length,
    5,
  );
  assert.match(
    roles,
    /aios_c09_runtime[\s\S]*NOBYPASSRLS/,
  );
  assert.match(
    roles,
    /GRANT SELECT, INSERT ON[\s\S]*memory_event[\s\S]*command_receipt/,
  );
  assert.doesNotMatch(
    roles,
    /GRANT[\s\S]{0,120}DELETE[\s\S]{0,120}aios_c09_runtime/,
  );
  assert.match(
    roles,
    /runtime_principal_allows\([\s\S]*tenant_id,[\s\S]*tenant_kind,[\s\S]*principal_id/,
  );
  assert.match(
    roles,
    /CREATE ROLE aios_c09_retention_runtime[\s\S]*NOBYPASSRLS/,
  );
  assert.match(
    schema,
    /SECURITY DEFINER[\s\S]*runtime_scope_allows\([\s\S]*scope_tenant_id,[\s\S]*'SYNTHETIC'/,
  );
  assert.match(
    schema,
    /state NOT IN \('CANDIDATE','CONFIRMED'\)[\s\S]*expires_at > effective_now/,
  );
  assert.equal(
    (
      roles.match(
        /GRANT (?:SELECT|INSERT|UPDATE|DELETE)[\s\S]*?;/g,
      ) ?? []
    ).some((grant) => grant.includes("aios_c09_retention_runtime")),
    false,
  );
  assert.equal((restoreRoles.match(/'aios_/g) ?? []).length, 11);
  assert.doesNotMatch(restoreRoles, /\sc09_test_/);
  assert.doesNotMatch(restoreRoles, /\sLOGIN\b/);
  assert.equal(
    (runner.match(/\/initdb"/g) ?? []).length,
    2,
  );
  assert.match(runner, /c09_restore_role_bootstrap\.v1\.sql/);
  assert.match(runner, /C09_TEST_SOURCE_SYSTEM_IDENTIFIER/);
  assert.match(
    runner,
    /C09_TEST_RESTORED=1[\s\S]*c09-personal-memory-postgres-restore\.test\.mjs/,
  );
});

test("C09 matrix covers every required P1 Synthetic evidence class", async () => {
  const matrix = await json(
    "implementation/p1/c09/memory-matrix.v1.json",
  );
  assert.equal(matrix.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(matrix.implementationStatus, "IMPLEMENTED");
  assert.equal(matrix.verificationStatus, "VERIFIED");
  assert.equal(matrix.productionVerificationStatus, "NOT_VERIFIED");
  assert.ok(matrix.cases.length >= 25);
  assert.equal(
    new Set(matrix.cases.map(({ caseId }) => caseId)).size,
    matrix.cases.length,
  );
  assert.equal(
    matrix.cases.every(
      ({ evidenceStatus }) =>
        evidenceStatus === "VERIFIED_P1_SYNTHETIC",
    ),
    true,
  );
  for (const required of [
    "MODEL-CANDIDATE-01",
    "HUMAN-CONSENT-BINDING-01",
    "HUMAN-CONSENT-EVIDENCE-CLOSED-01",
    "HUMAN-CONSENT-ONE-TIME-01",
    "CHECKPOINT-PAUSE-01",
    "EXPIRY-MATERIALIZE-IDEMPOTENT-01",
    "CROSS-USER-01",
    "CROSS-TENANT-01",
    "C06-ITEM-DENY-01",
    "C06-BINDING-01",
    "C05-RECHECK-01",
    "C05-RECALL-ITEM-RECHECK-01",
    "C06-POST-READ-REVOKE-01",
    "C05-POST-READ-RECHECK-01",
    "RECALL-CONTENT-BINDING-01",
    "PG-RECALL-VERSION-RACE-01",
    "FORBIDDEN-CATEGORY-01",
    "DELETE-SCRUB-01",
    "RECOVERY-SCRUB-01",
    "PG-RESTORE-RUNTIME-01",
    "REPLAY-CONFLICT-01",
    "PG-UNIQUE-ERROR-MAP-01",
    "CONCURRENT-CONFIRM-01",
    "PG-DOUBLE-SCOPE-01",
    "SCOPE-PRINCIPAL-BINDING-01",
    "RETENTION-WORKER-EXECUTION-01",
    "RETENTION-STORE-BINDING-01",
    "PG-POOL-SCOPE-CLEAR-01",
    "PG-PRINCIPAL-REVOCATION-01",
    "PG-ROLE-01",
  ]) {
    assert.ok(matrix.cases.some(({ caseId }) => caseId === required));
  }
});

test("C09 README preserves P1 and enterprise truth-source exclusions", async () => {
  const readme = await text("implementation/p1/c09/README.md");
  assert.match(readme, /只接受三个冻结 Synthetic Tenant/);
  assert.match(readme, /Tenant ID \+ C05 stable Human Principal ID/);
  assert.match(readme, /模型入口只能创建 `CANDIDATE`/);
  assert.match(readme, /Human consent artifact/);
  assert.match(readme, /固定九字段白名单/);
  assert.match(readme, /`MATERIALIZE_EXPIRY`/);
  assert.match(readme, /aios_c09_retention_runtime/);
  assert.match(readme, /fresh `initdb`/);
  assert.match(readme, /11 个 NOLOGIN/);
  assert.match(readme, /完整比较 Human、workload Actor、Delegation chain/);
  assert.match(readme, /除登录角色自身外，唯一\s+有效成员/);
  assert.match(readme, /18 个事务身份 GUC/);
  assert.match(readme, /未提交的 Human consent.*重新批准/);
  assert.match(readme, /恢复库[\s\S]*FORCE RLS/);
  assert.match(readme, /receipt[\s\S]*暂停[\s\S]*自然过期/);
  assert.match(readme, /企业接入与生产结论保持\s+`NOT_VERIFIED`/);
  assert.match(readme, /不保存 ERP、BI、OA/);
});

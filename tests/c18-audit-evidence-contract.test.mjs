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

test("C18 OpenAPI freezes Synthetic-only append, reader and Outbox boundaries", async () => {
  const api = await json(
    "implementation/p1/c18/audit.openapi.v1.json",
  );
  const boundary = api["x-c18-boundary"];
  assert.equal(boundary.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(boundary.data_classification, "SYNTHETIC_ONLY");
  assert.equal(boundary.production_verification_status, "NOT_VERIFIED");
  assert.equal(boundary.enterprise_integration_status, "P3_REQUIRED");
  assert.equal(boundary.enterprise_connectors, "C0_DISABLED");
  assert.equal(boundary.canonicalization, "RFC_8785");
  assert.equal(boundary.c08_event_is_c18_audit, false);
  assert.equal(boundary.c08_outbox_is_c18_outbox, false);
  assert.deepEqual(boundary.postgresql_roles, {
    append: "aios_c18_writer",
    business_query: "aios_c18_reader",
    outbox_delivery: "aios_c18_outbox_worker",
    recovery_export: "aios_c18_recovery_reader",
    recovery_import: "aios_c18_recovery_writer",
    retention_cleanup: "aios_c18_retention_worker",
  });
  assert.equal(
    boundary.outbox_lease_clock,
    "POSTGRESQL_STATEMENT_TIMESTAMP",
  );
  assert.equal(boundary.recovery_bundle, "c18-audit-recovery.v1");
  assert.equal(boundary.immutable_delivery_intent, true);
  assert.deepEqual(
    api.paths["/internal/v1/audit-evidence:append"].post[
      "x-runtime-order"
    ],
    [
      "C05_RESOLVE_ACTION_IDENTITY",
      "FROZEN_SYNTHETIC_EVIDENCE_BUNDLE",
      "C05_FINAL_IDENTITY_RECHECK",
      "C03_FINAL_ACTIVE_ADMISSION",
      "C07_SIGNED_TENANT_SCOPE",
      "ATOMIC_AUDIT_EVENT_INTENT_OUTBOX_RECEIPT",
    ],
  );
  assert.equal(
    api.components.schemas.AppendRequest.additionalProperties,
    false,
  );
  assert.equal(
    api.components.schemas.MetadataOnlyPayload.additionalProperties,
    false,
  );
  assert.equal(
    api.paths["/internal/v1/audit-evidence:export"].post[
      "x-postgresql-role"
    ],
    "aios_c18_recovery_reader",
  );
  assert.deepEqual(api.components.schemas.AuditExport.required, [
    "schemaVersion",
    "tenantId",
    "tenantKind",
    "head",
    "events",
    "deliveryIntents",
    "receipts",
    "outbox",
    "recoverySha256",
  ]);
  assert.equal(
    api.components.schemas.AuditExport.properties.schemaVersion.const,
    "c18-audit-recovery.v1",
  );
  assert.equal(
    api.paths["/internal/v1/audit-evidence:restore"].post[
      "x-postgresql-role"
    ],
    "aios_c18_recovery_writer",
  );
  assert.equal(
    api.components.schemas.IdentityEvidence.properties.artifact.$ref,
    "#/components/schemas/ActionIdentityArtifact",
  );
});

test("C18 CloudEvent remains a strict specialization of the F03 envelope", async () => {
  const f03 = await json(
    "implementation/p0/f03/schemas/cloud-event.v1.schema.json",
  );
  const c18 = await json(
    "implementation/p1/c18/audit-event.v1.schema.json",
  );
  for (const field of f03.required) {
    assert.ok(c18.required.includes(field), field);
  }
  assert.equal(c18.additionalProperties, false);
  assert.equal(c18.properties.specversion.const, "1.0");
  assert.equal(c18.properties.tenantkind.const, "SYNTHETIC");
  assert.equal(c18.properties.synthetic.const, true);
  assert.equal(
    c18.properties.type.const,
    "product.aios.audit-evidence-recorded.v1",
  );
  assert.equal(c18.properties.data.additionalProperties, false);
  assert.equal(
    c18["x-c18-payload-identity-artifact"],
    "c18-action-identity-artifact.v1",
  );
  assert.equal(
    c18["x-c18-recovery-bundle"],
    "c18-audit-recovery.v1",
  );
  for (const prohibited of [
    "body",
    "prompt",
    "tool_arguments",
    "model_input",
    "model_output",
    "file_bytes",
    "secret",
    "token",
  ]) {
    assert.equal(
      Object.hasOwn(c18.properties.data.properties, prohibited),
      false,
    );
  }
});
test("C18 PROV Profile requires every evidence class and standard relation", async () => {
  const profile = await json(
    "implementation/p1/c18/w3c-prov-profile.v1.json",
  );
  assert.equal(profile.baseStandard, "W3C PROV-DM");
  assert.equal(profile.productionVerificationStatus, "NOT_VERIFIED");
  for (const type of [
    "aios:IdentityEvidence",
    "aios:AuthorizationEvidence",
    "aios:ModelEvidence",
    "aios:KnowledgeEvidence",
    "aios:SkillEvidence",
    "aios:ToolEvidence",
    "aios:HumanDecisionEvidence",
    "aios:ResultEvidence",
    "aios:C08StateEvidence",
  ]) {
    assert.ok(profile.requiredEntityTypes.includes(type), type);
  }
  const relations = profile.allowedRelations.map(({ type }) => type);
  for (const relation of [
    "prov:wasAssociatedWith",
    "prov:actedOnBehalfOf",
    "prov:used",
    "prov:wasGeneratedBy",
    "prov:wasDerivedFrom",
  ]) {
    assert.ok(relations.includes(relation), relation);
  }
  assert.equal(
    profile.identityArtifact.registryResolutionRequired,
    true,
  );
  assert.equal(profile.identityArtifact.rawSessionTokenAllowed, false);
});

test("C18 retention separates immutable evidence from purgeable delivery state", async () => {
  const policy = await json(
    "implementation/p1/c18/retention-policy.v1.json",
  );
  assert.equal(policy.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(policy.externalArchiveStatus, "NOT_VERIFIED");
  assert.equal(policy.checkpointSignatureStatus, "NOT_VERIFIED");
  assert.equal(
    policy.queryContract.businessAdministratorRole,
    "aios_c18_reader",
  );
  assert.equal(policy.queryContract.maximumRows, 500);
  assert.equal(policy.queryContract.crossTenantQuery, false);
  assert.equal(policy.queryContract.updateAllowed, false);
  assert.equal(policy.queryContract.deleteAllowed, false);
  assert.ok(
    policy.classes.some(
      ({ retentionClass, payloadMode, appliesTo }) =>
        retentionClass === "AUDIT_7Y" &&
        payloadMode === "METADATA_REFERENCES_HASHES_ONLY" &&
        appliesTo.includes("AUDIT_DELIVERY_INTENT"),
    ),
  );
  const deliveryState = policy.classes.find(
    ({ retentionClass }) => retentionClass === "OUTBOX_DELIVERY_30D",
  );
  assert.equal(
    deliveryState.automaticDeletionStatus,
    "IMPLEMENTED_P1_BOUNDED",
  );
  assert.equal(
    policy.retentionCleanupContract.postgresqlRole,
    "aios_c18_retention_worker",
  );
  assert.equal(
    policy.recoveryContract.postgresqlRole,
    "aios_c18_recovery_reader",
  );
  assert.ok(
    policy.recoveryContract.includes.includes(
      "AUDIT_DELIVERY_INTENTS",
    ),
  );
  assert.equal(
    policy.recoveryImportContract.postgresqlRole,
    "aios_c18_recovery_writer",
  );
  assert.equal(
    policy.recoveryImportContract.businessRoleAccess,
    false,
  );
});

test("C18 SQL fixes FORCE RLS, append-only guards and separated grants", async () => {
  const schema = await text(
    "implementation/p1/c18/postgresql/0023_audit_evidence.sql",
  );
  const roles = await text(
    "implementation/p1/c18/postgresql/0024_audit_evidence_runtime_roles.sql",
  );
  const restoreRoles = await text(
    "implementation/p1/c18/postgresql/c18_restore_role_bootstrap.v1.sql",
  );
  const postgresRunner = await text(
    "scripts/run-c18-audit-evidence-postgres-tests.sh",
  );
  assert.equal(
    (
      schema.match(
        /ALTER TABLE aios_audit\.[a-z_]+\s+FORCE ROW LEVEL SECURITY;/g,
      ) ?? []
    ).length,
    5,
  );
  assert.match(schema, /audit_event_delivery_intent_pair/);
  assert.match(schema, /audit_event_receipt_pair/);
  assert.match(schema, /audit_event_outbox_pair/);
  assert.match(schema, /audit_delivery_intent_append_only_guard/);
  assert.match(schema, /audit_append_only_guard/);
  assert.match(schema, /audit_head_transition_guard/);
  assert.match(schema, /audit_event_metadata_only/);
  assert.match(schema, /statement_timestamp\(\) - interval '30 days'/);
  assert.match(roles, /CREATE ROLE aios_c18_writer[\s\S]*NOBYPASSRLS/);
  assert.match(roles, /CREATE ROLE aios_c18_reader[\s\S]*NOBYPASSRLS/);
  assert.match(
    roles,
    /CREATE ROLE aios_c18_outbox_worker[\s\S]*NOBYPASSRLS/,
  );
  assert.match(
    roles,
    /CREATE ROLE aios_c18_recovery_reader[\s\S]*NOBYPASSRLS/,
  );
  assert.match(
    roles,
    /CREATE ROLE aios_c18_recovery_writer[\s\S]*NOBYPASSRLS/,
  );
  assert.match(
    roles,
    /CREATE ROLE aios_c18_retention_worker[\s\S]*NOBYPASSRLS/,
  );
  assert.match(
    roles,
    /GRANT SELECT ON TABLE[\s\S]*audit_head,[\s\S]*audit_event[\s\S]*TO aios_c18_reader/,
  );
  assert.doesNotMatch(
    roles,
    /GRANT[\s\S]{0,100}(?:UPDATE|DELETE)[\s\S]{0,100}aios_c18_reader/,
  );
  assert.doesNotMatch(roles, /audit_outbox_writer_select_policy/);
  assert.match(
    roles,
    /GRANT DELETE ON TABLE aios_audit\.audit_outbox\s+TO aios_c18_retention_worker/,
  );
  assert.doesNotMatch(
    roles,
    /GRANT DELETE ON TABLE aios_audit\.audit_event/,
  );
  for (const role of [
    "aios_c07_owner",
    "aios_c07_lifecycle_runtime",
    "aios_c07_data_runtime",
    "aios_c07_scope_runtime",
    "aios_c07_restore_runtime",
    "aios_c18_owner",
    "aios_c18_writer",
    "aios_c18_reader",
    "aios_c18_outbox_worker",
    "aios_c18_recovery_reader",
    "aios_c18_recovery_writer",
    "aios_c18_retention_worker",
  ]) {
    assert.match(
      restoreRoles,
      new RegExp(
        `CREATE ROLE ${role}[\\s\\S]*?NOLOGIN[\\s\\S]*?NOBYPASSRLS;`,
      ),
    );
  }
  assert.match(
    postgresRunner,
    /c18_restore_role_bootstrap\.v1\.sql/,
  );
  assert.match(postgresRunner, /pg_control_system\(\)/);
  assert.match(
    postgresRunner,
    /tests\/integration\/c18-audit-evidence-postgres-restore\.test\.mjs/,
  );
});

test("C18 frozen registry resolves all catalog evidence by exact digest", async () => {
  const catalog = await json(
    "implementation/p1/c18/synthetic-evidence-catalog.v1.json",
  );
  const registry = await json(
    "implementation/p1/c18/synthetic-evidence-registry.v1.json",
  );
  assert.equal(registry.status, "SYNTHETIC_ONLY");
  assert.equal(registry.entries.length, 27);
  const registered = new Map(
    registry.entries.map((entry) => [
      `${entry.tenantId}\u0000${entry.evidenceRef}`,
      entry,
    ]),
  );
  for (const tenant of catalog.tenants) {
    for (const bundle of tenant.bundles) {
      const evidence = [
        bundle.authorization,
        bundle.model,
        ...bundle.knowledge,
        bundle.skill,
        bundle.tool,
        bundle.humanDecision,
        bundle.result,
        bundle.c08State,
      ];
      for (const item of evidence) {
        const entry = registered.get(
          `${tenant.tenantId}\u0000${item.evidenceRef}`,
        );
        assert.ok(entry, item.evidenceRef);
        assert.equal(entry.version, item.version);
        assert.equal(entry.sha256, item.sha256);
      }
    }
  }
});

test("C18 verification matrix covers every required failure and recovery class", async () => {
  const matrix = await json(
    "implementation/p1/c18/audit-verification-matrix.v1.json",
  );
  assert.equal(matrix.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(matrix.verificationStatus, "EVIDENCE_CANDIDATE");
  assert.equal(matrix.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(
    new Set(matrix.cases.map(({ caseId }) => caseId)).size,
    matrix.cases.length,
  );
  assert.ok(matrix.cases.length >= 30);
  assert.ok(
    matrix.cases.every(
      ({ evidenceStatus }) =>
        evidenceStatus === "VERIFIED_P1_SYNTHETIC",
    ),
  );
  for (const required of [
    "PROV-CHAIN-01",
    "BODY-DENY-01",
    "IDEMPOTENCY-01",
    "CONCURRENT-CHAIN-01",
    "OUTBOX-CRASH-01",
    "OUTBOX-ACK-LOSS-01",
    "THREE-TENANT-01",
    "TAMPER-01",
    "RESTORE-01",
    "RETENTION-QUERY-01",
    "PG-ATOMIC-OUTBOX-01",
    "PG-FORCE-RLS-01",
    "PG-READER-IMMUTABLE-01",
    "PG-WORKER-SEPARATION-01",
    "PG-BODY-DENY-01",
    "JCS-TOPLEVEL-STRING-01",
    "JCS-SPARSE-ARRAY-01",
    "EVIDENCE-DIGEST-01",
    "C05-SECURITY-SNAPSHOT-01",
    "CLOSED-PAYLOAD-PROV-01",
    "CREATED-AT-HASH-01",
    "RECOVERY-RECEIPT-01",
    "RECOVERY-OUTBOX-01",
    "RECOVERY-HEAD-INTENT-01",
    "IDENTITY-ARTIFACT-01",
    "PG-FRESH-RESTORE-01",
    "PG-DUMP-RESTORE-01",
    "PG-EVENT-PAIR-01",
    "PG-INITIAL-OUTBOX-PAIR-01",
    "PG-DATABASE-CLOCK-LEASE-01",
    "PG-RETENTION-SPLIT-01",
  ]) {
    assert.ok(matrix.cases.some(({ caseId }) => caseId === required));
  }
});

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
  });
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
      "ATOMIC_AUDIT_EVENT_OUTBOX_RECEIPT",
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
});

test("C18 retention is bounded, read-only and keeps archive claims unverified", async () => {
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
      ({ retentionClass, payloadMode }) =>
        retentionClass === "AUDIT_7Y" &&
        payloadMode === "METADATA_REFERENCES_HASHES_ONLY",
    ),
  );
});

test("C18 SQL fixes FORCE RLS, append-only guards and separated grants", async () => {
  const schema = await text(
    "implementation/p1/c18/postgresql/0023_audit_evidence.sql",
  );
  const roles = await text(
    "implementation/p1/c18/postgresql/0024_audit_evidence_runtime_roles.sql",
  );
  assert.equal(
    (
      schema.match(
        /ALTER TABLE aios_audit\.[a-z_]+\s+FORCE ROW LEVEL SECURITY;/g,
      ) ?? []
    ).length,
    4,
  );
  assert.match(schema, /audit_event_outbox_pair/);
  assert.match(schema, /audit_append_only_guard/);
  assert.match(schema, /audit_head_transition_guard/);
  assert.match(schema, /audit_event_metadata_only/);
  assert.match(roles, /CREATE ROLE aios_c18_writer[\s\S]*NOBYPASSRLS/);
  assert.match(roles, /CREATE ROLE aios_c18_reader[\s\S]*NOBYPASSRLS/);
  assert.match(
    roles,
    /CREATE ROLE aios_c18_outbox_worker[\s\S]*NOBYPASSRLS/,
  );
  assert.match(
    roles,
    /GRANT SELECT ON TABLE[\s\S]*audit_head,[\s\S]*audit_event[\s\S]*TO aios_c18_reader/,
  );
  assert.doesNotMatch(
    roles,
    /GRANT[\s\S]{0,100}(?:UPDATE|DELETE)[\s\S]{0,100}aios_c18_reader/,
  );
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
  assert.ok(matrix.cases.length >= 20);
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
  ]) {
    assert.ok(matrix.cases.some(({ caseId }) => caseId === required));
  }
});

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createG1SyntheticRuntime } from "../../lib/g1-synthetic-runtime.mjs";

export const G1_MATRIX_NOW = "2026-07-27T00:00:00.000Z";
export const G1_MATRIX_PROJECTIONS = Object.freeze([
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
]);

export async function loadG1MatrixJson(relativePath) {
  return JSON.parse(
    await readFile(new URL(`../../${relativePath}`, import.meta.url), "utf8"),
  );
}

export async function createG1MatrixDeployment() {
  return (await createG1SyntheticRuntime()).deploy();
}

export function stableG1DeploymentProjection(deployment) {
  return {
    schemaVersion: "g1-stable-deployment-projection.v1",
    tenants: deployment.tenants.map((tenant) => ({
      tenantId: tenant.tenantId,
      tenantKind: tenant.tenantKind,
      users: tenant.users.map((user) => ({
        fixtureUserId: user.fixtureUserId,
        role: user.role,
        principalId: user.principalId,
      })),
    })),
  };
}

export function g1MatrixSha256(value) {
  return `sha256:${createHash("sha256")
    .update(JSON.stringify(value))
    .digest("hex")}`;
}

export function g1DeploymentSha256(deployment) {
  return g1MatrixSha256(stableG1DeploymentProjection(deployment));
}

export function g1RestoreResourceId(user) {
  return `${user.fixtureUserId}-restore-replica`;
}

export function g1PositiveCaseId(surface, tenantIndex, userIndex) {
  return (
    `g1-${surface.toLowerCase()}-${tenantIndex + 1}-` +
    `${userIndex + 1}-positive`
  );
}

export function g1Attribution(tenant, user) {
  return {
    tenantId: tenant.tenantId,
    userId: user.fixtureUserId,
    role: user.role,
    principalId: user.principalId,
  };
}

export function g1RestoreValue(tenant, user, tenantIndex, userIndex) {
  return {
    attribution: g1Attribution(tenant, user),
    marker:
      `RESTORE_REPLICA:` +
      g1PositiveCaseId("RESTORE_REPLICA", tenantIndex, userIndex),
  };
}

export function g1LifecycleEvent(tenant, suffix, type, version, state) {
  return {
    specversion: "1.0",
    id: `evt-g1-matrix-${tenant.tenantId.slice(-4)}-${suffix}`,
    source: "/aios-core/tenant-registry",
    type,
    subject: tenant.tenantId,
    time: `2026-07-27T00:0${version}:00.000Z`,
    datacontenttype: "application/json",
    tenantkind: "SYNTHETIC",
    correlationid: `g1-matrix-${tenant.tenantId.slice(-4)}-${suffix}`,
    synthetic: true,
    data: {
      tenant_id: tenant.tenantId,
      lifecycle_version: version,
      generation: 1,
      operation_id: `op_${tenant.tenantId.slice(4)}`,
      state,
      actor_id: "prn_018f0000-0000-7000-8000-000000000099",
    },
  };
}

export function g1C07Scope(tenantId, correlationId) {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId,
    decisionId: `g1-matrix-${correlationId}`,
    evidenceRef: `evidence://g1/matrix/${correlationId}`,
    policyVersion: "g1-c06-role-model-v2",
  };
}

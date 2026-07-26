import assert from "node:assert/strict";
import test from "node:test";
import {
  createC02C06Authorizer,
} from "../lib/c02-c06-authorizer.mjs";

const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const HUMAN =
  "prn_018f0000-0000-7000-8000-000000000001";
const WORKLOAD =
  "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";

const serverContext = {
  synthetic: true,
  routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
  tenantId: TENANT,
  workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
  workloadActorPrincipalId: WORKLOAD,
};

const request = {
  sessionToken: "synthetic-session",
  delegationId: DELEGATION,
  correlationId: "corr-c02-c06",
  resourceId: "c02-tenant-config-general",
};

test("C02 maps one management operation to a bound C06 MANAGE decision", async () => {
  let received;
  const authorizer = createC02C06Authorizer({
    authorizationFacade: {
      async decide(context, input) {
        received = { context, input };
        return {
          effect: "ALLOW",
          authorizationStatus: "ALLOWED",
          decisionId: "dec-c02-c06-1",
          evidenceRef: "evidence://c06/decision/c02-c06-1",
          authorizationModelId: "model-c06-1",
          tenantId: TENANT,
          surface: "MANAGE",
          resourceId: input.resourceId,
          humanPrincipalId: HUMAN,
          humanSecurityEpoch: 1,
          workloadActorPrincipalId: WORKLOAD,
          workloadActorSecurityEpoch: 1,
          leafDelegationId: DELEGATION,
          delegationChainSha256:
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          purposeRef: "synthetic://c06/purpose/manage",
        };
      },
    },
  });

  const result = await authorizer.enforce(
    serverContext,
    request,
    {
      operationId: "C02_TENANT_CONFIG_VIEW",
      surface: "MANAGE",
      path: "tenant-governance",
      mode: "READ",
    },
  );

  assert.equal(received.context.surface, "MANAGE");
  assert.deepEqual(received.input, request);
  assert.deepEqual(result, {
    trustSource: "C06_BOUND_DECISION_EVIDENCE",
    tenantId: TENANT,
    humanPrincipalId: HUMAN,
    workloadActorPrincipalId: WORKLOAD,
    decisionId: "dec-c02-c06-1",
    evidenceRef: "evidence://c06/decision/c02-c06-1",
    policyVersion: "model-c06-1",
    resourceId: "c02-tenant-config-general",
    operationId: "C02_TENANT_CONFIG_VIEW",
  });
});

test("C02 rejects a mismatched operation binding before C06", async () => {
  let calls = 0;
  const authorizer = createC02C06Authorizer({
    authorizationFacade: {
      async decide() {
        calls += 1;
      },
    },
  });

  await assert.rejects(
    authorizer.enforce(serverContext, request, {
      operationId: "C02_TENANT_CONFIG_VIEW",
      surface: "MANAGE",
      path: "tenant-governance",
      mode: "WRITE",
    }),
    (error) => error.code === "AUTHORIZATION_UNAVAILABLE",
  );
  assert.equal(calls, 0);
});

test("the complete C02 catalog fixes mode and C06 resource prefix", async () => {
  const cases = [
    ["C02_TENANT_CONFIG_VIEW", "READ", "c02-tenant-config-demo"],
    ["C02_TENANT_CONFIG_CHANGE", "WRITE", "c02-tenant-config-demo"],
    ["C02_PRINCIPAL_ROLE_VIEW", "READ", "c02-principal-role-demo"],
    ["C02_PRINCIPAL_ROLE_CHANGE", "WRITE", "c02-principal-role-demo"],
    [
      "C02_KNOWLEDGE_RELEASE_VIEW",
      "READ",
      "c02-knowledge-release-demo",
    ],
    [
      "C02_KNOWLEDGE_RELEASE_CHANGE",
      "WRITE",
      "c02-knowledge-release-demo",
    ],
    ["C02_SKILL_RELEASE_VIEW", "READ", "c02-skill-release-demo"],
    [
      "C02_SKILL_RELEASE_CHANGE",
      "WRITE",
      "c02-skill-release-demo",
    ],
    ["C02_QUOTA_VIEW", "READ", "c02-quota-demo"],
    ["C02_QUOTA_CHANGE", "WRITE", "c02-quota-demo"],
    [
      "C02_FORMAL_ARTIFACT_VIEW",
      "READ",
      "c02-formal-artifact-demo",
    ],
    [
      "C02_FORMAL_ARTIFACT_PUBLISH",
      "WRITE",
      "c02-formal-artifact-demo",
    ],
    ["C02_AUDIT_VIEW", "READ", "c02-audit-demo"],
    ["C02_CONNECTOR_STAGE_VIEW", "READ", "c02-connector-demo"],
    [
      "C02_CONNECTOR_STAGE_CHANGE",
      "WRITE",
      "c02-connector-demo",
    ],
    [
      "C02_OBSERVABILITY_VIEW",
      "READ",
      "c02-observability-demo",
    ],
  ];
  const authorizer = createC02C06Authorizer({
    authorizationFacade: {
      async decide(context, input) {
        return {
          effect: "ALLOW",
          authorizationStatus: "ALLOWED",
          decisionId: "dec-c02-catalog",
          evidenceRef: "evidence://c06/decision/c02-catalog",
          authorizationModelId: "model-c06-1",
          tenantId: TENANT,
          surface: "MANAGE",
          resourceId: input.resourceId,
          humanPrincipalId: HUMAN,
          humanSecurityEpoch: 1,
          workloadActorPrincipalId: WORKLOAD,
          workloadActorSecurityEpoch: 1,
          leafDelegationId: DELEGATION,
          delegationChainSha256:
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          purposeRef: "synthetic://c06/purpose/manage",
        };
      },
    },
  });

  for (const [operationId, mode, resourceId] of cases) {
    const result = await authorizer.enforce(
      serverContext,
      { ...request, resourceId },
      {
        operationId,
        surface: "MANAGE",
        path: "tenant-governance",
        mode,
      },
    );
    assert.equal(result.operationId, operationId);
    assert.equal(result.resourceId, resourceId);
  }
});

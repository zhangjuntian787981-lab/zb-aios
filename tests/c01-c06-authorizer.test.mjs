import assert from "node:assert/strict";
import test from "node:test";
import {
  createC01C06Authorizer,
} from "../lib/c01-c06-authorizer.mjs";

const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const HUMAN =
  "prn_018f0000-0000-7000-8000-000000000001";
const WORKLOAD =
  "prn_018f0000-0000-7000-8000-000000000002";

const context = {
  routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
  tenantId: TENANT,
  workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
  workloadActorPrincipalId: WORKLOAD,
};
const request = {
  sessionToken: "synthetic-session",
  delegationId: "dlg-demo",
  correlationId: "corr-c01-auth",
  resourceId: "c01-thread-demo",
};

test("C01 maps a portal operation to a request-bound C06 decision", async () => {
  let received;
  const authorizer = createC01C06Authorizer({
    authorizationFacade: {
      async decide(serverContext, input) {
        received = { serverContext, input };
        return {
          effect: "ALLOW",
          authorizationStatus: "ALLOWED",
          decisionId: "dec-c01-1",
          evidenceRef: "evidence://c06/decision/c01-1",
          authorizationModelId: "model-c06-1",
          tenantId: TENANT,
          surface: "READ",
          resourceId: request.resourceId,
          humanPrincipalId: HUMAN,
          humanSecurityEpoch: 1,
          workloadActorPrincipalId: WORKLOAD,
          workloadActorSecurityEpoch: 1,
          leafDelegationId: request.delegationId,
          delegationChainSha256:
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          purposeRef: "synthetic://c06/purpose/read",
        };
      },
    },
  });

  const result = await authorizer.enforce(context, request, {
    operationId: "C01_THREAD_VIEW",
    surface: "READ",
    path: "employee-portal",
    mode: "READ",
  });

  assert.equal(received.serverContext.surface, "READ");
  assert.equal(received.input.resourceId, request.resourceId);
  assert.equal(result.humanPrincipalId, HUMAN);
  assert.equal(result.operationId, "C01_THREAD_VIEW");
});

test("C01 rejects an operation/prefix mismatch before C06", async () => {
  let calls = 0;
  const authorizer = createC01C06Authorizer({
    authorizationFacade: {
      async decide() {
        calls += 1;
      },
    },
  });

  await assert.rejects(
    authorizer.enforce(
      context,
      { ...request, resourceId: "c01-file-demo" },
      {
        operationId: "C01_THREAD_VIEW",
        surface: "READ",
        path: "employee-portal",
        mode: "READ",
      },
    ),
    (error) => error.code === "AUTHORIZATION_UNAVAILABLE",
  );
  assert.equal(calls, 0);
});

test("the complete C01 operation catalog fixes C06 surface and resource prefix", async () => {
  const cases = [
    ["C01_PORTAL_HOME_VIEW", "READ", "READ", "c01-portal-home-demo"],
    ["C01_THREAD_VIEW", "READ", "READ", "c01-thread-demo"],
    ["C01_RUN_VIEW", "READ", "READ", "c01-run-demo"],
    ["C01_RUN_STREAM_VIEW", "READ", "READ", "c01-run-demo"],
    ["C01_FILE_STATUS_VIEW", "READ", "READ", "c01-file-demo"],
    [
      "C01_RESOURCE_DIRECTORY_VIEW",
      "READ",
      "READ",
      "c01-resource-directory-demo",
    ],
    [
      "C01_AGENT_SKILL_DIRECTORY_VIEW",
      "READ",
      "READ",
      "c01-agent-skill-directory-demo",
    ],
    ["C01_MEMORY_VIEW", "READ", "READ", "c01-memory-demo"],
    ["C01_APPROVAL_VIEW", "READ", "READ", "c01-approval-demo"],
    ["C01_CITATION_VIEW", "READ", "READ", "c01-citation-demo"],
    ["C01_THREAD_CREATE", "WRITE", "MANAGE", "c01-thread-demo"],
    ["C01_CHAT_SUBMIT", "WRITE", "MANAGE", "c01-thread-demo"],
    [
      "C01_FILE_QUARANTINE_REQUEST",
      "WRITE",
      "MANAGE",
      "c01-file-demo",
    ],
    ["C01_MEMORY_CONFIRM", "WRITE", "MANAGE", "c01-memory-demo"],
    ["C01_APPROVAL_DECIDE", "WRITE", "MANAGE", "c01-approval-demo"],
  ];
  const authorizer = createC01C06Authorizer({
    authorizationFacade: {
      async decide(serverContext, input) {
        return {
          effect: "ALLOW",
          authorizationStatus: "ALLOWED",
          decisionId: "dec-c01-catalog",
          evidenceRef: "evidence://c06/decision/c01-catalog",
          authorizationModelId: "model-c06-1",
          tenantId: TENANT,
          surface: serverContext.surface,
          resourceId: input.resourceId,
          humanPrincipalId: HUMAN,
          humanSecurityEpoch: 1,
          workloadActorPrincipalId: WORKLOAD,
          workloadActorSecurityEpoch: 1,
          leafDelegationId: input.delegationId,
          delegationChainSha256:
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          purposeRef:
            `synthetic://c06/purpose/${serverContext.surface.toLowerCase()}`,
        };
      },
    },
  });

  for (const [operationId, mode, surface, resourceId] of cases) {
    const result = await authorizer.enforce(
      context,
      { ...request, resourceId },
      {
        operationId,
        surface,
        path: "employee-portal",
        mode,
      },
    );
    assert.equal(result.operationId, operationId);
    assert.equal(result.resourceId, resourceId);
  }
});

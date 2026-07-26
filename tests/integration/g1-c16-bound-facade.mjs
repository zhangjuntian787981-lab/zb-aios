import { AsyncLocalStorage } from "node:async_hooks";
import {
  createSyntheticToolCatalog,
  createToolGateway,
  toolGatewaySha256,
} from "../../lib/tool-gateway.mjs";
import { createC16EphemeralCredentialBroker } from "../../lib/c16-ephemeral-credential-broker.mjs";
import { createC16SyntheticToolAdapter } from "../../lib/c16-synthetic-tool-adapter.mjs";

const AUTHORIZATION_KEYS = Object.freeze([
  "effect",
  "authorizationStatus",
  "c06BoundaryEntered",
  "tenantId",
  "surface",
  "resourceId",
  "sessionId",
  "principalId",
  "authoritativeRole",
  "storeId",
  "authorizationModelId",
  "consistency",
]);
const OPERATION_BY_ROLE = Object.freeze({
  sales_analyst: "synthetic.approval.status.get",
  operations_planner: "synthetic.erp.order.get",
  quality_reviewer: "synthetic.bi.metric.get",
});
const SHA256 = /^sha256:[0-9a-f]{64}$/;

class G1C16BoundFacadeError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "G1C16BoundFacadeError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new G1C16BoundFacadeError(code, message);
}

function plainObject(value) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exactObject(value, keys, code = "G1_C16_INVALID_INPUT") {
  if (
    !plainObject(value) ||
    Object.keys(value).length !== keys.length ||
    Object.keys(value).some((key) => !keys.includes(key))
  ) {
    fail(code, "G1 C16 input is invalid.");
  }
}

function nonEmpty(value, max = 256) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= max
  );
}

function hexDigest(value) {
  return toolGatewaySha256(value).slice(7);
}

function validateStoreObservation(value) {
  if (
    !plainObject(value) ||
    !["C16_POSTGRESQL_STORE", "NON_GATE_TEST_DOUBLE"].includes(
      value.backendKind,
    ) ||
    !nonEmpty(value.backendInstanceId) ||
    typeof value.persistent !== "boolean" ||
    !Number.isSafeInteger(value.negativeStorageTouchCount) ||
    value.negativeStorageTouchCount < 0 ||
    (value.backendKind === "C16_POSTGRESQL_STORE" &&
      value.persistent !== true) ||
    (value.backendKind === "NON_GATE_TEST_DOUBLE" &&
      value.persistent !== false)
  ) {
    fail(
      "G1_C16_INVALID_CONFIGURATION",
      "G1 C16 store evidence is invalid.",
    );
  }
  return value;
}

function deploymentProjection(deployment) {
  if (
    !plainObject(deployment) ||
    !Array.isArray(deployment.tenants) ||
    deployment.tenants.length !== 3
  ) {
    fail(
      "G1_C16_INVALID_CONFIGURATION",
      "G1 C16 deployment is invalid.",
    );
  }
  const tenantIds = new Set();
  const sessions = new Map();
  for (const tenant of deployment.tenants) {
    if (
      !plainObject(tenant) ||
      !nonEmpty(tenant.tenantId) ||
      tenant.tenantKind !== "SYNTHETIC" ||
      !Array.isArray(tenant.users) ||
      tenant.users.length !== 3 ||
      tenantIds.has(tenant.tenantId)
    ) {
      fail(
        "G1_C16_INVALID_CONFIGURATION",
        "G1 C16 deployment is invalid.",
      );
    }
    const projectedTenant = Object.freeze({
      tenantId: tenant.tenantId,
      tenantKind: "SYNTHETIC",
      lifecycleVersion:
        Number.isSafeInteger(tenant.lifecycleVersion) &&
        tenant.lifecycleVersion > 0
          ? tenant.lifecycleVersion
          : 1,
      workloadActorPrincipalId:
        `prn_${tenant.tenantId.slice(4)}`,
    });
    tenantIds.add(tenant.tenantId);
    for (const user of tenant.users) {
      if (
        !plainObject(user) ||
        !nonEmpty(user.accountId) ||
        !nonEmpty(user.fixtureUserId) ||
        !nonEmpty(user.sessionId, 4096) ||
        !nonEmpty(user.principalId) ||
        !OPERATION_BY_ROLE[user.role] ||
        user.trustSource !== "VERIFIED_SESSION" ||
        !plainObject(user.delegationIds) ||
        !nonEmpty(user.delegationIds.TOOL_CALL) ||
        sessions.has(user.sessionId)
      ) {
        fail(
          "G1_C16_INVALID_CONFIGURATION",
          "G1 C16 deployment is invalid.",
        );
      }
      const purposeRef = "synthetic://c06/purpose/tool-call";
      const identity = Object.freeze({
        tenantId: tenant.tenantId,
        tenantKind: "SYNTHETIC",
        identityAccountId: user.accountId,
        identityLinkId: `lnk_${user.sessionId.slice(4)}`,
        sessionId: user.sessionId,
        humanSubject: Object.freeze({
          principalId: user.principalId,
          principalType: "HUMAN",
          lifecycleVersion: 1,
          securityEpoch: 1,
        }),
        workloadActor: Object.freeze({
          principalId: projectedTenant.workloadActorPrincipalId,
          principalType: "AGENT",
          lifecycleVersion: 1,
          securityEpoch: 1,
        }),
        purposeRef,
        delegationChain: Object.freeze([
          Object.freeze({
            delegationId: user.delegationIds.TOOL_CALL,
            delegatorPrincipalId: user.principalId,
            delegatePrincipalId:
              projectedTenant.workloadActorPrincipalId,
            purposeRef,
            lifecycleVersion: 1,
            expiresAt: "9999-12-31T23:59:59.999Z",
          }),
        ]),
        trustSource:
          "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
        authorizationStatus: "NOT_EVALUATED",
      });
      sessions.set(
        user.sessionId,
        Object.freeze({
          tenant: projectedTenant,
          fixtureUserId: user.fixtureUserId,
          principalId: user.principalId,
          role: user.role,
          delegationId: user.delegationIds.TOOL_CALL,
          identity,
        }),
      );
    }
  }
  return sessions;
}

function serverContext(binding) {
  return Object.freeze({
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: binding.tenantId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId:
      binding.user.tenant.workloadActorPrincipalId,
  });
}

function validateAuthorization(input, sessions) {
  exactObject(input.authorization, AUTHORIZATION_KEYS);
  const decision = input.authorization;
  const user = sessions.get(decision.sessionId);
  if (
    decision.effect !== "ALLOW" ||
    decision.authorizationStatus !== "ALLOWED" ||
    decision.c06BoundaryEntered !== true ||
    decision.tenantId !== input.tenantId ||
    decision.surface !== "TOOL" ||
    decision.resourceId !== input.resourceId ||
    decision.consistency !== "HIGHER_CONSISTENCY" ||
    !nonEmpty(decision.storeId) ||
    !nonEmpty(decision.authorizationModelId) ||
    !user ||
    user.tenant.tenantId !== input.tenantId ||
    decision.principalId !== user.principalId ||
    decision.authoritativeRole !== user.role ||
    OPERATION_BY_ROLE[user.role] !== input.operationId
  ) {
    fail(
      "G1_C16_ACCESS_DENIED",
      "G1 C16 authorization binding was denied.",
    );
  }
  return user;
}

function validateCommonInput(input, expectedKeys, sessions, catalog) {
  exactObject(input, expectedKeys);
  if (
    !nonEmpty(input.tenantId) ||
    !nonEmpty(input.resourceId, 128) ||
    !nonEmpty(input.caseId, 128) ||
    !nonEmpty(input.operationId, 128)
  ) {
    fail("G1_C16_INVALID_INPUT", "G1 C16 input is invalid.");
  }
  const user = validateAuthorization(input, sessions);
  let operation;
  try {
    operation = catalog.operation(input.operationId);
  } catch {
    fail("G1_C16_ACCESS_DENIED", "G1 C16 operation was denied.");
  }
  const digest = hexDigest({
    caseId: input.caseId,
    tenantId: input.tenantId,
    resourceId: input.resourceId,
    operationId: input.operationId,
    authorization: input.authorization,
    resolvedPrincipalId: user.principalId,
    resolvedRole: user.role,
  });
  return Object.freeze({
    tenantId: input.tenantId,
    resourceId: input.resourceId,
    caseId: input.caseId,
    operationId: input.operationId,
    nativeResourceId: `c16-${operation.authorizationResourceSuffix}`,
    digest,
    correlationId: `g1-c16-${digest.slice(0, 48)}`,
    user,
  });
}

function validateConfirmation(confirmation, binding) {
  if (
    !plainObject(confirmation) ||
    !nonEmpty(confirmation.confirmationId, 64) ||
    confirmation.tenantId !== binding.tenantId ||
    confirmation.tenantKind !== "SYNTHETIC" ||
    confirmation.operationId !== binding.operationId ||
    !SHA256.test(confirmation.confirmationSha256 ?? "") ||
    !SHA256.test(confirmation.normalizedParamSha256 ?? "")
  ) {
    fail(
      "G1_C16_ACCESS_DENIED",
      "G1 C16 confirmation binding was denied.",
    );
  }
}

export function createG1C16BoundFacade(options) {
  exactObject(
    options,
    [
      "deployment",
      "store",
      "catalogDocument",
      "fixtureDocument",
      "clock",
      "idFactory",
    ],
    "G1_C16_INVALID_CONFIGURATION",
  );
  if (
    !options.store ||
    typeof options.store.saveConfirmation !== "function" ||
    typeof options.store.getConfirmation !== "function" ||
    typeof options.store.beginExecution !== "function" ||
    typeof options.store.completeExecution !== "function" ||
    typeof options.store.failExecution !== "function" ||
    typeof options.store.observations !== "function" ||
    typeof options.clock !== "function" ||
    typeof options.idFactory !== "function"
  ) {
    fail(
      "G1_C16_INVALID_CONFIGURATION",
      "G1 C16 dependencies are incomplete.",
    );
  }
  const sessions = deploymentProjection(options.deployment);
  validateStoreObservation(options.store.observations());
  const catalog = createSyntheticToolCatalog(options.catalogDocument);
  const credentialBroker = createC16EphemeralCredentialBroker({
    clock: options.clock,
    idFactory: options.idFactory,
  });
  const adapter = createC16SyntheticToolAdapter({
    credentialBroker,
    fixtureDocument: options.fixtureDocument,
  });
  const authorizationContext = new AsyncLocalStorage();
  const confirmationBindings = new Map();
  let confirmCount = 0;
  let executeCount = 0;

  function currentBinding() {
    const binding = authorizationContext.getStore();
    if (!binding) {
      fail(
        "G1_C16_ACCESS_DENIED",
        "G1 C16 authorization context is missing.",
      );
    }
    return binding;
  }

  const gateway = createToolGateway({
    tenantRegistry: {
      async admitNewRequest({ tenantId, expectedTenantKind }) {
        const binding = currentBinding();
        if (
          tenantId !== binding.tenantId ||
          expectedTenantKind !== "SYNTHETIC"
        ) {
          fail(
            "G1_C16_ACCESS_DENIED",
            "G1 C16 Tenant admission was denied.",
          );
        }
        return binding.user.tenant;
      },
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity(context, request) {
        const binding = currentBinding();
        if (
          context?.synthetic !== true ||
          context?.workloadTrustSource !==
            "VERIFIED_WORKLOAD_CONTEXT" ||
          context?.workloadActorPrincipalId !==
            binding.user.tenant.workloadActorPrincipalId ||
          request?.sessionToken !==
            binding.user.identity.sessionId ||
          request?.expectedTenantId !== binding.tenantId ||
          request?.delegationId !== binding.user.delegationId
        ) {
          fail(
            "G1_C16_ACCESS_DENIED",
            "G1 C16 identity resolution was denied.",
          );
        }
        return binding.user.identity;
      },
    },
    authorizer: {
      async enforce(context, request, descriptor) {
        const binding = currentBinding();
        if (
          context?.tenantId !== binding.tenantId ||
          context?.workloadActorPrincipalId !==
            binding.user.tenant.workloadActorPrincipalId ||
          request?.sessionToken !==
            binding.user.identity.sessionId ||
          request?.delegationId !== binding.user.delegationId ||
          request?.correlationId !== binding.correlationId ||
          request?.resourceId !== binding.nativeResourceId ||
          descriptor?.surface !== "TOOL_CALL" ||
          descriptor?.resourceId !== undefined ||
          descriptor?.path !== "tool-gateway" ||
          descriptor?.mode !== "READ" ||
          !["C16_CONFIRM_TOOL", "C16_EXECUTE_TOOL"].includes(
            descriptor?.operationId,
          )
        ) {
          fail(
            "G1_C16_ACCESS_DENIED",
            "G1 C16 native authorization was denied.",
          );
        }
        const identity = binding.user.identity;
        return Object.freeze({
          trustSource: "C06_BOUND_DECISION_EVIDENCE",
          operationId: descriptor.operationId,
          decisionId:
            `g1-c06-${descriptor.operationId.toLowerCase()}-` +
            binding.digest.slice(0, 24),
          evidenceRef:
            `evidence://g1/c06-bound/${binding.digest}/` +
            descriptor.operationId.toLowerCase(),
          policyVersion: `g1-c06-bound-${binding.digest}`,
          tenantId: binding.tenantId,
          surface: "TOOL_CALL",
          resourceId: binding.nativeResourceId,
          humanPrincipalId: binding.user.principalId,
          humanSecurityEpoch: identity.humanSubject.securityEpoch,
          workloadActorPrincipalId:
            identity.workloadActor.principalId,
          workloadActorSecurityEpoch:
            identity.workloadActor.securityEpoch,
          leafDelegationId: binding.user.delegationId,
          delegationChainSha256: toolGatewaySha256(
            identity.delegationChain,
          ),
          purposeRef: identity.purposeRef,
        });
      },
    },
    catalog,
    store: options.store,
    credentialBroker,
    adapter,
    idFactory: options.idFactory,
    clock: options.clock,
  });

  return Object.freeze({
    async confirmBound(input) {
      const binding = validateCommonInput(
        input,
        [
          "tenantId",
          "resourceId",
          "caseId",
          "operationId",
          "params",
          "authorization",
        ],
        sessions,
        catalog,
      );
      if (!plainObject(input.params)) {
        fail("G1_C16_INVALID_INPUT", "G1 C16 parameters are invalid.");
      }
      confirmCount += 1;
      const confirmation = await authorizationContext.run(
        binding,
        () =>
          gateway.confirm(serverContext(binding), {
            sessionToken: binding.user.identity.sessionId,
            delegationId: binding.user.delegationId,
            correlationId: binding.correlationId,
            operationId: binding.operationId,
            idempotencyKey:
              `g1-c16-confirm-${binding.digest.slice(0, 64)}`,
            params: structuredClone(input.params),
          }),
      );
      confirmationBindings.set(
        `${binding.tenantId}|${confirmation.confirmationId}`,
        binding.digest,
      );
      return confirmation;
    },

    async executeBound(input) {
      const binding = validateCommonInput(
        input,
        [
          "tenantId",
          "resourceId",
          "caseId",
          "operationId",
          "confirmation",
          "authorization",
        ],
        sessions,
        catalog,
      );
      validateConfirmation(input.confirmation, binding);
      const knownDigest = confirmationBindings.get(
        `${binding.tenantId}|${input.confirmation.confirmationId}`,
      );
      if (knownDigest !== undefined && knownDigest !== binding.digest) {
        fail(
          "G1_C16_ACCESS_DENIED",
          "G1 C16 outer decision changed after confirmation.",
        );
      }
      executeCount += 1;
      return authorizationContext.run(binding, () =>
        gateway.execute(serverContext(binding), {
          sessionToken: binding.user.identity.sessionId,
          delegationId: binding.user.delegationId,
          correlationId: binding.correlationId,
          operationId: binding.operationId,
          idempotencyKey:
            `g1-c16-execute-${hexDigest({
              confirmationId: input.confirmation.confirmationId,
              authorizationDigest: binding.digest,
            }).slice(0, 64)}`,
          confirmationId: input.confirmation.confirmationId,
          confirmationSha256:
            input.confirmation.confirmationSha256,
          expectedParamSha256:
            input.confirmation.normalizedParamSha256,
        }),
      );
    },

    observations() {
      const storage = validateStoreObservation(
        options.store.observations(),
      );
      const snapshot = adapter.snapshot();
      const persistent =
        storage.backendKind === "C16_POSTGRESQL_STORE" &&
        storage.persistent === true;
      return Object.freeze({
        backendKind: persistent
          ? "C16_POSTGRESQL_GATEWAY_C0"
          : "NON_GATE_TEST_DOUBLE",
        backendInstanceId: storage.backendInstanceId,
        persistent,
        confirmCount,
        executeCount,
        newExecutionCount: snapshot.newExecutionCount,
        networkRequestCount: snapshot.networkRequestCount,
        enterpriseEndpointCount: snapshot.enterpriseEndpointCount,
        enterpriseCredentialCount:
          snapshot.enterpriseCredentialCount,
        externalEffectCount: snapshot.externalEffectCount,
        negativeStorageTouchCount:
          storage.negativeStorageTouchCount,
      });
    },
  });
}

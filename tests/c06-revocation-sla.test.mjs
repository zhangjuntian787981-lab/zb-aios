import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

import { createC01C06Authorizer } from "../lib/c01-c06-authorizer.mjs";
import { createC02C06Authorizer } from "../lib/c02-c06-authorizer.mjs";
import { createC08C06Authorizer } from "../lib/c08-c06-authorizer.mjs";
import { createC10C06Authorizer } from "../lib/c10-c06-authorizer.mjs";
import { createC11C06Authorizer } from "../lib/c11-c06-authorizer.mjs";
import { createC13C06Authorizer } from "../lib/c13-c06-authorizer.mjs";
import { createC14C06Authorizer } from "../lib/c14-c06-authorizer.mjs";
import { createC15C06Authorizer } from "../lib/c15-c06-authorizer.mjs";
import { createC16C06Authorizer } from "../lib/c16-c06-authorizer.mjs";
import { createSyntheticPepAdapters } from "../lib/synthetic-pep-adapters.mjs";
import {
  createC06TenantDataAuthorizer,
  createTenantDataBoundary,
} from "../lib/tenant-data-boundary.mjs";

const TENANT_ID = "stn_018f0000-0000-7000-8000-000000000010";
const HUMAN_ID = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR_ID = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION_ID = "dlg_018f0000-0000-7000-8000-000000000020";

const SERVER_CONTEXT = Object.freeze({
  synthetic: true,
  routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
  tenantId: TENANT_ID,
  workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
  workloadActorPrincipalId: ACTOR_ID,
});

const PRODUCT_PEPS = Object.freeze([
  {
    consumer: "C01",
    module: "lib/c01-c06-authorizer.mjs",
    create: createC01C06Authorizer,
    request: {
      resourceId: "c01-thread-synthetic",
    },
    descriptor: {
      operationId: "C01_THREAD_VIEW",
      surface: "READ",
      path: "employee-portal",
      mode: "READ",
    },
  },
  {
    consumer: "C02",
    module: "lib/c02-c06-authorizer.mjs",
    create: createC02C06Authorizer,
    request: {
      resourceId: "c02-tenant-config-synthetic",
    },
    descriptor: {
      operationId: "C02_TENANT_CONFIG_VIEW",
      surface: "MANAGE",
      path: "tenant-governance",
      mode: "READ",
    },
  },
  {
    consumer: "C07",
    module: "lib/tenant-data-boundary.mjs",
    create: createC06TenantDataAuthorizer,
    request: {
      resourceId: "c07-cache-synthetic",
    },
    descriptor: {
      operationId: "C07_CACHE_GET",
      surface: "READ",
      path: "cache",
      mode: "READ",
    },
  },
  {
    consumer: "C08",
    module: "lib/c08-c06-authorizer.mjs",
    create: createC08C06Authorizer,
    request: {
      resourceId: "c08-state-synthetic",
    },
    descriptor: {
      operationId: "C08_STATE_VIEW",
      surface: "READ",
      path: "state-core",
      mode: "READ",
    },
  },
  {
    consumer: "C10",
    module: "lib/c10-c06-authorizer.mjs",
    create: createC10C06Authorizer,
    request: {
      resourceId: "c10-policy-synthetic",
    },
    descriptor: {
      operationId: "C10_POLICY_VIEW",
      surface: "MANAGE",
      path: "policy-control",
      mode: "READ",
    },
  },
  {
    consumer: "C11",
    module: "lib/c11-c06-authorizer.mjs",
    create: createC11C06Authorizer,
    request: {
      resourceId: "c11-knowledge-synthetic",
    },
    descriptor: {
      operationId: "C11_KNOWLEDGE_RETRIEVE",
      surface: "RETRIEVE",
      path: "knowledge",
      mode: "READ",
    },
  },
  {
    consumer: "C13",
    module: "lib/c13-c06-authorizer.mjs",
    create: createC13C06Authorizer,
    request: {
      resourceId: "c13-synthetic--skill-resolve",
    },
    descriptor: {
      operationId: "C13_RESOLVE_FOR_RUN",
      surface: "READ",
      path: "skill-registry",
      mode: "READ",
    },
  },
  {
    consumer: "C14",
    module: "lib/c14-c06-authorizer.mjs",
    create: createC14C06Authorizer,
    request: {
      resourceId: "c14-route-synthetic",
    },
    descriptor: {
      operationId: "C14_ROUTE_MODEL",
      surface: "MANAGE",
      path: "model-router",
      mode: "READ",
    },
  },
  {
    consumer: "C15",
    module: "lib/c15-c06-authorizer.mjs",
    create: createC15C06Authorizer,
    request: {
      resourceId: "c15-synthetic--decision-execute",
    },
    descriptor: {
      operationId: "C15_EXECUTE_SYNTHETIC_PREVIEW",
      surface: "TOOL_CALL",
      path: "human-decision",
      mode: "WRITE",
    },
  },
  {
    consumer: "C16",
    module: "lib/c16-c06-authorizer.mjs",
    create: createC16C06Authorizer,
    request: {
      resourceId: "c16-erp-order-get",
    },
    descriptor: {
      operationId: "C16_EXECUTE_TOOL",
      surface: "TOOL_CALL",
      path: "tool-gateway",
      mode: "READ",
    },
  },
]);

async function loadSla() {
  return JSON.parse(
    await readFile(
      new URL(
        "../implementation/p1/c06/revocation-sla.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
}

function syntheticClock() {
  let nowMs = Date.parse("2026-07-28T00:00:00.000Z");
  return Object.freeze({
    now: () => nowMs,
    advance: (milliseconds) => {
      nowMs += milliseconds;
    },
  });
}

function revocableFacade(clock) {
  let revokedAtMs = null;
  const calls = [];
  return Object.freeze({
    authorizationFacade: Object.freeze({
      async decide(context, request) {
        calls.push({
          atMs: clock.now(),
          surface: context.surface,
          resourceId: request.resourceId,
        });
        if (revokedAtMs !== null && clock.now() >= revokedAtMs) {
          return Object.freeze({
            effect: "DENY",
            authorizationStatus: "DENIED",
          });
        }
        return Object.freeze({
          effect: "ALLOW",
          authorizationStatus: "ALLOWED",
          decisionId: `azd_${String(calls.length).padStart(4, "0")}`,
          evidenceRef: `evidence://c06/revocation/${calls.length}`,
          authorizationModelId: "01J00000000000000000000001",
          tenantId: context.tenantId,
          surface: context.surface,
          resourceId: request.resourceId,
          humanPrincipalId: HUMAN_ID,
          humanSecurityEpoch: 1,
          workloadActorPrincipalId: context.workloadActorPrincipalId,
          workloadActorSecurityEpoch: 1,
          leafDelegationId: request.delegationId,
          delegationChainSha256:
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          purposeRef:
            `synthetic://c06/purpose/${context.surface.toLowerCase()}`,
        });
      },
    }),
    calls,
    revoke: () => {
      revokedAtMs = clock.now();
      return revokedAtMs;
    },
  });
}

function request(resourceId, correlationId) {
  return Object.freeze({
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION_ID,
    resourceId,
    correlationId,
  });
}

async function expectRevokedWithinSla({
  enforce,
  revoke,
  clock,
  maximumPropagationMs,
}) {
  await enforce();
  clock.advance(1);
  const revokedAtMs = revoke();
  await assert.rejects(enforce(), { code: "ACCESS_DENIED" });
  assert.ok(clock.now() - revokedAtMs <= maximumPropagationMs);
}

test("the frozen C06 revocation profile inventories every implemented product PEP", async () => {
  const sla = await loadSla();
  const libUrl = new URL("../lib/", import.meta.url);
  const discovered = [];
  for (const name of await readdir(libUrl)) {
    if (!name.endsWith(".mjs") || name === "authorization-facade.mjs") {
      continue;
    }
    const source = await readFile(new URL(name, libUrl), "utf8");
    if (
      source.includes("authorizationFacade.decide(") ||
      source.includes("createPepSdk({ authorizationFacade })")
    ) {
      if (name !== "synthetic-pep-adapters.mjs") {
        discovered.push(`lib/${name}`);
      }
    }
  }
  discovered.sort();

  assert.equal(sla.criterion_id, "C06-AC08");
  assert.equal(sla.data_classification, "SYNTHETIC_ONLY");
  assert.equal(sla.maximum_propagation_ms, 1000);
  assert.equal(sla.clock_source, "INJECTED_SYNTHETIC_CLOCK");
  assert.deepEqual(
    sla.implemented_product_peps.map(({ implementation_ref }) =>
      implementation_ref.split("#")[0],
    ).sort(),
    discovered,
  );
  assert.deepEqual(
    PRODUCT_PEPS.map(({ module }) => module).sort(),
    discovered,
  );
  assert.deepEqual(sla.product_paths_not_implemented, [
    {
      surface: "DOWNLOAD",
      owner: "C01",
      status: "REPRESENTATIVE_PEP_ONLY",
    },
    {
      surface: "SANDBOX_RUN",
      owner: "O01",
      status: "REPRESENTATIVE_PEP_ONLY",
    },
  ]);
});

for (const entry of PRODUCT_PEPS) {
  test(`${entry.consumer} product PEP denies the first action after revocation`, async () => {
    const sla = await loadSla();
    const clock = syntheticClock();
    const revocable = revocableFacade(clock);
    const authorizer = entry.create({
      authorizationFacade: revocable.authorizationFacade,
    });
    const action = request(
      entry.request.resourceId,
      `c06-revoke-${entry.consumer.toLowerCase()}`,
    );

    await expectRevokedWithinSla({
      enforce: () =>
        authorizer.enforce(SERVER_CONTEXT, action, entry.descriptor),
      revoke: revocable.revoke,
      clock,
      maximumPropagationMs: sla.maximum_propagation_ms,
    });
    assert.equal(revocable.calls.length, 2);
  });
}

test("all six representative PEP surfaces deny the first action after revocation", async () => {
  const sla = await loadSla();
  for (const entry of sla.representative_peps) {
    const clock = syntheticClock();
    const revocable = revocableFacade(clock);
    const adapters = createSyntheticPepAdapters({
      authorizationFacade: revocable.authorizationFacade,
      tenantId: TENANT_ID,
      workloadActorPrincipalId: ACTOR_ID,
    });
    await expectRevokedWithinSla({
      enforce: () =>
        adapters[entry.adapter_id].enforce(
          request(
            `representative-${entry.surface.toLowerCase()}`,
            `c06-revoke-${entry.surface.toLowerCase()}`,
          ),
        ),
      revoke: revocable.revoke,
      clock,
      maximumPropagationMs: sla.maximum_propagation_ms,
    });
    assert.equal(revocable.calls.length, 2);
  }
});

test("a warm C07 cache cannot serve after C06 revocation", async () => {
  const sla = await loadSla();
  const clock = syntheticClock();
  const revocable = revocableFacade(clock);
  let cacheReads = 0;
  const descriptor = Object.freeze({
    operationId: "C07_CACHE_GET",
    adapterId: "c07.cache",
    surface: "READ",
    path: "cache",
    mode: "READ",
    inputKeys: ["cacheKey"],
  });
  const boundary = createTenantDataBoundary({
    tenantRegistry: {
      async admitNewRequest({ tenantId }) {
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 1,
          trustSource: "VERIFIED_SERVER_CONTEXT",
        };
      },
    },
    authorizer: createC06TenantDataAuthorizer({
      authorizationFacade: revocable.authorizationFacade,
    }),
    lifecycleSource: {
      async verify() {
        throw new Error("not used");
      },
    },
    operationCatalog: {
      list: () => [descriptor],
      resolve: () => descriptor,
    },
    adapters: {
      "c07.cache": {
        async execute() {
          cacheReads += 1;
          return { hit: true, value: "synthetic" };
        },
        async project() {
          throw new Error("not used");
        },
        async snapshot() {
          return { cacheReads };
        },
      },
    },
  });
  const serverContext = {
    ...SERVER_CONTEXT,
    operationId: "C07_CACHE_GET",
  };
  const cacheRequest = {
    ...request("c07-cache-synthetic", "c06-revoke-cache"),
    input: {
      cacheKey: "synthetic-answer",
    },
  };

  await expectRevokedWithinSla({
    enforce: () => boundary.execute(serverContext, cacheRequest),
    revoke: revocable.revoke,
    clock,
    maximumPropagationMs: sla.maximum_propagation_ms,
  });
  assert.equal(revocable.calls.length, 2);
  assert.equal(cacheReads, 1);
});

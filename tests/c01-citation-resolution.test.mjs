import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createC10SyntheticBenchmark,
  createKnowledgeCatalog,
  createMemoryKnowledgeCatalogStore,
} from "../lib/knowledge-catalog.mjs";
import {
  c11Sha256,
  createC11SyntheticBenchmark,
  createC11SyntheticPrincipalResolver,
  createMemoryPermissionAwareRagStore,
  createPermissionAwareRag,
} from "../lib/permission-aware-rag.mjs";
import {
  createC01CitationReader,
} from "../lib/c01-citation-reader.mjs";
import {
  createEmployeePortalBff,
} from "../lib/employee-portal-bff.mjs";
import {
  createEmployeePortalShell,
} from "../lib/employee-portal-shell.mjs";

const c10Benchmark = createC10SyntheticBenchmark(
  JSON.parse(
    await readFile(
      new URL(
        "../implementation/p1/c10/synthetic-document-benchmark.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
);
const c11Document = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c11/synthetic-rag-benchmark.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const c11Benchmark = createC11SyntheticBenchmark(c11Document);
const TENANT = "stn_01984910-7000-7000-8000-000000000001";
const SALES = "prn_01984910-7000-7000-8000-000000000011";
const OUTSIDER = "prn_01984910-7000-7000-8000-000000000013";
const WORKLOAD = "prn_01984910-7000-7000-8000-000000000031";
const DELEGATION = "dlg_01984910-7000-7000-8000-000000000041";
const AS_OF = "2026-07-26T12:00:00.000Z";
const TENANT_SCOPE = Object.freeze({
  trustSource: "C07_VERIFIED_TENANT_SCOPE",
  tenantId: TENANT,
  tenantKind: "SYNTHETIC",
  lifecycleVersion: 2,
  correlationId: "c01-citation-tenant",
  decisionId: "c07-c01-citation",
  evidenceRef: "evidence://c07/c01-citation",
  policyVersion: "c07-policy-v1",
});

function monotonicClock(start = "2026-07-26T08:00:00.000Z") {
  let milliseconds = Date.parse(start);
  return () => {
    const value = new Date(milliseconds).toISOString();
    milliseconds += 60_000;
    return value;
  };
}

function coreContext(token = "sales") {
  return {
    tenantScope: TENANT_SCOPE,
    c06ServerContext: {
      synthetic: true,
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId: TENANT,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId: WORKLOAD,
    },
    authorizationRequest: {
      sessionToken: token,
      delegationId: DELEGATION,
      correlationId: `c01-citation-${token}`,
    },
  };
}

function portalContext() {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: TENANT,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: WORKLOAD,
  };
}

function principals(token) {
  return {
    sales: SALES,
    outsider: OUTSIDER,
    owner: SALES,
  }[token];
}

function c06Authorizer() {
  let sequence = 0;
  return {
    async enforce(serverContext, request, descriptor) {
      sequence += 1;
      const humanPrincipalId = principals(request.sessionToken);
      if (!humanPrincipalId) {
        throw Object.assign(new Error("denied"), {
          code: "ACCESS_DENIED",
        });
      }
      return {
        trustSource: "C06_BOUND_DECISION_EVIDENCE",
        decisionId: `c06-citation-${sequence}`,
        evidenceRef: `evidence://c06/citation/${sequence}`,
        policyVersion: "c06-policy-v1",
        tenantId: serverContext.tenantId,
        surface: descriptor.surface,
        resourceId: request.resourceId,
        humanPrincipalId,
        humanSecurityEpoch: 1,
        workloadActorPrincipalId: WORKLOAD,
        workloadActorSecurityEpoch: 1,
        leafDelegationId: DELEGATION,
        delegationChainSha256:
          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        purposeRef: "synthetic://c01/citation",
      };
    },
  };
}

function publication() {
  const document = c11Document.documents.find(
    ({ document_id: documentId }) => documentId === "sales-guide",
  );
  return {
    ownerPrincipalId: document.publication.owner_principal_id,
    sourceRef: document.publication.source_ref,
    version: document.publication.version,
    validFrom: document.publication.valid_from,
    validUntil: document.publication.valid_until,
    classification: document.publication.classification,
    acl: structuredClone(document.publication.acl),
  };
}

function command(operation, expectedRevision) {
  return {
    idempotencyKey: `${operation}-sales-guide-${expectedRevision}`,
    documentId: "sales-guide",
    documentVersion: 1,
    expectedRevision,
  };
}

async function publishSalesGuide(catalog) {
  await catalog.upload(coreContext("owner"), {
    idempotencyKey: "upload-sales-guide",
    documentId: "sales-guide",
    documentVersion: 1,
    expectedRevision: 0,
    fixtureRef: "fixture://c10/clean-markdown",
    filename: "sales-guide.md",
    declaredMediaType: "text/markdown",
    sourceRef: "fixture://c11/sales-guide/source",
  });
  await catalog.inspect(
    coreContext("owner"),
    command("inspect", 1),
  );
  await catalog.parse(
    coreContext("owner"),
    command("parse", 2),
  );
  return catalog.publish(coreContext("owner"), {
    ...command("publish", 3),
    metadata: publication(),
  });
}

function portalAuthorizer() {
  return {
    async enforce(serverContext, input, descriptor) {
      const humanPrincipalId = principals(input.sessionToken);
      if (!humanPrincipalId) throw new Error("denied");
      return {
        trustSource: "C06_BOUND_DECISION_EVIDENCE",
        tenantId: serverContext.tenantId,
        humanPrincipalId,
        workloadActorPrincipalId:
          serverContext.workloadActorPrincipalId,
        decisionId: `c06-portal-${humanPrincipalId}`,
        evidenceRef: `evidence://c06/portal/${humanPrincipalId}`,
        policyVersion: "c06-policy-v1",
        resourceId: input.resourceId,
        operationId: descriptor.operationId,
      };
    },
  };
}

function portalRequest(token, resourceId) {
  return {
    sessionToken: token,
    delegationId: DELEGATION,
    correlationId: `c01-citation-open-${token}`,
    operationId: "CITATION_VIEW",
    resourceId,
  };
}

function evidenceWithId(evidence) {
  const value = structuredClone(evidence);
  delete value.evidenceId;
  return {
    evidenceId: `evr_${c11Sha256(value).slice(7, 39)}`,
    ...value,
  };
}

async function harness() {
  const catalogStore = createMemoryKnowledgeCatalogStore();
  const authorization = c06Authorizer();
  const catalog = createKnowledgeCatalog({
    store: catalogStore,
    c06Authorizer: authorization,
    benchmark: c10Benchmark,
    clock: monotonicClock(),
  });
  await publishSalesGuide(catalog);
  const rag = createPermissionAwareRag({
    store: createMemoryPermissionAwareRagStore(),
    catalogReader: catalogStore,
    c06Authorizer: authorization,
    principalResolver: createC11SyntheticPrincipalResolver({
      benchmark: c11Benchmark,
    }),
    benchmark: c11Benchmark,
    clock: () => AS_OF,
  });
  await rag.synchronize(coreContext("owner"), {
    idempotencyKey: "project-sales-guide-0",
    documentId: "sales-guide",
    documentVersion: 1,
    expectedProjectionVersion: 0,
  });
  const answer = await rag.search(coreContext("sales"), {
    requestId: "c01-citation-answer",
    query: "Synthetic only",
    limit: 5,
  });
  const evidence = answer.evidence.find(
    ({ table }) => table !== null,
  );
  assert.ok(evidence, "C11 must return a table-backed EvidenceRef.");

  let currentEvidence = structuredClone(evidence);
  const principalResolver = createC11SyntheticPrincipalResolver({
    benchmark: c11Benchmark,
  });
  const citationReader = createC01CitationReader({
    evidenceReader: {
      async readCurrent() {
        return structuredClone(currentEvidence);
      },
    },
    catalogReader: {
      async readCurrent(scope, coordinates) {
        assert.equal(scope.tenantId, TENANT);
        return catalogStore.readCurrent(
          TENANT_SCOPE,
          coordinates,
        );
      },
    },
    principalReader: {
      async resolveCurrent(scope) {
        return principalResolver.resolve({
          tenantScope: TENANT_SCOPE,
          authorizationEvidence: {
            tenantId: scope.tenantId,
            humanPrincipalId: scope.humanPrincipalId,
            humanSecurityEpoch: 1,
          },
        });
      },
    },
    clock: () => "2026-07-26T12:30:00.000Z",
  });
  const bff = createEmployeePortalBff({
    authorizer: portalAuthorizer(),
    corePort: {
      read: citationReader.read,
      async mutate() {
        throw new Error("not used");
      },
      async *stream() {
        throw new Error("not used");
      },
    },
  });
  const shell = createEmployeePortalShell({
    renderer: "MINIMAL_REPLACEMENT",
    bffClient: {
      read(request) {
        return bff.read(portalContext(), request);
      },
      async mutate() {
        throw new Error("not used");
      },
      async *stream() {
        throw new Error("not used");
      },
    },
  });
  const resourceId =
    `c01-citation-${evidence.evidenceId.replace("_", "-")}`;

  return {
    catalog,
    evidence,
    resourceId,
    setEvidence(value) {
      currentEvidence = structuredClone(value);
    },
    async open(token = "sales") {
      return shell.load(portalRequest(token, resourceId));
    },
  };
}

test("C01 opens a current C11 EvidenceRef at its exact C10 source node", async () => {
  const { evidence, open } = await harness();

  const result = await open();

  assert.deepEqual(result.items[0], {
    evidenceRef: `evidence://c11/${evidence.evidenceId}`,
    resourceRef:
      `synthetic://c10/document/${TENANT}/sales-guide/1/4`,
    locatorRef: `synthetic://c10/node/${evidence.chunk.nodeId}`,
    titleRef: "synthetic://c10/title/sales-guide/1",
    status: "AVAILABLE",
    reasonCode: "CURRENT_AUTHORIZED_SOURCE",
    ownerPrincipalId: SALES,
  });
});

test("C01 reconciles every C11 source coordinate with current C10", async (t) => {
  const { evidence, open, setEvidence } = await harness();
  const mutations = [
    ["tenant", (value) => { value.tenantId = "stn_01984910-7000-7000-8000-000000000002"; }],
    ["document", (value) => { value.documentId = "finance-register"; }],
    ["version", (value) => { value.documentVersion = 2; }],
    ["revision", (value) => { value.catalogRevision += 1; }],
    ["content hash", (value) => { value.contentSha256 = `sha256:${"b".repeat(64)}`; }],
    ["original node", (value) => { value.original.nodeId = `knn_${"b".repeat(32)}`; }],
    ["original hash", (value) => { value.original.contentSha256 = `sha256:${"b".repeat(64)}`; }],
    ["page node", (value) => { value.page.nodeId = `knn_${"b".repeat(32)}`; }],
    ["page number", (value) => { value.page.page += 1; }],
    ["section node", (value) => { value.section.nodeId = `knn_${"b".repeat(32)}`; }],
    ["table node", (value) => { value.table.nodeId = `knn_${"b".repeat(32)}`; }],
    ["chunk node", (value) => { value.chunk.nodeId = `knn_${"b".repeat(32)}`; }],
    ["chunk ordinal", (value) => { value.chunk.ordinal += 1; }],
    ["chunk hash", (value) => { value.chunk.textSha256 = `sha256:${"b".repeat(64)}`; }],
    ["chunk location", (value) => { value.chunk.location.row += 1; }],
  ];

  for (const [name, mutate] of mutations) {
    await t.test(name, async () => {
      const changed = structuredClone(evidence);
      mutate(changed);
      setEvidence(evidenceWithId(changed));

      const result = await open();

      assert.equal(result.items[0].status, "UNAVAILABLE");
      assert.notEqual(
        result.items[0].reasonCode,
        "CURRENT_AUTHORIZED_SOURCE",
      );
      assert.match(
        result.items[0].resourceRef,
        /^synthetic:\/\/c01\/citation-unavailable\//,
      );
      assert.match(
        result.items[0].locatorRef,
        /^synthetic:\/\/c01\/citation-unavailable\//,
      );
    });
  }
});

test("C01 never opens a withdrawn or deleted C10 source", async () => {
  const { catalog, evidence, open } = await harness();
  const available = await open();
  assert.equal(available.items[0].status, "AVAILABLE");

  await catalog.withdraw(
    coreContext("owner"),
    command("withdraw", 4),
  );
  const withdrawn = await open();
  assert.equal(withdrawn.items[0].status, "UNAVAILABLE");
  assert.equal(
    withdrawn.items[0].reasonCode,
    "SOURCE_NOT_CURRENT",
  );
  assert.notEqual(
    withdrawn.items[0].locatorRef,
    `synthetic://c10/node/${evidence.chunk.nodeId}`,
  );

  await catalog.delete(
    coreContext("owner"),
    command("delete", 5),
  );
  const deleted = await open();
  assert.equal(deleted.items[0].status, "UNAVAILABLE");
  assert.equal(deleted.items[0].reasonCode, "SOURCE_NOT_CURRENT");
  assert.match(
    deleted.items[0].locatorRef,
    /^synthetic:\/\/c01\/citation-unavailable\//,
  );
});

test("C01 shows unavailable when the current Principal lacks source access", async () => {
  const { evidence, open } = await harness();

  const result = await open("outsider");

  assert.equal(result.items[0].status, "UNAVAILABLE");
  assert.equal(result.items[0].reasonCode, "ACCESS_DENIED");
  assert.equal(result.items[0].ownerPrincipalId, OUTSIDER);
  assert.notEqual(
    result.items[0].locatorRef,
    `synthetic://c10/node/${evidence.chunk.nodeId}`,
  );
});

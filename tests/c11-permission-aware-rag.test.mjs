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
  c11DeterministicEmbedding,
  createC11SyntheticBenchmark,
  createC11SyntheticPrincipalResolver,
  createMemoryPermissionAwareRagStore,
  createPermissionAwareRag,
} from "../lib/permission-aware-rag.mjs";

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
const TENANT_A = "stn_01984910-7000-7000-8000-000000000001";
const TENANT_B = "stn_01984910-7000-7000-8000-000000000002";
const SALES = "prn_01984910-7000-7000-8000-000000000011";
const FINANCE = "prn_01984910-7000-7000-8000-000000000012";
const OUTSIDER = "prn_01984910-7000-7000-8000-000000000013";
const WORKLOAD = "prn_01984910-7000-7000-8000-000000000031";
const DELEGATION = "dlg_01984910-7000-7000-8000-000000000041";
const AS_OF = "2026-07-26T12:00:00.000Z";

function context(
  tenantId = TENANT_A,
  token = "sales",
) {
  return {
    tenantScope: {
      trustSource: "C07_VERIFIED_TENANT_SCOPE",
      tenantId,
      tenantKind: "SYNTHETIC",
      lifecycleVersion: 2,
      correlationId: `c11-${tenantId}`,
      decisionId: `c07-decision-${tenantId}`,
      evidenceRef: `evidence://c07/${tenantId}`,
      policyVersion: "c07-policy-v1",
    },
    c06ServerContext: {
      synthetic: true,
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId: WORKLOAD,
    },
    authorizationRequest: {
      sessionToken: token,
      delegationId: DELEGATION,
      correlationId: `c06-${tenantId}`,
    },
  };
}

function authorizer(calls = []) {
  const principals = {
    sales: SALES,
    finance: FINANCE,
    outsider: OUTSIDER,
    owner: SALES,
  };
  return {
    async enforce(serverContext, request, descriptor) {
      calls.push({
        tenantId: serverContext.tenantId,
        resourceId: request.resourceId,
        surface: descriptor.surface,
      });
      const humanPrincipalId = principals[request.sessionToken];
      if (!humanPrincipalId) {
        const error = new Error("denied");
        error.code = "ACCESS_DENIED";
        throw error;
      }
      return {
        trustSource: "C06_BOUND_DECISION_EVIDENCE",
        decisionId: `c06-${calls.length}`,
        evidenceRef: `evidence://c06/${calls.length}`,
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
        purposeRef: "synthetic://c11/test",
      };
    },
  };
}

function monotonicClock(start = "2026-07-26T08:00:00.000Z") {
  let milliseconds = Date.parse(start);
  return () => {
    const value = new Date(milliseconds).toISOString();
    milliseconds += 60_000;
    return value;
  };
}

function fixture(documentId) {
  const value = c11Document.documents.find(
    (candidate) => candidate.document_id === documentId,
  );
  assert.ok(value, `Missing fixture ${documentId}.`);
  return value;
}

function publication(value) {
  return {
    ownerPrincipalId: value.publication.owner_principal_id,
    sourceRef: value.publication.source_ref,
    version: value.publication.version,
    validFrom: value.publication.valid_from,
    validUntil: value.publication.valid_until,
    classification: value.publication.classification,
    acl: structuredClone(value.publication.acl),
  };
}

function command(operation, documentId, expectedRevision) {
  return {
    idempotencyKey: `${operation}-${documentId}-${expectedRevision}`,
    documentId,
    documentVersion: 1,
    expectedRevision,
  };
}

async function prepareCatalogDocument(
  catalog,
  tenantContext,
  documentId,
  { publish = true } = {},
) {
  const value = fixture(documentId);
  const markdown = value.fixture_ref.endsWith("clean-markdown");
  await catalog.upload(tenantContext, {
    idempotencyKey: `upload-${documentId}`,
    documentId,
    documentVersion: 1,
    expectedRevision: 0,
    fixtureRef: value.fixture_ref,
    filename: markdown ? `${documentId}.md` : `${documentId}.csv`,
    declaredMediaType: markdown ? "text/markdown" : "text/csv",
    sourceRef: `fixture://c11/${documentId}/source`,
  });
  await catalog.inspect(
    tenantContext,
    command("inspect", documentId, 1),
  );
  const parsed = await catalog.parse(
    tenantContext,
    command("parse", documentId, 2),
  );
  assert.equal(parsed.document.parseSha256, value.parse_sha256);
  if (!publish) return parsed.document;
  const result = await catalog.publish(tenantContext, {
    ...command("publish", documentId, 3),
    metadata: publication(value),
  });
  return result.document;
}

async function harness({
  ragClock = () => AS_OF,
  ragStore = createMemoryPermissionAwareRagStore(),
} = {}) {
  const catalogStore = createMemoryKnowledgeCatalogStore();
  const calls = [];
  const c06Authorizer = authorizer(calls);
  const catalog = createKnowledgeCatalog({
    store: catalogStore,
    c06Authorizer,
    benchmark: c10Benchmark,
    clock: monotonicClock(),
  });
  const rag = createPermissionAwareRag({
    store: ragStore,
    catalogReader: catalogStore,
    c06Authorizer,
    principalResolver: createC11SyntheticPrincipalResolver({
      benchmark: c11Benchmark,
    }),
    benchmark: c11Benchmark,
    clock: ragClock,
  });
  return { catalog, catalogStore, rag, ragStore, calls };
}

function synchronize(rag, tenantContext, documentId, expected = 0) {
  return rag.synchronize(tenantContext, {
    idempotencyKey: `project-${documentId}-${expected}`,
    documentId,
    documentVersion: 1,
    expectedProjectionVersion: expected,
  });
}

function search(rag, token, query, requestId = `request-${token}`) {
  return rag.search(context(TENANT_A, token), {
    requestId,
    query,
    limit: 5,
  });
}

test("C11 freezes deterministic synthetic embeddings and query cases", () => {
  assert.equal(c11Benchmark.embeddingDimensions, 8);
  assert.equal(c11Benchmark.queryCases.length, 4);
  assert.deepEqual(
    c11DeterministicEmbedding("owner ACL publication"),
    c11DeterministicEmbedding("owner ACL publication"),
  );
  assert.notDeepEqual(
    c11DeterministicEmbedding("owner ACL publication"),
    c11DeterministicEmbedding("alpha value"),
  );
});

test("C11 rejects all client-selected filters before authorization", async () => {
  const { rag, calls } = await harness();
  await assert.rejects(
    rag.search(context(), {
      requestId: "client-as-of",
      query: "owner",
      asOf: AS_OF,
      limit: 5,
    }),
    (error) => error.code === "CLIENT_FILTER_FORBIDDEN",
  );
  await assert.rejects(
    rag.search(context(), {
      requestId: "client-filter",
      query: "owner",
      limit: 5,
      filter: { tenantId: TENANT_B },
    }),
    (error) => error.code === "CLIENT_FILTER_FORBIDDEN",
  );
  assert.equal(calls.length, 0);
});

test("C11 derives the validity instant only from the trusted clock", async () => {
  async function searchDraft(ragClock, requestId) {
    const { catalog, rag } = await harness({ ragClock });
    const ownerContext = context(TENANT_A, "owner");
    await prepareCatalogDocument(catalog, ownerContext, "draft-guide");
    await synchronize(rag, ownerContext, "draft-guide");
    return rag.search(context(TENANT_A, "sales"), {
      requestId,
      query: "synthetic records",
      limit: 5,
    });
  }

  const beforeExpiry = await searchDraft(
    monotonicClock("2026-07-24T10:00:00.000Z"),
    "server-before-expiry",
  );
  const afterExpiry = await searchDraft(
    monotonicClock("2026-07-26T10:00:00.000Z"),
    "server-after-expiry",
  );
  assert.equal(beforeExpiry.status, "ANSWERABLE");
  assert.equal(afterExpiry.status, "REFUSED");
});

test("C11 requires C06 before any retrieval and fails closed", async () => {
  const { ragStore } = await harness();
  let searched = false;
  const guardedStore = {
    ...ragStore,
    async search(...args) {
      searched = true;
      return ragStore.search(...args);
    },
  };
  const guarded = createPermissionAwareRag({
    store: guardedStore,
    catalogReader: { async readCurrent() { return null; } },
    c06Authorizer: authorizer(),
    principalResolver: createC11SyntheticPrincipalResolver({
      benchmark: c11Benchmark,
    }),
    benchmark: c11Benchmark,
  });
  await assert.rejects(
    guarded.search(context(TENANT_A, "deny"), {
      requestId: "denied",
      query: "owner",
      limit: 5,
    }),
    (error) => error.code === "ACCESS_DENIED",
  );
  assert.equal(searched, false);
});

test("C11 rejects a forged server Principal scope hash", async () => {
  const { catalogStore, ragStore } = await harness();
  const forged = createPermissionAwareRag({
    store: ragStore,
    catalogReader: catalogStore,
    c06Authorizer: authorizer(),
    principalResolver: {
      async resolve({ tenantScope, authorizationEvidence }) {
        return {
          trustSource: "C06_HUMAN_AND_SERVER_GROUP_RESOLUTION",
          tenantId: tenantScope.tenantId,
          humanPrincipalId: authorizationEvidence.humanPrincipalId,
          humanSecurityEpoch: 1,
          principalRefs: [
            `human:${authorizationEvidence.humanPrincipalId}`,
            "group:synthetic-finance",
          ],
          principalScopeHash:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        };
      },
    },
    benchmark: c11Benchmark,
  });
  await assert.rejects(
    forged.search(context(TENANT_A, "sales"), {
      requestId: "forged-principal-scope",
      query: "alpha",
      limit: 5,
    }),
    (error) => error.code === "PRINCIPAL_UNVERIFIED",
  );
  assert.equal(ragStore.inspect().audits.length, 0);
});

test("C11 rejects a stale server Principal security epoch", async () => {
  const { catalogStore, ragStore } = await harness();
  const principalRefs = [
    `human:${SALES}`,
    "group:synthetic-finance",
  ];
  const stale = createPermissionAwareRag({
    store: ragStore,
    catalogReader: catalogStore,
    c06Authorizer: authorizer(),
    principalResolver: {
      async resolve({ tenantScope, authorizationEvidence }) {
        return {
          trustSource: "C06_HUMAN_AND_SERVER_GROUP_RESOLUTION",
          tenantId: tenantScope.tenantId,
          humanPrincipalId: authorizationEvidence.humanPrincipalId,
          humanSecurityEpoch: 2,
          principalRefs,
          principalScopeHash: c11Sha256(principalRefs),
        };
      },
    },
    benchmark: c11Benchmark,
  });
  await assert.rejects(
    stale.search(context(TENANT_A, "sales"), {
      requestId: "stale-principal-epoch",
      query: "alpha",
      limit: 5,
    }),
    (error) => error.code === "PRINCIPAL_UNVERIFIED",
  );
  assert.equal(ragStore.inspect().audits.length, 0);
});

test("C11 prefilters state, validity, ACL, and Tenant before hybrid ranking", async () => {
  const { catalog, rag, ragStore } = await harness();
  const ownerContext = context(TENANT_A, "owner");
  for (const documentId of [
    "sales-guide",
    "finance-register",
    "draft-guide",
  ]) {
    await prepareCatalogDocument(catalog, ownerContext, documentId);
    await synchronize(rag, ownerContext, documentId);
  }
  await prepareCatalogDocument(
    catalog,
    ownerContext,
    "withdrawn-guide",
    { publish: false },
  );
  await synchronize(rag, ownerContext, "withdrawn-guide");

  const sales = await search(
    rag,
    "sales",
    "owner ACL publication",
    "sales-owner",
  );
  assert.equal(sales.status, "ANSWERABLE");
  assert.equal(sales.evidence[0].documentId, "sales-guide");
  assert.equal(sales.evidence[0].chunk.ordinal, 9);

  const finance = await search(
    rag,
    "finance",
    "alpha value",
    "finance-alpha",
  );
  assert.equal(finance.status, "ANSWERABLE");
  assert.equal(finance.evidence[0].documentId, "finance-register");

  const salesFinance = await search(
    rag,
    "sales",
    "alpha value",
    "sales-finance",
  );
  assert.equal(salesFinance.status, "REFUSED");
  const expired = await search(
    rag,
    "sales",
    "synthetic records",
    "expired-document",
  );
  assert.equal(expired.status, "ANSWERABLE");
  assert.ok(
    expired.evidence.every(
      (evidence) => evidence.documentId === "sales-guide",
    ),
  );
  const outsider = await search(
    rag,
    "outsider",
    "owner ACL publication",
    "outsider",
  );
  assert.equal(outsider.status, "REFUSED");
  assert.equal(
    ragStore.inspect().chunks.some(
      (chunk) => chunk.documentId === "withdrawn-guide",
    ),
    false,
  );
});

test("C11 EvidenceRef spans Original, Page, Section, Table, and Chunk", async () => {
  const { catalog, rag } = await harness();
  const ownerContext = context(TENANT_A, "owner");
  await prepareCatalogDocument(catalog, ownerContext, "sales-guide");
  await synchronize(rag, ownerContext, "sales-guide");
  const result = await search(
    rag,
    "sales",
    "Synthetic only",
    "provenance-table",
  );
  assert.equal(result.status, "ANSWERABLE");
  const tableEvidence = result.evidence.find(
    (evidence) => evidence.table !== null,
  );
  assert.ok(tableEvidence);
  assert.match(tableEvidence.original.nodeId, /^knn_[0-9a-f]{32}$/);
  assert.match(tableEvidence.page.nodeId, /^knn_[0-9a-f]{32}$/);
  assert.match(tableEvidence.section.nodeId, /^knn_[0-9a-f]{32}$/);
  assert.match(tableEvidence.table.nodeId, /^knn_[0-9a-f]{32}$/);
  assert.match(tableEvidence.chunk.nodeId, /^knn_[0-9a-f]{32}$/);
  assert.equal(
    result.answer.citations[0],
    result.evidence[0].evidenceId,
  );
});

test("C11 refuses deterministically when authorized evidence is insufficient", async () => {
  const { catalog, rag } = await harness();
  const ownerContext = context(TENANT_A, "owner");
  await prepareCatalogDocument(catalog, ownerContext, "sales-guide");
  await synchronize(rag, ownerContext, "sales-guide");
  const result = await search(
    rag,
    "sales",
    "quantum turbine warranty",
    "insufficient",
  );
  assert.deepEqual(
    {
      status: result.status,
      reasonCode: result.reasonCode,
      answer: result.answer,
      modelContext: result.modelContext,
      evidence: result.evidence,
    },
    {
      status: "REFUSED",
      reasonCode: "INSUFFICIENT_AUTHORIZED_EVIDENCE",
      answer: null,
      modelContext: [],
      evidence: [],
    },
  );
});

test("C11 cache is principal-scoped and audits contain hashes, not bodies", async () => {
  const { catalog, rag, ragStore } = await harness();
  const ownerContext = context(TENANT_A, "owner");
  await prepareCatalogDocument(catalog, ownerContext, "sales-guide");
  await synchronize(rag, ownerContext, "sales-guide");
  const first = await search(rag, "sales", "owner ACL", "cache-one");
  const second = await search(rag, "sales", "owner ACL", "cache-two");
  const outsider = await search(
    rag,
    "outsider",
    "owner ACL",
    "cache-outsider",
  );
  assert.equal(first.cacheHit, false);
  assert.equal(second.cacheHit, true);
  assert.equal(outsider.cacheHit, false);
  assert.equal(outsider.status, "REFUSED");
  const snapshot = ragStore.inspect();
  assert.equal(snapshot.caches.length, 2);
  for (const audit of snapshot.audits) {
    assert.equal("query" in audit, false);
    assert.equal("text" in audit, false);
    assert.equal("context" in audit, false);
    assert.equal("answer" in audit, false);
    assert.match(audit.queryHash, /^sha256:[0-9a-f]{64}$/);
  }
});

test("C11 withdrawal and deletion deactivate index rows and invalidate cache", async () => {
  const { catalog, rag, ragStore } = await harness();
  const ownerContext = context(TENANT_A, "owner");
  await prepareCatalogDocument(catalog, ownerContext, "sales-guide");
  await synchronize(rag, ownerContext, "sales-guide");
  await search(rag, "sales", "owner ACL", "before-withdraw");
  await catalog.withdraw(
    ownerContext,
    command("withdraw", "sales-guide", 4),
  );
  const withdrawn = await synchronize(
    rag,
    ownerContext,
    "sales-guide",
    1,
  );
  assert.equal(withdrawn.activeChunkCount, 0);
  assert.equal(withdrawn.invalidatedCacheCount, 1);
  assert.equal(
    (await search(rag, "sales", "owner ACL", "after-withdraw")).status,
    "REFUSED",
  );
  assert.ok(
    ragStore
      .inspect()
      .chunks.filter((chunk) => chunk.documentId === "sales-guide")
      .every((chunk) => chunk.active === false),
  );

  await prepareCatalogDocument(
    catalog,
    ownerContext,
    "withdrawn-guide",
  );
  await synchronize(rag, ownerContext, "withdrawn-guide");
  await search(rag, "sales", "owner ACL", "before-delete");
  await catalog.delete(
    ownerContext,
    command("delete", "withdrawn-guide", 4),
  );
  const deleted = await synchronize(
    rag,
    ownerContext,
    "withdrawn-guide",
    1,
  );
  assert.equal(deleted.projection.state, "DELETED");
  assert.equal(deleted.activeChunkCount, 0);
  assert.equal(
    (await search(rag, "sales", "owner ACL", "after-delete")).status,
    "REFUSED",
  );
});

test("C11 does not revive cache entries written across an epoch change", async () => {
  const baseStore = createMemoryPermissionAwareRagStore();
  let pauseWrite = false;
  let signalWrite;
  let resumeWrite;
  const writeStarted = new Promise((resolve) => {
    signalWrite = resolve;
  });
  const writeMayResume = new Promise((resolve) => {
    resumeWrite = resolve;
  });
  const delayedStore = {
    ...baseStore,
    async writeCache(...args) {
      if (pauseWrite) {
        signalWrite();
        await writeMayResume;
      }
      return baseStore.writeCache(...args);
    },
  };
  const { catalog, rag } = await harness({ ragStore: delayedStore });
  const ownerContext = context(TENANT_A, "owner");
  await prepareCatalogDocument(catalog, ownerContext, "sales-guide");
  await synchronize(rag, ownerContext, "sales-guide");

  pauseWrite = true;
  const inFlight = search(
    rag,
    "sales",
    "owner ACL publication",
    "epoch-race-in-flight",
  );
  await writeStarted;
  await catalog.withdraw(
    ownerContext,
    command("withdraw", "sales-guide", 4),
  );
  await synchronize(rag, ownerContext, "sales-guide", 1);
  resumeWrite();

  const raced = await inFlight;
  pauseWrite = false;
  const after = await search(
    rag,
    "sales",
    "owner ACL publication",
    "epoch-race-after",
  );
  assert.equal(raced.status, "REFUSED");
  assert.equal(after.status, "REFUSED");
  assert.equal(after.cacheHit, true);
  assert.deepEqual(after.evidence, []);
});

test("C11 safely refuses after two cache epoch conflicts", async () => {
  const baseStore = createMemoryPermissionAwareRagStore();
  let retrievalCount = 0;
  const unstableStore = {
    ...baseStore,
    async search(...args) {
      retrievalCount += 1;
      return baseStore.search(...args);
    },
    async writeCache() {
      return false;
    },
  };
  const { catalog, rag } = await harness({ ragStore: unstableStore });
  const ownerContext = context(TENANT_A, "owner");
  await prepareCatalogDocument(catalog, ownerContext, "sales-guide");
  await synchronize(rag, ownerContext, "sales-guide");

  const result = await search(
    rag,
    "sales",
    "owner ACL publication",
    "epoch-conflict-twice",
  );
  assert.equal(retrievalCount, 2);
  assert.equal(result.status, "REFUSED");
  assert.equal(result.answer, null);
  assert.deepEqual(result.modelContext, []);
  assert.deepEqual(result.evidence, []);
});

test("C11 projection is replay-safe, concurrent, and recoverable from snapshot", async () => {
  const { catalog, catalogStore, rag, ragStore } = await harness();
  const ownerContext = context(TENANT_A, "owner");
  await prepareCatalogDocument(catalog, ownerContext, "sales-guide");
  const first = await synchronize(rag, ownerContext, "sales-guide");
  const replay = await synchronize(rag, ownerContext, "sales-guide");
  assert.equal(first.replayed, false);
  assert.equal(replay.replayed, true);
  await assert.rejects(
    rag.synchronize(ownerContext, {
      idempotencyKey: "project-sales-guide-0",
      documentId: "sales-guide",
      documentVersion: 1,
      expectedProjectionVersion: 99,
    }),
    (error) => error.code === "IDEMPOTENCY_CONFLICT",
  );

  await prepareCatalogDocument(
    catalog,
    ownerContext,
    "finance-register",
  );
  const conflicting = [
    rag.synchronize(ownerContext, {
      idempotencyKey: "concurrent-a",
      documentId: "finance-register",
      documentVersion: 1,
      expectedProjectionVersion: 0,
    }),
    rag.synchronize(ownerContext, {
      idempotencyKey: "concurrent-b",
      documentId: "finance-register",
      documentVersion: 1,
      expectedProjectionVersion: 0,
    }),
  ];
  const settled = await Promise.allSettled(conflicting);
  assert.equal(
    settled.filter((result) => result.status === "fulfilled").length,
    1,
  );
  assert.equal(
    settled.find((result) => result.status === "rejected").reason.code,
    "VERSION_CONFLICT",
  );

  const recoveredStore = createMemoryPermissionAwareRagStore({
    snapshot: ragStore.exportSnapshot(),
  });
  const recovered = createPermissionAwareRag({
    store: recoveredStore,
    catalogReader: catalogStore,
    c06Authorizer: authorizer(),
    principalResolver: createC11SyntheticPrincipalResolver({
      benchmark: c11Benchmark,
    }),
    benchmark: c11Benchmark,
    clock: monotonicClock("2026-07-26T11:00:00.000Z"),
  });
  const result = await search(
    recovered,
    "sales",
    "owner ACL publication",
    "recovered",
  );
  assert.equal(result.status, "ANSWERABLE");
});

test("C11 cross-Tenant data cannot appear in another Tenant response", async () => {
  const { catalog, rag } = await harness();
  const tenantB = context(TENANT_B, "owner");
  await prepareCatalogDocument(catalog, tenantB, "sales-guide");
  await synchronize(rag, tenantB, "sales-guide");
  const tenantAResult = await search(
    rag,
    "sales",
    "owner ACL publication",
    "tenant-a-empty",
  );
  assert.equal(tenantAResult.status, "REFUSED");
  const tenantBResult = await rag.search(context(TENANT_B, "sales"), {
    requestId: "tenant-b",
    query: "owner ACL publication",
    limit: 5,
  });
  assert.equal(tenantBResult.status, "ANSWERABLE");
  assert.ok(
    tenantBResult.evidence.every(
      (evidence) => evidence.tenantId === TENANT_B,
    ),
  );
});

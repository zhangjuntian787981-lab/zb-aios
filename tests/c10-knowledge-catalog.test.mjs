import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  buildC10SyntheticParserQualityReport,
  c10Sha256,
  createC10SyntheticParserAdapter,
  createC10SyntheticBenchmark,
  createKnowledgeCatalog,
  createMemoryC10QuarantineStore,
  createMemoryKnowledgeCatalogStore,
  inspectSyntheticDocument,
  parseSyntheticCandidate,
  validateKnowledgeProvenance,
} from "../lib/knowledge-catalog.mjs";

const benchmarkDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c10/synthetic-document-benchmark.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const benchmark = createC10SyntheticBenchmark(benchmarkDocument);
const parserGoldenDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c10/synthetic-parser-golden.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const frozenParserQualityReport = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c10/synthetic-parser-quality-report.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const TENANT_A = "stn_01984910-5000-7000-8000-000000000001";
const TENANT_B = "stn_01984910-5000-7000-8000-000000000002";
const HUMAN = "prn_01984910-5000-7000-8000-000000000011";
const WORKLOAD = "prn_01984910-5000-7000-8000-000000000012";
const DELEGATION = "dlg_01984910-5000-7000-8000-000000000021";

function timeSource(start = "2026-07-26T00:00:00.000Z") {
  let time = Date.parse(start);
  return {
    clock: () => {
      const result = new Date(time).toISOString();
      time += 60_000;
      return result;
    },
    set(value) {
      time = Date.parse(value);
    },
  };
}

function context(tenantId = TENANT_A, token = "allow") {
  return {
    tenantScope: {
      trustSource: "C07_VERIFIED_TENANT_SCOPE",
      tenantId,
      tenantKind: "SYNTHETIC",
      lifecycleVersion: 2,
      correlationId: `c10-${tenantId}`,
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
  return {
    async enforce(serverContext, request, descriptor) {
      calls.push({
        tenantId: serverContext.tenantId,
        resourceId: request.resourceId,
        surface: descriptor.surface,
      });
      if (request.sessionToken !== "allow") {
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
        humanPrincipalId: HUMAN,
        humanSecurityEpoch: 1,
        workloadActorPrincipalId: WORKLOAD,
        workloadActorSecurityEpoch: 1,
        leafDelegationId: DELEGATION,
        delegationChainSha256:
          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        purposeRef: "synthetic://c10/test",
      };
    },
  };
}

function metadata(
  documentId = "policy-guide",
  version = "2026.1",
  validUntil = "2027-01-01T00:00:00.000Z",
) {
  return {
    ownerPrincipalId: HUMAN,
    sourceRef: "fixture://c10/source-register",
    version,
    validFrom: "2026-01-01T00:00:00.000Z",
    validUntil,
    classification: "INTERNAL",
    acl: {
      resourceId: documentId,
      readPrincipalRefs: ["group:synthetic-readers"],
      managePrincipalRefs: ["group:synthetic-knowledge-owners"],
    },
  };
}

function uploadCommand(
  documentId = "policy-guide",
  documentVersion = 1,
  fixtureRef = "fixture://c10/clean-markdown",
) {
  return {
    idempotencyKey: `upload-${documentId}-${documentVersion}`,
    documentId,
    documentVersion,
    expectedRevision: 0,
    fixtureRef,
    filename: "clean-guide.md",
    declaredMediaType: "text/markdown",
    sourceRef: `fixture://c10/${documentId}/source`,
  };
}

function lifecycleCommand(
  operation,
  documentId,
  documentVersion,
  expectedRevision,
) {
  return {
    idempotencyKey: `${operation}-${documentId}-${documentVersion}-${expectedRevision}`,
    documentId,
    documentVersion,
    expectedRevision,
  };
}

async function parsedCatalog({
  store = createMemoryKnowledgeCatalogStore(),
  clock = timeSource(),
  documentId = "policy-guide",
  documentVersion = 1,
  fixtureRef = "fixture://c10/clean-markdown",
} = {}) {
  const calls = [];
  const catalog = createKnowledgeCatalog({
    store,
    c06Authorizer: authorizer(calls),
    benchmark,
    clock: clock.clock,
  });
  const ctx = context();
  await catalog.upload(
    ctx,
    uploadCommand(documentId, documentVersion, fixtureRef),
  );
  const inspected = await catalog.inspect(
    ctx,
    lifecycleCommand("inspect", documentId, documentVersion, 1),
  );
  assert.equal(inspected.document.state, "INSPECTED");
  const parsed = await catalog.parse(
    ctx,
    lifecycleCommand("parse", documentId, documentVersion, 2),
  );
  assert.equal(parsed.document.state, "PARSED_CANDIDATE");
  return { catalog, store, clock, ctx, calls, parsed };
}

test("C10 benchmark freezes only synthetic bytes and verifies every hash", () => {
  assert.equal(benchmark.refs.length, 7);
  for (const fixtureRef of benchmark.refs) {
    const resolved = benchmark.resolve(fixtureRef);
    assert.equal(
      resolved.content.byteLength,
      resolved.fixture.content_size,
    );
  }
  assert.throws(
    () => benchmark.resolve("fixture://enterprise/private-document"),
    (error) => error.code === "SYNTHETIC_BOUNDARY_VIOLATION",
  );
});

test("C10 upload writes only to the Tenant quarantine and deletion erases it", async () => {
  const quarantineStore = createMemoryC10QuarantineStore();
  const store = createMemoryKnowledgeCatalogStore();
  const clock = timeSource();
  const catalog = createKnowledgeCatalog({
    store,
    c06Authorizer: authorizer(),
    benchmark,
    quarantineStore,
    clock: clock.clock,
  });
  const ctx = context();
  const uploaded = await catalog.upload(ctx, uploadCommand());
  assert.equal(uploaded.document.state, "QUARANTINED");
  assert.match(
    uploaded.document.quarantineRef,
    new RegExp(
      `^quarantine://c10/${TENANT_A}/policy-guide/1/[0-9a-f]{64}$`,
    ),
  );
  assert.equal(
    quarantineStore.has({
      tenantId: TENANT_A,
      contentSha256: uploaded.document.contentSha256,
    }),
    true,
  );
  await assert.rejects(
    quarantineStore.read({
      tenantId: TENANT_B,
      quarantineRef: uploaded.document.quarantineRef,
      contentSha256: uploaded.document.contentSha256,
    }),
    (error) => error.code === "TENANT_SCOPE_VIOLATION",
  );
  await catalog.delete(
    ctx,
    lifecycleCommand("delete", "policy-guide", 1, 1),
  );
  assert.equal(
    quarantineStore.has({
      tenantId: TENANT_A,
      contentSha256: uploaded.document.contentSha256,
    }),
    false,
  );
  const oldUploadReplay = await catalog.upload(ctx, uploadCommand());
  assert.equal(oldUploadReplay.replayed, true);
  assert.equal(
    quarantineStore.has({
      tenantId: TENANT_A,
      contentSha256: uploaded.document.contentSha256,
    }),
    false,
  );
});

test("C10 preserves shared bytes until every document-version reference is deleted", async () => {
  const quarantineStore = createMemoryC10QuarantineStore();
  const store = createMemoryKnowledgeCatalogStore();
  const catalog = createKnowledgeCatalog({
    store,
    c06Authorizer: authorizer(),
    benchmark,
    quarantineStore,
    clock: timeSource().clock,
  });
  const ctx = context();
  const first = await catalog.upload(
    ctx,
    uploadCommand("shared-policy", 1),
  );
  const second = await catalog.upload(
    ctx,
    uploadCommand("shared-policy", 2),
  );
  assert.notEqual(
    first.document.quarantineRef,
    second.document.quarantineRef,
  );
  const sharedSnapshot = quarantineStore.exportSnapshot();
  assert.equal(sharedSnapshot.objects.length, 1);
  assert.equal(sharedSnapshot.references.length, 2);

  await catalog.delete(
    ctx,
    lifecycleCommand("delete", "shared-policy", 1, 1),
  );
  const remaining = await quarantineStore.read({
    tenantId: TENANT_A,
    quarantineRef: second.document.quarantineRef,
    contentSha256: second.document.contentSha256,
  });
  assert.equal(c10Sha256(remaining), second.document.contentSha256);
  const remainingSnapshot = quarantineStore.exportSnapshot();
  assert.equal(remainingSnapshot.objects.length, 1);
  assert.equal(remainingSnapshot.references.length, 1);

  const recoveredQuarantine = createMemoryC10QuarantineStore({
    snapshot: quarantineStore.exportSnapshot(),
  });
  const recoveredStore = createMemoryKnowledgeCatalogStore({
    snapshot: store.exportSnapshot(),
  });
  const recovered = createKnowledgeCatalog({
    store: recoveredStore,
    c06Authorizer: authorizer(),
    benchmark,
    quarantineStore: recoveredQuarantine,
    clock: timeSource("2026-07-27T00:00:00.000Z").clock,
  });
  const deletion = lifecycleCommand("delete", "shared-policy", 2, 1);
  await recovered.delete(ctx, deletion);
  const replay = await recovered.delete(ctx, deletion);
  assert.equal(replay.replayed, true);
  assert.equal(
    recoveredQuarantine.has({
      tenantId: TENANT_A,
      contentSha256: second.document.contentSha256,
    }),
    false,
  );
});

test("C10 isolation inspection checks type, size, macro, virus, and hidden instructions", () => {
  const expected = new Map([
    ["fixture://c10/clean-markdown", []],
    ["fixture://c10/macro-docm", ["MACRO_DETECTED"]],
    ["fixture://c10/virus-marker", ["VIRUS_MARKER"]],
    ["fixture://c10/hidden-instruction", ["HIDDEN_INSTRUCTION"]],
    ["fixture://c10/oversized", ["FILE_TOO_LARGE"]],
  ]);
  for (const [fixtureRef, requiredFindings] of expected) {
    const { content, fixture } = benchmark.resolve(fixtureRef);
    const result = inspectSyntheticDocument({
      filename: fixture.filename,
      declaredMediaType: fixture.declared_media_type,
      content,
      maxFileBytes: benchmark.maxFileBytes,
    });
    for (const finding of requiredFindings) {
      assert.equal(result.findings.includes(finding), true, fixtureRef);
    }
    assert.equal(
      result.outcome,
      requiredFindings.length === 0 ? "PASS" : "REJECT",
    );
  }
  const { content } = benchmark.resolve("fixture://c10/clean-markdown");
  const mismatch = inspectSyntheticDocument({
    filename: "wrong.pdf",
    declaredMediaType: "application/pdf",
    content,
    maxFileBytes: benchmark.maxFileBytes,
  });
  assert.equal(mismatch.findings.includes("FILE_TYPE_MISMATCH"), true);
  assert.equal(mismatch.findings.includes("UNSUPPORTED_FILE_TYPE"), true);
});

test("C10 parser emits candidates with original-page-section-table-chunk provenance", () => {
  const { content, fixture } = benchmark.resolve(
    "fixture://c10/clean-markdown",
  );
  const parsed = parseSyntheticCandidate({
    documentId: "policy-guide",
    documentVersion: 1,
    content,
    contentSha256: fixture.content_sha256,
    mediaType: fixture.declared_media_type,
    parserVersion: benchmark.parserVersion,
  });
  assert.equal(parsed.authorityStatus, "CANDIDATE");
  assert.equal(parsed.pageCount, 2);
  assert.equal(parsed.sectionCount, 2);
  assert.equal(parsed.tableCount, 1);
  assert.equal(parsed.chunkCount >= 4, true);
  assert.equal(
    parsed.nodes.every(
      (node) =>
        node.authorityStatus === "CANDIDATE" &&
        node.availabilityState === "CANDIDATE",
    ),
    true,
  );
  assert.equal(
    validateKnowledgeProvenance(parsed.nodes, fixture.content_sha256),
    true,
  );
  const table = parsed.nodes.find((node) => node.nodeType === "TABLE");
  const row = parsed.nodes.find(
    (node) =>
      node.nodeType === "CHUNK" &&
      node.location.chunkKind === "TABLE_ROW",
  );
  assert.equal(row.parentNodeId, table.nodeId);
});

test("C10 parser adapter exposes a frozen synthetic scan seam without claiming OCR", async () => {
  const parserAdapter = createC10SyntheticParserAdapter({
    goldenDocument: parserGoldenDocument,
  });
  const fixtureRef = "fixture://c10/synthetic-scan";
  const { content, fixture } = benchmark.resolve(fixtureRef);
  const inspection = inspectSyntheticDocument({
    filename: fixture.filename,
    declaredMediaType: fixture.declared_media_type,
    content,
    maxFileBytes: benchmark.maxFileBytes,
  });
  assert.equal(inspection.outcome, "PASS");

  const parsed = await parserAdapter.parse({
    fixtureRef,
    documentId: "golden-scan",
    documentVersion: 1,
    content,
    contentSha256: fixture.content_sha256,
    mediaType: fixture.declared_media_type,
    parserVersion: benchmark.parserVersion,
  });
  assert.equal(parsed.adapterKind, "SYNTHETIC_DETERMINISTIC");
  assert.equal(
    parsed.parserRoute,
    "SYNTHETIC_SCANNED_IMAGE_TRANSCRIPT",
  );
  assert.equal(parsed.verificationScope, "P1_SYNTHETIC_ONLY");
  assert.equal(parsed.productionOcrVerified, false);
  assert.equal(parsed.nodes[0].textSha256, fixture.content_sha256);
  assert.equal(
    parsed.nodes.every(
      (node) => node.sourceSha256 === fixture.content_sha256,
    ),
    true,
  );
  assert.deepEqual(
    {
      pageCount: parsed.pageCount,
      sectionCount: parsed.sectionCount,
      tableCount: parsed.tableCount,
      chunkCount: parsed.chunkCount,
    },
    {
      pageCount:
        parserGoldenDocument.fixtures[1].expected.pageCount,
      sectionCount:
        parserGoldenDocument.fixtures[1].expected.sectionCount,
      tableCount:
        parserGoldenDocument.fixtures[1].expected.tableCount,
      chunkCount:
        parserGoldenDocument.fixtures[1].expected.chunkCount,
    },
  );
});

test("C10 catalog accepts a replacement parser only through the closed adapter seam", async () => {
  const base = createC10SyntheticParserAdapter({
    goldenDocument: parserGoldenDocument,
  });
  const calls = [];
  const parserAdapter = {
    async parse(input) {
      calls.push(input.fixtureRef);
      const parsed = await base.parse(input);
      return {
        ...parsed,
        adapterId: "c10-replacement-adapter-test-v1",
        parserVersion: "c10-replacement-parser-test-v1",
      };
    },
  };
  const catalog = createKnowledgeCatalog({
    store: createMemoryKnowledgeCatalogStore(),
    c06Authorizer: authorizer(),
    benchmark,
    parserAdapter,
    clock: timeSource().clock,
  });
  const ctx = context();
  await catalog.upload(ctx, uploadCommand("replacement-seam"));
  await catalog.inspect(
    ctx,
    lifecycleCommand("inspect", "replacement-seam", 1, 1),
  );
  const parsed = await catalog.parse(
    ctx,
    lifecycleCommand("parse", "replacement-seam", 1, 2),
  );
  assert.deepEqual(calls, ["fixture://c10/clean-markdown"]);
  assert.equal(
    parsed.document.parserVersion,
    "c10-replacement-parser-test-v1",
  );
});

test("C10 catalog rejects an adapter result with undeclared output fields", async () => {
  const base = createC10SyntheticParserAdapter({
    goldenDocument: parserGoldenDocument,
  });
  const catalog = createKnowledgeCatalog({
    store: createMemoryKnowledgeCatalogStore(),
    c06Authorizer: authorizer(),
    benchmark,
    parserAdapter: {
      async parse(input) {
        return {
          ...(await base.parse(input)),
          undeclared: true,
        };
      },
    },
    clock: timeSource().clock,
  });
  const ctx = context();
  await catalog.upload(ctx, uploadCommand("closed-adapter"));
  await catalog.inspect(
    ctx,
    lifecycleCommand("inspect", "closed-adapter", 1, 1),
  );
  await assert.rejects(
    catalog.parse(
      ctx,
      lifecycleCommand("parse", "closed-adapter", 1, 2),
    ),
    (error) => error.code === "INVALID_PARSER_RESULT",
  );
});

test("C10 parser quality report is recomputable from frozen synthetic golden fixtures", async () => {
  const report = await buildC10SyntheticParserQualityReport({
    benchmark,
    goldenDocument: parserGoldenDocument,
    parserAdapter: createC10SyntheticParserAdapter({
      goldenDocument: parserGoldenDocument,
    }),
  });
  assert.equal(report.verificationScope, "P1_SYNTHETIC_ONLY");
  assert.equal(report.productionOcrVerified, false);
  assert.equal(report.fixtureCount, 2);
  assert.equal(report.passedCount, 2);
  assert.equal(report.failedCount, 0);
  assert.match(report.reportSha256, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(report, frozenParserQualityReport);
});

test("C10 clean lifecycle keeps parser output candidate until complete metadata publication", async () => {
  const { catalog, parsed, ctx } = await parsedCatalog();
  assert.equal(parsed.document.metadata, null);
  const published = await catalog.publish(ctx, {
    ...lifecycleCommand("publish", "policy-guide", 1, 3),
    metadata: metadata(),
  });
  assert.equal(published.document.state, "PUBLISHED");
  assert.equal(published.document.revision, 4);
  assert.equal(
    published.document.nodes.every(
      (node) => node.availabilityState === "PUBLISHED",
    ),
    true,
  );
});

test("C10 refuses publication when any required catalog field is missing", async (t) => {
  const required = [
    "ownerPrincipalId",
    "sourceRef",
    "version",
    "validFrom",
    "validUntil",
    "classification",
    "acl",
  ];
  for (const field of required) {
    await t.test(field, async () => {
      const { catalog, ctx } = await parsedCatalog({
        documentId: `missing-${field.toLowerCase()}`,
      });
      const value = metadata(`missing-${field.toLowerCase()}`);
      delete value[field];
      await assert.rejects(
        catalog.publish(ctx, {
          ...lifecycleCommand(
            "publish",
            `missing-${field.toLowerCase()}`,
            1,
            3,
          ),
          metadata: value,
        }),
        (error) =>
          ["INVALID_INPUT", "REQUIRED_METADATA_MISSING"].includes(
            error.code,
          ),
      );
    });
  }
});

test("C10 invokes same-Tenant server-side C06 on every operation and fails closed", async () => {
  const calls = [];
  const store = createMemoryKnowledgeCatalogStore();
  const clock = timeSource();
  const catalog = createKnowledgeCatalog({
    store,
    c06Authorizer: authorizer(calls),
    benchmark,
    clock: clock.clock,
  });
  await catalog.upload(context(), uploadCommand());
  await assert.rejects(
    catalog.inspect(
      context(TENANT_A, "deny"),
      lifecycleCommand("inspect", "policy-guide", 1, 1),
    ),
    (error) => error.code === "ACCESS_DENIED",
  );
  const mismatched = context();
  mismatched.c06ServerContext.tenantId = TENANT_B;
  await assert.rejects(
    catalog.inspect(
      mismatched,
      lifecycleCommand("inspect", "policy-guide", 1, 1),
    ),
    (error) => error.code === "TENANT_SCOPE_VIOLATION",
  );
  assert.equal(calls[0].surface, "MANAGE");
  assert.equal(calls[0].resourceId, "policy-guide");
});

test("C10 rejects cross-Tenant reads and never falls back to another Tenant", async () => {
  const { catalog } = await parsedCatalog();
  const other = context(TENANT_B);
  const result = await catalog.readAsOf(other, {
    documentId: "policy-guide",
    asOf: "2026-07-26T23:00:00.000Z",
  });
  assert.equal(result, null);
});

test("C10 idempotent replay survives renewed authorization but conflicts on changed input", async () => {
  const calls = [];
  const store = createMemoryKnowledgeCatalogStore();
  const clock = timeSource();
  const catalog = createKnowledgeCatalog({
    store,
    c06Authorizer: authorizer(calls),
    benchmark,
    clock: clock.clock,
  });
  const first = await catalog.upload(context(), uploadCommand());
  const replay = await catalog.upload(context(), uploadCommand());
  assert.equal(first.document.revision, 1);
  assert.equal(replay.replayed, true);
  assert.equal(replay.document.createdAt, first.document.createdAt);
  assert.equal(calls.length, 2);
  await assert.rejects(
    catalog.upload(context(), {
      ...uploadCommand(),
      filename: "changed.md",
    }),
    (error) => error.code === "IDEMPOTENCY_CONFLICT",
  );
});

test("C10 optimistic concurrency lets only one publication win", async () => {
  const { catalog, ctx } = await parsedCatalog();
  const attempts = await Promise.allSettled([
    catalog.publish(ctx, {
      ...lifecycleCommand("publish-a", "policy-guide", 1, 3),
      metadata: metadata(),
    }),
    catalog.publish(ctx, {
      ...lifecycleCommand("publish-b", "policy-guide", 1, 3),
      metadata: metadata("policy-guide", "2026.2"),
    }),
  ]);
  assert.equal(
    attempts.filter((result) => result.status === "fulfilled").length,
    1,
  );
  assert.equal(
    attempts.filter(
      (result) =>
        result.status === "rejected" &&
        result.reason.code === "VERSION_CONFLICT",
    ).length,
    1,
  );
});

test("C10 version and as-of selection exclude withdrawn current knowledge", async () => {
  const clock = timeSource();
  const store = createMemoryKnowledgeCatalogStore();
  const { catalog, ctx } = await parsedCatalog({ store, clock });
  await catalog.publish(ctx, {
    ...lifecycleCommand("publish", "policy-guide", 1, 3),
    metadata: metadata(),
  });
  const beforeWithdraw = "2026-07-26T00:03:30.000Z";
  const selected = await catalog.readAsOf(ctx, {
    documentId: "policy-guide",
    asOf: beforeWithdraw,
  });
  assert.equal(selected.documentVersion, 1);
  await catalog.withdraw(
    ctx,
    lifecycleCommand("withdraw", "policy-guide", 1, 4),
  );
  const unavailable = await catalog.readAsOf(ctx, {
    documentId: "policy-guide",
    asOf: "2026-07-26T00:10:00.000Z",
  });
  assert.equal(unavailable, null);
  const historical = await catalog.readAsOf(ctx, {
    documentId: "policy-guide",
    asOf: beforeWithdraw,
  });
  assert.equal(historical.state, "PUBLISHED");
});

test("C10 rejects a version gap and selects the highest valid published version", async () => {
  const clock = timeSource();
  const store = createMemoryKnowledgeCatalogStore();
  const first = await parsedCatalog({ store, clock });
  await first.catalog.publish(first.ctx, {
    ...lifecycleCommand("publish", "policy-guide", 1, 3),
    metadata: metadata(),
  });
  await assert.rejects(
    first.catalog.upload(
      first.ctx,
      uploadCommand("policy-guide", 3),
    ),
    (error) => error.code === "VERSION_CONFLICT",
  );
  const second = await parsedCatalog({
    store,
    clock,
    documentId: "policy-guide",
    documentVersion: 2,
  });
  await second.catalog.publish(second.ctx, {
    ...lifecycleCommand("publish", "policy-guide", 2, 3),
    metadata: metadata("policy-guide", "2026.2"),
  });
  const selected = await second.catalog.readAsOf(second.ctx, {
    documentId: "policy-guide",
    asOf: "2026-07-26T00:20:00.000Z",
  });
  assert.equal(selected.documentVersion, 2);
  assert.equal(selected.metadata.version, "2026.2");
});

test("C10 expiration uses the catalog validity boundary", async () => {
  const clock = timeSource();
  const { catalog, ctx } = await parsedCatalog({ clock });
  await catalog.publish(ctx, {
    ...lifecycleCommand("publish", "policy-guide", 1, 3),
    metadata: metadata(
      "policy-guide",
      "2026.1",
      "2026-07-27T00:00:00.000Z",
    ),
  });
  await assert.rejects(
    catalog.expire(
      ctx,
      lifecycleCommand("expire-early", "policy-guide", 1, 4),
    ),
    (error) => error.code === "INVALID_STATE",
  );
  clock.set("2026-07-27T00:00:00.000Z");
  const expired = await catalog.expire(
    ctx,
    lifecycleCommand("expire", "policy-guide", 1, 4),
  );
  assert.equal(expired.document.state, "EXPIRED");
  assert.equal(
    expired.document.nodes.every(
      (node) => node.availabilityState === "EXPIRED",
    ),
    true,
  );
});

test("C10 deletion propagates to every source node and recovered receipts stay idempotent", async () => {
  const store = createMemoryKnowledgeCatalogStore();
  const initial = await parsedCatalog({ store });
  const published = await initial.catalog.publish(initial.ctx, {
    ...lifecycleCommand("publish", "policy-guide", 1, 3),
    metadata: metadata(),
  });
  const deletionCommand = lifecycleCommand(
    "delete",
    "policy-guide",
    1,
    published.document.revision,
  );
  const deleted = await initial.catalog.delete(
    initial.ctx,
    deletionCommand,
  );
  assert.equal(deleted.document.state, "DELETED");
  assert.equal(
    deleted.document.nodes.every(
      (node) =>
        node.availabilityState === "DELETED" &&
        node.deletedAt === deleted.document.deletedAt,
    ),
    true,
  );

  const recoveredStore = createMemoryKnowledgeCatalogStore({
    snapshot: store.exportSnapshot(),
  });
  const recovered = createKnowledgeCatalog({
    store: recoveredStore,
    c06Authorizer: authorizer(),
    benchmark,
    clock: timeSource("2026-07-27T00:00:00.000Z").clock,
  });
  const replay = await recovered.delete(initial.ctx, deletionCommand);
  assert.equal(replay.replayed, true);
  assert.equal(replay.document.revision, deleted.document.revision);
  assert.equal(
    await recovered.readAsOf(initial.ctx, {
      documentId: "policy-guide",
      asOf: "2026-07-27T01:00:00.000Z",
    }),
    null,
  );
});

test("C10 rejected inspection can never be parsed or published", async () => {
  const store = createMemoryKnowledgeCatalogStore();
  const clock = timeSource();
  const catalog = createKnowledgeCatalog({
    store,
    c06Authorizer: authorizer(),
    benchmark,
    clock: clock.clock,
  });
  const ctx = context();
  await catalog.upload(ctx, {
    ...uploadCommand(
      "macro-document",
      1,
      "fixture://c10/macro-docm",
    ),
    filename: "macro.docm",
    declaredMediaType:
      "application/vnd.ms-word.document.macroenabled.12",
  });
  const rejected = await catalog.inspect(
    ctx,
    lifecycleCommand("inspect", "macro-document", 1, 1),
  );
  assert.equal(rejected.document.state, "REJECTED");
  await assert.rejects(
    catalog.parse(
      ctx,
      lifecycleCommand("parse", "macro-document", 1, 2),
    ),
    (error) => error.code === "INSPECTION_FAILED",
  );
  await assert.rejects(
    catalog.publish(ctx, {
      ...lifecycleCommand("publish", "macro-document", 1, 2),
      metadata: metadata("macro-document"),
    }),
    (error) => error.code === "INVALID_STATE",
  );
});

test("C10 provenance validator rejects broken parentage and altered source hashes", () => {
  const { content, fixture } = benchmark.resolve(
    "fixture://c10/clean-markdown",
  );
  const parsed = parseSyntheticCandidate({
    documentId: "policy-guide",
    documentVersion: 1,
    content,
    contentSha256: fixture.content_sha256,
    mediaType: fixture.declared_media_type,
    parserVersion: benchmark.parserVersion,
  });
  const brokenParent = structuredClone(parsed.nodes);
  const chunk = brokenParent.find((node) => node.nodeType === "CHUNK");
  chunk.parentNodeId = "knn_missing";
  assert.throws(
    () => validateKnowledgeProvenance(brokenParent, fixture.content_sha256),
    (error) => error.code === "INVALID_PROVENANCE",
  );
  const alteredHash = structuredClone(parsed.nodes);
  alteredHash[1].sourceSha256 =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  assert.throws(
    () => validateKnowledgeProvenance(alteredHash, fixture.content_sha256),
    (error) => error.code === "INVALID_PROVENANCE",
  );
});

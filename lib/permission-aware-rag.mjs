import { createHash } from "node:crypto";

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const PRINCIPAL_ID = new RegExp(`^prn_${UUID_V7}$`);
const DELEGATION_ID = new RegExp(`^dlg_${UUID_V7}$`);
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const DOCUMENT_ID = /^[a-z][a-z0-9_-]{0,127}$/;
const SEARCH_SURFACE = "RETRIEVE";
const PROJECT_SURFACE = "MANAGE";
const NON_RETRIEVABLE_STATES = new Set([
  "QUARANTINED",
  "INSPECTED",
  "REJECTED",
  "PARSED_CANDIDATE",
  "WITHDRAWN",
  "EXPIRED",
  "DELETED",
]);

export class PermissionAwareRagError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PermissionAwareRagError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new PermissionAwareRagError(code, message);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function exactKeys(value, allowed, field, required = allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_INPUT", `${field} must be an object.`);
  }
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.includes(key))) {
    fail("CLIENT_FILTER_FORBIDDEN", `${field} has unsupported fields.`);
  }
  if (required.some((key) => !keys.includes(key))) {
    fail("INVALID_INPUT", `${field} is incomplete.`);
  }
}

function nonEmpty(value, field, maximum = 512) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > maximum
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function positiveInteger(value, field, { allowZero = false } = {}) {
  if (
    !Number.isSafeInteger(value) ||
    value < (allowZero ? 0 : 1)
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail("INVALID_INPUT", "Only finite JSON numbers are supported.");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  fail("INVALID_INPUT", "Only JSON values are supported.");
}

export function c11Sha256(value) {
  const input =
    typeof value === "string" || value instanceof Uint8Array
      ? value
      : canonicalize(value);
  return `sha256:${createHash("sha256").update(input).digest("hex")}`;
}

function instant(value, field) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
    new Date(value).toISOString() !== value
  ) {
    fail("INVALID_INPUT", `${field} must be a canonical UTC instant.`);
  }
  return value;
}

function validateScope(scope) {
  exactKeys(
    scope,
    [
      "trustSource",
      "tenantId",
      "tenantKind",
      "lifecycleVersion",
      "correlationId",
      "decisionId",
      "evidenceRef",
      "policyVersion",
    ],
    "C07 Tenant scope",
  );
  if (
    scope.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
    scope.tenantKind !== "SYNTHETIC" ||
    !SYNTHETIC_TENANT_ID.test(scope.tenantId ?? "") ||
    !Number.isSafeInteger(scope.lifecycleVersion) ||
    scope.lifecycleVersion < 1
  ) {
    fail(
      "TENANT_SCOPE_VIOLATION",
      "C11 requires a C07 verified Synthetic Tenant scope.",
    );
  }
  for (const field of [
    "correlationId",
    "decisionId",
    "evidenceRef",
    "policyVersion",
  ]) {
    nonEmpty(scope[field], `scope.${field}`);
  }
}

function validateContext(context) {
  exactKeys(
    context,
    ["tenantScope", "c06ServerContext", "authorizationRequest"],
    "C11 request context",
  );
  validateScope(context.tenantScope);
  exactKeys(
    context.c06ServerContext,
    [
      "synthetic",
      "routeTrustSource",
      "tenantId",
      "workloadTrustSource",
      "workloadActorPrincipalId",
    ],
    "C06 server context",
  );
  if (
    context.c06ServerContext.synthetic !== true ||
    context.c06ServerContext.routeTrustSource !==
      "VERIFIED_ROUTE_DESCRIPTOR" ||
    context.c06ServerContext.tenantId !== context.tenantScope.tenantId ||
    context.c06ServerContext.workloadTrustSource !==
      "VERIFIED_WORKLOAD_CONTEXT" ||
    !PRINCIPAL_ID.test(
      context.c06ServerContext.workloadActorPrincipalId ?? "",
    )
  ) {
    fail(
      "TENANT_SCOPE_VIOLATION",
      "C06 and C07 contexts are not bound to one Synthetic Tenant.",
    );
  }
  exactKeys(
    context.authorizationRequest,
    ["sessionToken", "delegationId", "correlationId"],
    "authorization request",
  );
  nonEmpty(
    context.authorizationRequest.sessionToken,
    "authorizationRequest.sessionToken",
    128,
  );
  if (
    !DELEGATION_ID.test(
      context.authorizationRequest.delegationId ?? "",
    )
  ) {
    fail("INVALID_INPUT", "authorizationRequest.delegationId is invalid.");
  }
  nonEmpty(
    context.authorizationRequest.correlationId,
    "authorizationRequest.correlationId",
    128,
  );
}

function validateAuthorizationEvidence(
  evidence,
  { tenantId, surface, resourceId },
) {
  if (
    evidence?.trustSource !== "C06_BOUND_DECISION_EVIDENCE" ||
    evidence?.tenantId !== tenantId ||
    evidence?.surface !== surface ||
    evidence?.resourceId !== resourceId ||
    !PRINCIPAL_ID.test(evidence?.humanPrincipalId ?? "") ||
    typeof evidence?.decisionId !== "string" ||
    !evidence.decisionId ||
    typeof evidence?.evidenceRef !== "string" ||
    !evidence.evidenceRef ||
    typeof evidence?.policyVersion !== "string" ||
    !evidence.policyVersion
  ) {
    fail(
      "AUTHORIZATION_UNAVAILABLE",
      "C06 decision is not bound to this C11 operation.",
    );
  }
}

function tokens(value) {
  return [
    ...new Set(
      value
        .toLowerCase()
        .replace(/[^\p{L}\p{N}]+/gu, " ")
        .trim()
        .split(/\s+/)
        .filter((token) => token.length > 0),
    ),
  ];
}

export function c11DeterministicEmbedding(text, dimensions = 8) {
  positiveInteger(dimensions, "embeddingDimensions");
  const vector = Array.from({ length: dimensions }, () => 0);
  for (const token of tokens(text)) {
    const hash = createHash("sha256").update(token).digest();
    const index = hash[0] % dimensions;
    const sign = (hash[1] & 1) === 0 ? 1 : -1;
    vector[index] += sign * (1 + hash[2] / 255);
  }
  const magnitude = Math.sqrt(
    vector.reduce((sum, value) => sum + value * value, 0),
  );
  if (magnitude === 0) return vector;
  return vector.map((value) => Number((value / magnitude).toFixed(8)));
}

function cosine(left, right) {
  if (
    !Array.isArray(left) ||
    !Array.isArray(right) ||
    left.length !== right.length
  ) {
    fail("INVALID_INDEX", "Embedding dimensions do not match.");
  }
  const dot = left.reduce(
    (sum, value, index) => sum + value * right[index],
    0,
  );
  const leftMagnitude = Math.sqrt(
    left.reduce((sum, value) => sum + value * value, 0),
  );
  const rightMagnitude = Math.sqrt(
    right.reduce((sum, value) => sum + value * value, 0),
  );
  if (leftMagnitude === 0 || rightMagnitude === 0) return 0;
  return dot / (leftMagnitude * rightMagnitude);
}

function lexicalScore(query, text) {
  const queryTokens = tokens(query);
  const textTokens = new Set(tokens(text));
  if (queryTokens.length === 0) return 0;
  return (
    queryTokens.filter((token) => textTokens.has(token)).length /
    queryTokens.length
  );
}

function sameJson(left, right) {
  return canonicalize(left) === canonicalize(right);
}

function publicationFromFixture(document) {
  return Object.freeze({
    ownerPrincipalId: document.publication.owner_principal_id,
    sourceRef: document.publication.source_ref,
    version: document.publication.version,
    validFrom: document.publication.valid_from,
    validUntil: document.publication.valid_until,
    classification: document.publication.classification,
    acl: clone(document.publication.acl),
  });
}

function chainFor(node, nodesById) {
  const chain = {
    original: null,
    page: null,
    section: null,
    table: null,
    chunk: node,
  };
  const seen = new Set([node.nodeId]);
  let current = node.parentNodeId
    ? nodesById.get(node.parentNodeId)
    : null;
  while (current) {
    if (seen.has(current.nodeId)) {
      fail("INVALID_PROVENANCE", "C10 source chain contains a cycle.");
    }
    seen.add(current.nodeId);
    if (current.nodeType === "ORIGINAL") chain.original = current;
    if (current.nodeType === "PAGE") chain.page = current;
    if (current.nodeType === "SECTION") chain.section = current;
    if (current.nodeType === "TABLE") chain.table = current;
    current = current.parentNodeId
      ? nodesById.get(current.parentNodeId)
      : null;
  }
  if (!chain.original || !chain.page || chain.chunk.nodeType !== "CHUNK") {
    fail("INVALID_PROVENANCE", "C10 source chain is incomplete.");
  }
  return chain;
}

export function createC11SyntheticBenchmark(document) {
  if (
    document?.schema_version !== "1.0.0" ||
    document?.work_package_id !== "C11" ||
    document?.data_classification !== "SYNTHETIC_ONLY" ||
    document?.enterprise_connectors !== "C0_DISABLED" ||
    document?.embedding_model !==
      "c11-deterministic-hash-embedding-v1" ||
    document?.embedding_dimensions !== 8 ||
    typeof document?.minimum_score !== "number" ||
    document.minimum_score <= 0 ||
    document.minimum_score > 1 ||
    !Number.isSafeInteger(document?.minimum_evidence_count) ||
    document.minimum_evidence_count < 1 ||
    document?.search_resource_id !== "knowledge-search" ||
    !Array.isArray(document?.principals) ||
    !Array.isArray(document?.documents) ||
    !Array.isArray(document?.queries)
  ) {
    fail("INVALID_BENCHMARK", "C11 synthetic benchmark is invalid.");
  }
  const principals = new Map();
  for (const principal of document.principals) {
    if (
      !PRINCIPAL_ID.test(principal?.human_principal_id ?? "") ||
      principals.has(principal.human_principal_id) ||
      !Array.isArray(principal?.principal_refs) ||
      principal.principal_refs.length === 0 ||
      principal.principal_refs.some(
        (reference) =>
          typeof reference !== "string" ||
          !/^(?:human|group):[A-Za-z0-9._-]{1,128}$/.test(reference),
      ) ||
      !principal.principal_refs.includes(
        `human:${principal.human_principal_id}`,
      )
    ) {
      fail("INVALID_BENCHMARK", "Synthetic principal fixture is invalid.");
    }
    principals.set(
      principal.human_principal_id,
      Object.freeze([...new Set(principal.principal_refs)].sort()),
    );
  }
  const documents = new Map();
  for (const fixture of document.documents) {
    if (
      !DOCUMENT_ID.test(fixture?.document_id ?? "") ||
      fixture?.document_version !== 1 ||
      !fixture?.fixture_ref?.startsWith("fixture://c10/") ||
      !SHA256.test(fixture?.content_sha256 ?? "") ||
      !SHA256.test(fixture?.parse_sha256 ?? "") ||
      !fixture?.publication ||
      !Array.isArray(fixture?.chunks) ||
      fixture.chunks.length === 0
    ) {
      fail("INVALID_BENCHMARK", "Synthetic document fixture is invalid.");
    }
    const key = `${fixture.document_id}\u0000${fixture.document_version}`;
    if (documents.has(key)) {
      fail("INVALID_BENCHMARK", "Synthetic documents must be unique.");
    }
    const ordinals = new Set();
    for (const chunk of fixture.chunks) {
      if (
        !Number.isSafeInteger(chunk?.ordinal) ||
        chunk.ordinal < 1 ||
        ordinals.has(chunk.ordinal) ||
        typeof chunk?.text !== "string" ||
        !chunk.text ||
        c11Sha256(chunk.text) !== chunk.text_sha256
      ) {
        fail("INVALID_BENCHMARK", "Synthetic Chunk fixture is invalid.");
      }
      ordinals.add(chunk.ordinal);
    }
    const publication = publicationFromFixture(fixture);
    instant(publication.validFrom, "publication.validFrom");
    instant(publication.validUntil, "publication.validUntil");
    if (
      publication.acl.resourceId !== fixture.document_id ||
      !Array.isArray(publication.acl.readPrincipalRefs) ||
      publication.acl.readPrincipalRefs.length === 0
    ) {
      fail("INVALID_BENCHMARK", "Synthetic publication ACL is invalid.");
    }
    documents.set(key, Object.freeze(clone(fixture)));
  }

  return Object.freeze({
    embeddingModel: document.embedding_model,
    embeddingDimensions: document.embedding_dimensions,
    minimumScore: document.minimum_score,
    minimumEvidenceCount: document.minimum_evidence_count,
    searchResourceId: document.search_resource_id,
    queryCases: Object.freeze(clone(document.queries)),
    resolvePrincipal({ tenantScope, authorizationEvidence }) {
      validateScope(tenantScope);
      if (
        authorizationEvidence.tenantId !== tenantScope.tenantId ||
        !PRINCIPAL_ID.test(
          authorizationEvidence.humanPrincipalId ?? "",
        )
      ) {
        fail(
          "PRINCIPAL_UNVERIFIED",
          "C06 Human is not bound to the Tenant.",
        );
      }
      const principalRefs = principals.get(
        authorizationEvidence.humanPrincipalId,
      );
      if (!principalRefs) {
        fail(
          "PRINCIPAL_UNVERIFIED",
          "Synthetic principal is not in the frozen C11 catalog.",
        );
      }
      return Object.freeze({
        trustSource: "C06_HUMAN_AND_SERVER_GROUP_RESOLUTION",
        tenantId: tenantScope.tenantId,
        humanPrincipalId: authorizationEvidence.humanPrincipalId,
        humanSecurityEpoch: authorizationEvidence.humanSecurityEpoch,
        principalRefs,
        principalScopeHash: c11Sha256(principalRefs),
      });
    },
    projectCatalogDocument(catalogDocument) {
      if (
        !catalogDocument ||
        catalogDocument.tenantKind !== "SYNTHETIC" ||
        !SYNTHETIC_TENANT_ID.test(catalogDocument.tenantId ?? "") ||
        !DOCUMENT_ID.test(catalogDocument.documentId ?? "") ||
        !Number.isSafeInteger(catalogDocument.documentVersion) ||
        !Number.isSafeInteger(catalogDocument.revision) ||
        catalogDocument.revision < 1
      ) {
        fail("CATALOG_UNVERIFIED", "C10 catalog document is invalid.");
      }
      const fixture = documents.get(
        `${catalogDocument.documentId}\u0000${catalogDocument.documentVersion}`,
      );
      if (
        !fixture ||
        fixture.fixture_ref !== catalogDocument.fixtureRef ||
        fixture.content_sha256 !== catalogDocument.contentSha256 ||
        (catalogDocument.parseSha256 !== null &&
          fixture.parse_sha256 !== catalogDocument.parseSha256)
      ) {
        fail(
          "CATALOG_UNVERIFIED",
          "C10 document does not match the frozen C11 corpus.",
        );
      }
      if (
        catalogDocument.state === "PUBLISHED" &&
        !sameJson(
          catalogDocument.metadata,
          publicationFromFixture(fixture),
        )
      ) {
        fail(
          "CATALOG_UNVERIFIED",
          "C10 publication metadata differs from the frozen corpus.",
        );
      }
      if (
        catalogDocument.state !== "PUBLISHED" &&
        !NON_RETRIEVABLE_STATES.has(catalogDocument.state)
      ) {
        fail("CATALOG_UNVERIFIED", "C10 state is unsupported.");
      }
      const nodesById = new Map(
        (catalogDocument.nodes ?? []).map((node) => [node.nodeId, node]),
      );
      const nodesByOrdinal = new Map(
        (catalogDocument.nodes ?? []).map((node) => [node.ordinal, node]),
      );
      const chunks = [];
      if (catalogDocument.state === "PUBLISHED") {
        for (const frozenChunk of fixture.chunks) {
          const node = nodesByOrdinal.get(frozenChunk.ordinal);
          if (
            node?.nodeType !== "CHUNK" ||
            node.textSha256 !== frozenChunk.text_sha256 ||
            node.sourceSha256 !== fixture.content_sha256 ||
            node.authorityStatus !== "CANDIDATE" ||
            node.availabilityState !== "PUBLISHED"
          ) {
            fail(
              "CATALOG_UNVERIFIED",
              "C10 published Chunk differs from the frozen corpus.",
            );
          }
          const chain = chainFor(node, nodesById);
          chunks.push(
            Object.freeze({
              chunkId: node.nodeId,
              ordinal: node.ordinal,
              text: frozenChunk.text,
              textSha256: frozenChunk.text_sha256,
              sourceSha256: node.sourceSha256,
              embedding: c11DeterministicEmbedding(
                frozenChunk.text,
                document.embedding_dimensions,
              ),
              originalNodeId: chain.original.nodeId,
              pageNodeId: chain.page.nodeId,
              sectionNodeId: chain.section?.nodeId ?? null,
              tableNodeId: chain.table?.nodeId ?? null,
              location: clone(node.location),
            }),
          );
        }
      }
      return Object.freeze({
        tenantId: catalogDocument.tenantId,
        tenantKind: "SYNTHETIC",
        documentId: catalogDocument.documentId,
        documentVersion: catalogDocument.documentVersion,
        catalogRevision: catalogDocument.revision,
        state: catalogDocument.state,
        contentSha256: catalogDocument.contentSha256,
        parseSha256: catalogDocument.parseSha256,
        metadata: clone(catalogDocument.metadata),
        chunks: Object.freeze(chunks),
      });
    },
  });
}

function documentKey(tenantId, documentId, documentVersion) {
  return `${tenantId}\u0000${documentId}\u0000${documentVersion}`;
}

function receiptKey(tenantId, idempotencyKey) {
  return `${tenantId}\u0000${idempotencyKey}`;
}

function aclAllows(acl, principalRefs) {
  const allowed = new Set(acl?.readPrincipalRefs ?? []);
  return principalRefs.some((reference) => allowed.has(reference));
}

function validateTrustedFilter(filter) {
  const stable = filter && typeof filter === "object"
    ? { ...filter }
    : null;
  if (stable) delete stable.filterHash;
  if (
    filter?.trustSource !== "C11_SERVER_CONSTRUCTED_FILTER" ||
    !SYNTHETIC_TENANT_ID.test(filter?.tenantId ?? "") ||
    !PRINCIPAL_ID.test(filter?.humanPrincipalId ?? "") ||
    !Array.isArray(filter?.principalRefs) ||
    filter.principalRefs.length === 0 ||
    filter.allowedState !== "PUBLISHED" ||
    !SHA256.test(filter?.principalScopeHash ?? "") ||
    !SHA256.test(filter?.filterHash ?? "") ||
    c11Sha256(filter.principalRefs) !== filter.principalScopeHash ||
    c11Sha256(stable) !== filter.filterHash
  ) {
    fail("UNTRUSTED_FILTER", "C11 retrieval filter is not server trusted.");
  }
  instant(filter.asOf, "filter.asOf");
}

function projectionNext(current, command, tenantEpoch) {
  if (
    command.state !== "PUBLISHED" &&
    !NON_RETRIEVABLE_STATES.has(command.state)
  ) {
    fail("INVALID_STATE", "C11 projection state is invalid.");
  }
  if (current) {
    if (
      current.projectionVersion !== command.expectedProjectionVersion ||
      command.catalogRevision <= current.catalogRevision
    ) {
      fail("VERSION_CONFLICT", "C11 projection revision is stale.");
    }
  } else if (command.expectedProjectionVersion !== 0) {
    fail("VERSION_CONFLICT", "Initial C11 projection version must be zero.");
  }
  if (
    command.state === "PUBLISHED" &&
    (!command.metadata || command.chunks.length === 0)
  ) {
    fail("CATALOG_UNVERIFIED", "Published projection needs catalog Chunks.");
  }
  if (command.state !== "PUBLISHED" && command.chunks.length !== 0) {
    fail(
      "PRE_FILTER_VIOLATION",
      "Non-published material cannot enter the C11 index.",
    );
  }
  return Object.freeze({
    tenantId: command.tenantId,
    tenantKind: "SYNTHETIC",
    documentId: command.documentId,
    documentVersion: command.documentVersion,
    projectionVersion: (current?.projectionVersion ?? 0) + 1,
    catalogRevision: command.catalogRevision,
    state: command.state,
    contentSha256: command.contentSha256,
    parseSha256: command.parseSha256,
    validFrom: command.metadata?.validFrom ?? null,
    validUntil: command.metadata?.validUntil ?? null,
    classification: command.metadata?.classification ?? null,
    acl: clone(command.metadata?.acl ?? null),
    indexEpoch: tenantEpoch,
    authorizationEvidence: clone(command.authorizationEvidence),
    updatedAt: command.at,
  });
}

export function createMemoryPermissionAwareRagStore({ snapshot } = {}) {
  const projections = new Map(snapshot?.projections ?? []);
  const chunks = new Map(snapshot?.chunks ?? []);
  const receipts = new Map(snapshot?.receipts ?? []);
  const caches = new Map(snapshot?.caches ?? []);
  const tenantEpochs = new Map(snapshot?.tenantEpochs ?? []);
  const audits = [...(snapshot?.audits ?? [])];
  let queue = Promise.resolve();

  async function serialized(operation) {
    const result = queue.then(operation);
    queue = result.catch(() => undefined);
    return result;
  }

  return Object.freeze({
    async applyProjection(scope, envelope) {
      validateScope(scope);
      return serialized(async () => {
        const receipt = receipts.get(
          receiptKey(scope.tenantId, envelope.idempotencyKey),
        );
        if (receipt) {
          if (receipt.requestHash !== envelope.requestHash) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "Projection idempotency key was reused.",
            );
          }
          return { ...clone(receipt.result), replayed: true };
        }
        const key = documentKey(
          scope.tenantId,
          envelope.command.documentId,
          envelope.command.documentVersion,
        );
        const current = projections.get(key) ?? null;
        const nextEpoch = (tenantEpochs.get(scope.tenantId) ?? 0) + 1;
        const projection = projectionNext(
          current,
          envelope.command,
          nextEpoch,
        );
        projections.set(key, clone(projection));
        tenantEpochs.set(scope.tenantId, nextEpoch);
        for (const [chunkKey, chunk] of chunks) {
          if (
            chunk.tenantId === scope.tenantId &&
            chunk.documentId === projection.documentId &&
            chunk.documentVersion === projection.documentVersion
          ) {
            chunks.set(chunkKey, {
              ...chunk,
              active: false,
              state: projection.state,
              indexEpoch: nextEpoch,
            });
          }
        }
        if (projection.state === "PUBLISHED") {
          for (const chunk of envelope.command.chunks) {
            chunks.set(
              documentKey(
                scope.tenantId,
                projection.documentId,
                `${projection.documentVersion}\u0000${chunk.chunkId}`,
              ),
              Object.freeze({
                tenantId: scope.tenantId,
                documentId: projection.documentId,
                documentVersion: projection.documentVersion,
                catalogRevision: projection.catalogRevision,
                state: "PUBLISHED",
                active: true,
                indexEpoch: nextEpoch,
                ...clone(chunk),
              }),
            );
          }
        }
        let invalidatedCacheCount = 0;
        for (const [cacheKey, cache] of caches) {
          if (cache.tenantId === scope.tenantId) {
            invalidatedCacheCount += 1;
            caches.delete(cacheKey);
          }
        }
        const result = Object.freeze({
          replayed: false,
          projection: clone(projection),
          activeChunkCount:
            projection.state === "PUBLISHED"
              ? envelope.command.chunks.length
              : 0,
          invalidatedCacheCount,
        });
        receipts.set(receiptKey(scope.tenantId, envelope.idempotencyKey), {
          requestHash: envelope.requestHash,
          result: clone(result),
        });
        return result;
      });
    },
    async search(scope, filter, input) {
      validateScope(scope);
      validateTrustedFilter(filter);
      if (scope.tenantId !== filter.tenantId) {
        fail("TENANT_SCOPE_VIOLATION", "Search filter crossed Tenant.");
      }
      const candidates = [];
      for (const projection of projections.values()) {
        if (
          projection.tenantId !== filter.tenantId ||
          projection.state !== "PUBLISHED" ||
          Date.parse(projection.validFrom) > Date.parse(filter.asOf) ||
          Date.parse(filter.asOf) >= Date.parse(projection.validUntil) ||
          !aclAllows(projection.acl, filter.principalRefs)
        ) {
          continue;
        }
        for (const chunk of chunks.values()) {
          if (
            chunk.tenantId !== projection.tenantId ||
            chunk.documentId !== projection.documentId ||
            chunk.documentVersion !== projection.documentVersion ||
            chunk.active !== true ||
            chunk.state !== "PUBLISHED"
          ) {
            continue;
          }
          const lexical = lexicalScore(input.query, chunk.text);
          if (lexical <= 0) continue;
          const vector = Math.max(
            0,
            cosine(input.embedding, chunk.embedding),
          );
          candidates.push({
            ...clone(chunk),
            projection: clone(projection),
            lexicalScore: lexical,
            vectorScore: vector,
            score: 0.6 * lexical + 0.4 * vector,
          });
        }
      }
      return Object.freeze(
        candidates
          .sort(
            (left, right) =>
              right.score - left.score ||
              left.documentId.localeCompare(right.documentId) ||
              left.ordinal - right.ordinal,
          )
          .slice(0, input.limit),
      );
    },
    async readCache(scope, filter, cacheKey) {
      validateScope(scope);
      validateTrustedFilter(filter);
      const cache = caches.get(`${scope.tenantId}\u0000${cacheKey}`);
      const epoch = tenantEpochs.get(scope.tenantId) ?? 0;
      if (
        !cache ||
        cache.principalScopeHash !== filter.principalScopeHash ||
        cache.asOf !== filter.asOf ||
        cache.indexEpoch !== epoch
      ) {
        return null;
      }
      return clone(cache.candidates);
    },
    async writeCache(scope, filter, cacheKey, candidates) {
      validateScope(scope);
      validateTrustedFilter(filter);
      caches.set(`${scope.tenantId}\u0000${cacheKey}`, {
        tenantId: scope.tenantId,
        principalScopeHash: filter.principalScopeHash,
        asOf: filter.asOf,
        indexEpoch: tenantEpochs.get(scope.tenantId) ?? 0,
        documentRefs: [
          ...new Map(
            candidates.map((candidate) => {
              const value = {
                documentId: candidate.documentId,
                documentVersion: candidate.documentVersion,
                catalogRevision: candidate.catalogRevision,
              };
              return [canonicalize(value), value];
            }),
          ).values(),
        ],
        candidates: clone(candidates),
      });
    },
    async recordAudit(scope, record) {
      validateScope(scope);
      if (
        "query" in record ||
        "text" in record ||
        "context" in record ||
        "answer" in record
      ) {
        fail("LOG_BODY_FORBIDDEN", "C11 audit cannot store body text.");
      }
      audits.push(Object.freeze(clone(record)));
    },
    exportSnapshot() {
      return clone({
        projections: [...projections.entries()],
        chunks: [...chunks.entries()],
        receipts: [...receipts.entries()],
        caches: [...caches.entries()],
        tenantEpochs: [...tenantEpochs.entries()],
        audits,
      });
    },
    inspect() {
      return clone({
        projections: [...projections.values()],
        chunks: [...chunks.values()],
        caches: [...caches.values()],
        audits,
      });
    },
  });
}

async function authorize(c06Authorizer, context, resourceId, surface) {
  let evidence;
  try {
    evidence = await c06Authorizer.enforce(
      context.c06ServerContext,
      {
        ...context.authorizationRequest,
        resourceId,
      },
      { surface },
    );
  } catch (error) {
    if (error?.code === "ACCESS_DENIED") {
      fail("ACCESS_DENIED", "C06 denied the C11 operation.");
    }
    fail("AUTHORIZATION_UNAVAILABLE", "C06 authorization is unavailable.");
  }
  validateAuthorizationEvidence(evidence, {
    tenantId: context.tenantScope.tenantId,
    surface,
    resourceId,
  });
  return evidence;
}

function stableEnvelope(command, idempotencyKey) {
  const stable = { ...command };
  delete stable.at;
  delete stable.authorizationEvidence;
  return Object.freeze({
    idempotencyKey,
    requestHash: c11Sha256(stable),
    command,
  });
}

function evidenceRef(candidate, filter, authorizationEvidence) {
  const value = {
    type: "KnowledgeEvidenceRef",
    tenantId: candidate.tenantId,
    documentId: candidate.documentId,
    documentVersion: candidate.documentVersion,
    catalogRevision: candidate.catalogRevision,
    contentSha256: candidate.projection.contentSha256,
    original: {
      nodeId: candidate.originalNodeId,
      contentSha256: candidate.sourceSha256,
    },
    page: {
      nodeId: candidate.pageNodeId,
      page: candidate.location.page,
    },
    section:
      candidate.sectionNodeId === null
        ? null
        : { nodeId: candidate.sectionNodeId },
    table:
      candidate.tableNodeId === null
        ? null
        : { nodeId: candidate.tableNodeId },
    chunk: {
      nodeId: candidate.chunkId,
      ordinal: candidate.ordinal,
      textSha256: candidate.textSha256,
      location: clone(candidate.location),
    },
    asOf: filter.asOf,
    authorization: {
      decisionId: authorizationEvidence.decisionId,
      evidenceRef: authorizationEvidence.evidenceRef,
      policyVersion: authorizationEvidence.policyVersion,
      humanPrincipalId: authorizationEvidence.humanPrincipalId,
      principalScopeHash: filter.principalScopeHash,
    },
  };
  return Object.freeze({
    evidenceId: `evr_${c11Sha256(value).slice(7, 39)}`,
    ...value,
  });
}

export function createPermissionAwareRag({
  store,
  catalogReader,
  c06Authorizer,
  principalResolver,
  benchmark,
  clock = () => new Date().toISOString(),
}) {
  if (
    typeof store?.applyProjection !== "function" ||
    typeof store?.search !== "function" ||
    typeof store?.readCache !== "function" ||
    typeof store?.writeCache !== "function" ||
    typeof store?.recordAudit !== "function" ||
    typeof catalogReader?.readCurrent !== "function" ||
    typeof c06Authorizer?.enforce !== "function" ||
    typeof principalResolver?.resolve !== "function" ||
    typeof benchmark?.projectCatalogDocument !== "function" ||
    typeof benchmark?.searchResourceId !== "string" ||
    !Number.isSafeInteger(benchmark?.embeddingDimensions) ||
    typeof clock !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C11 dependencies are incomplete.");
  }

  return Object.freeze({
    async synchronize(context, command) {
      validateContext(context);
      exactKeys(
        command,
        [
          "idempotencyKey",
          "documentId",
          "documentVersion",
          "expectedProjectionVersion",
        ],
        "C11 projection command",
      );
      nonEmpty(command.idempotencyKey, "idempotencyKey", 128);
      if (!DOCUMENT_ID.test(command.documentId ?? "")) {
        fail("INVALID_INPUT", "documentId is invalid.");
      }
      positiveInteger(command.documentVersion, "documentVersion");
      positiveInteger(
        command.expectedProjectionVersion,
        "expectedProjectionVersion",
        { allowZero: true },
      );
      const authorizationEvidence = await authorize(
        c06Authorizer,
        context,
        command.documentId,
        PROJECT_SURFACE,
      );
      const catalogDocument = await catalogReader.readCurrent(
        context.tenantScope,
        {
          documentId: command.documentId,
          documentVersion: command.documentVersion,
        },
      );
      if (
        !catalogDocument ||
        catalogDocument.tenantId !== context.tenantScope.tenantId
      ) {
        fail("CATALOG_UNVERIFIED", "C10 catalog document is unavailable.");
      }
      const projection = benchmark.projectCatalogDocument(catalogDocument);
      const normalized = Object.freeze({
        type: "PROJECT_C10_DOCUMENT",
        tenantId: context.tenantScope.tenantId,
        documentId: projection.documentId,
        documentVersion: projection.documentVersion,
        expectedProjectionVersion: command.expectedProjectionVersion,
        catalogRevision: projection.catalogRevision,
        state: projection.state,
        contentSha256: projection.contentSha256,
        parseSha256: projection.parseSha256,
        metadata: projection.metadata,
        chunks: projection.chunks,
        authorizationEvidence,
        at: instant(clock(), "clock"),
      });
      return store.applyProjection(
        context.tenantScope,
        stableEnvelope(normalized, command.idempotencyKey),
      );
    },
    async search(context, request) {
      validateContext(context);
      exactKeys(
        request,
        ["requestId", "query", "asOf", "limit"],
        "C11 search request",
      );
      nonEmpty(request.requestId, "requestId", 128);
      nonEmpty(request.query, "query", 1000);
      instant(request.asOf, "asOf");
      positiveInteger(request.limit, "limit");
      if (request.limit > 20) {
        fail("INVALID_INPUT", "limit exceeds the C11 P1 boundary.");
      }
      const authorizationEvidence = await authorize(
        c06Authorizer,
        context,
        benchmark.searchResourceId,
        SEARCH_SURFACE,
      );
      let principal;
      try {
        principal = await principalResolver.resolve({
          tenantScope: context.tenantScope,
          authorizationEvidence,
        });
      } catch {
        fail(
          "PRINCIPAL_UNVERIFIED",
          "Server-side Principal resolution failed.",
        );
      }
      if (
        principal?.trustSource !==
          "C06_HUMAN_AND_SERVER_GROUP_RESOLUTION" ||
        principal?.tenantId !== context.tenantScope.tenantId ||
        principal?.humanPrincipalId !==
          authorizationEvidence.humanPrincipalId ||
        !Number.isSafeInteger(principal?.humanSecurityEpoch) ||
        principal.humanSecurityEpoch < 1 ||
        principal.humanSecurityEpoch !==
          authorizationEvidence.humanSecurityEpoch ||
        !Array.isArray(principal?.principalRefs) ||
        principal.principalRefs.length === 0 ||
        !SHA256.test(principal?.principalScopeHash ?? "")
      ) {
        fail(
          "PRINCIPAL_UNVERIFIED",
          "Server-side Principal binding is invalid.",
        );
      }
      const principalRefs = [
        ...new Set(principal.principalRefs),
      ].sort();
      if (
        c11Sha256(principalRefs) !== principal.principalScopeHash
      ) {
        fail(
          "PRINCIPAL_UNVERIFIED",
          "Server-side Principal scope hash is invalid.",
        );
      }
      const filterBase = {
        trustSource: "C11_SERVER_CONSTRUCTED_FILTER",
        tenantId: context.tenantScope.tenantId,
        humanPrincipalId: principal.humanPrincipalId,
        humanSecurityEpoch: principal.humanSecurityEpoch,
        principalRefs,
        principalScopeHash: principal.principalScopeHash,
        allowedState: "PUBLISHED",
        asOf: request.asOf,
      };
      const filter = Object.freeze({
        ...filterBase,
        filterHash: c11Sha256(filterBase),
      });
      validateTrustedFilter(filter);
      const queryHash = c11Sha256(request.query);
      const cacheKey = c11Sha256({
        queryHash,
        filterHash: filter.filterHash,
        limit: request.limit,
        embeddingModel: benchmark.embeddingModel,
      });
      let candidates = await store.readCache(
        context.tenantScope,
        filter,
        cacheKey,
      );
      const cacheHit = candidates !== null;
      if (!candidates) {
        candidates = await store.search(context.tenantScope, filter, {
          query: request.query,
          queryHash,
          embedding: c11DeterministicEmbedding(
            request.query,
            benchmark.embeddingDimensions,
          ),
          embeddingModel: benchmark.embeddingModel,
          limit: request.limit,
        });
        await store.writeCache(
          context.tenantScope,
          filter,
          cacheKey,
          candidates,
        );
      }
      const qualified = candidates.filter(
        (candidate) =>
          candidate.score >= benchmark.minimumScore &&
          candidate.lexicalScore > 0,
      );
      const evidence = qualified.map((candidate) =>
        evidenceRef(candidate, filter, authorizationEvidence),
      );
      const answerable =
        evidence.length >= benchmark.minimumEvidenceCount;
      const response = answerable
        ? Object.freeze({
            requestId: request.requestId,
            status: "ANSWERABLE",
            reasonCode: "SUFFICIENT_AUTHORIZED_EVIDENCE",
            answer: Object.freeze({
              kind: "EXTRACTIVE_DRAFT",
              text: qualified[0].text,
              citations: Object.freeze(
                evidence.map(({ evidenceId }) => evidenceId),
              ),
            }),
            modelContext: Object.freeze(
              qualified.map((candidate, index) =>
                Object.freeze({
                  text: candidate.text,
                  score: Number(candidate.score.toFixed(8)),
                  evidenceRef: evidence[index],
                }),
              ),
            ),
            evidence: Object.freeze(evidence),
            cacheHit,
          })
        : Object.freeze({
            requestId: request.requestId,
            status: "REFUSED",
            reasonCode: "INSUFFICIENT_AUTHORIZED_EVIDENCE",
            answer: null,
            modelContext: Object.freeze([]),
            evidence: Object.freeze([]),
            cacheHit,
          });
      await store.recordAudit(context.tenantScope, {
        auditVersion: "c11-query-audit-v1",
        requestIdHash: c11Sha256(request.requestId),
        queryHash,
        filterHash: filter.filterHash,
        principalScopeHash: filter.principalScopeHash,
        authorizationDecisionId:
          authorizationEvidence.decisionId,
        candidateCount: candidates.length,
        evidenceCount: response.evidence.length,
        resultStatus: response.status,
        reasonCode: response.reasonCode,
        evidenceIdHashes: response.evidence.map(({ evidenceId }) =>
          c11Sha256(evidenceId),
        ),
        cacheHit,
        recordedAt: instant(clock(), "clock"),
      });
      return response;
    },
  });
}

export function createC11SyntheticPrincipalResolver({ benchmark }) {
  if (typeof benchmark?.resolvePrincipal !== "function") {
    fail("INVALID_CONFIGURATION", "C11 benchmark resolver is required.");
  }
  return Object.freeze({
    async resolve(input) {
      return benchmark.resolvePrincipal(input);
    },
  });
}

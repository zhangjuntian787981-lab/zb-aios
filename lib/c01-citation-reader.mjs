import {
  c11Sha256,
} from "./permission-aware-rag.mjs";

const SYNTHETIC_TENANT =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRINCIPAL =
  /^prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const EVIDENCE_ID = /^evr_[0-9a-f]{32}$/;
const NODE_ID = /^knn_[0-9a-f]{32}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const DOCUMENT_ID = /^[a-z][a-z0-9_-]{0,127}$/;
const REASON_CODES = new Set([
  "EVIDENCE_NOT_FOUND",
  "EVIDENCE_MISMATCH",
  "SOURCE_NOT_CURRENT",
  "ACCESS_DENIED",
  "DEPENDENCY_UNAVAILABLE",
]);

export class C01CitationReaderError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C01CitationReaderError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C01CitationReaderError(code, message);
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    Object.keys(value).every((key) => keys.includes(key))
  );
}

function canonicalInstant(value) {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    new Date(value).toISOString() === value
  );
}

function evidenceReference(evidence, resourceId) {
  return EVIDENCE_ID.test(evidence?.evidenceId ?? "")
    ? `evidence://c11/${evidence.evidenceId}`
    : `evidence://c11/unavailable/${resourceId}`;
}

function unavailable(scope, command, evidence, reasonCode, revision = 1) {
  if (!REASON_CODES.has(reasonCode)) {
    fail("INVALID_CONFIGURATION", "C01 citation reason is invalid.");
  }
  const suffix = reasonCode.toLowerCase().replaceAll("_", "-");
  const item = Object.freeze({
    evidenceRef: evidenceReference(evidence, command.resourceId),
    resourceRef: `synthetic://c01/citation-unavailable/${suffix}`,
    locatorRef:
      `synthetic://c01/citation-unavailable/${suffix}/locator`,
    titleRef:
      `synthetic://c01/citation-unavailable/${suffix}/title`,
    status: "UNAVAILABLE",
    reasonCode,
    ownerPrincipalId: scope.humanPrincipalId,
  });
  return Object.freeze({
    schemaVersion: "c01-portal-view.v1",
    tenantId: scope.tenantId,
    operationId: command.operationId,
    resourceId: command.resourceId,
    resourceVersion:
      Number.isSafeInteger(revision) && revision > 0 ? revision : 1,
    items: Object.freeze([item]),
    evidenceRefs: Object.freeze([item.evidenceRef]),
  });
}

function evidenceShapeIsValid(evidence) {
  if (
    !exactKeys(evidence, [
      "evidenceId",
      "type",
      "tenantId",
      "documentId",
      "documentVersion",
      "catalogRevision",
      "contentSha256",
      "original",
      "page",
      "section",
      "table",
      "chunk",
      "asOf",
      "filterHash",
      "authorization",
    ]) ||
    evidence.type !== "KnowledgeEvidenceRef" ||
    !EVIDENCE_ID.test(evidence.evidenceId ?? "") ||
    !SYNTHETIC_TENANT.test(evidence.tenantId ?? "") ||
    !DOCUMENT_ID.test(evidence.documentId ?? "") ||
    !Number.isSafeInteger(evidence.documentVersion) ||
    evidence.documentVersion < 1 ||
    !Number.isSafeInteger(evidence.catalogRevision) ||
    evidence.catalogRevision < 1 ||
    !SHA256.test(evidence.contentSha256 ?? "") ||
    !canonicalInstant(evidence.asOf) ||
    !SHA256.test(evidence.filterHash ?? "") ||
    !exactKeys(evidence.original, ["nodeId", "contentSha256"]) ||
    !NODE_ID.test(evidence.original.nodeId ?? "") ||
    !SHA256.test(evidence.original.contentSha256 ?? "") ||
    !exactKeys(evidence.page, ["nodeId", "page"]) ||
    !NODE_ID.test(evidence.page.nodeId ?? "") ||
    !Number.isSafeInteger(evidence.page.page) ||
    evidence.page.page < 1 ||
    (
      evidence.section !== null &&
      (
        !exactKeys(evidence.section, ["nodeId"]) ||
        !NODE_ID.test(evidence.section.nodeId ?? "")
      )
    ) ||
    (
      evidence.table !== null &&
      (
        !exactKeys(evidence.table, ["nodeId"]) ||
        !NODE_ID.test(evidence.table.nodeId ?? "")
      )
    ) ||
    !exactKeys(evidence.chunk, [
      "nodeId",
      "ordinal",
      "textSha256",
      "location",
    ]) ||
    !NODE_ID.test(evidence.chunk.nodeId ?? "") ||
    !Number.isSafeInteger(evidence.chunk.ordinal) ||
    evidence.chunk.ordinal < 0 ||
    !SHA256.test(evidence.chunk.textSha256 ?? "") ||
    !evidence.chunk.location ||
    typeof evidence.chunk.location !== "object" ||
    Array.isArray(evidence.chunk.location) ||
    !exactKeys(evidence.authorization, [
      "decisionId",
      "evidenceRef",
      "policyVersion",
      "humanPrincipalId",
      "principalScopeHash",
    ]) ||
    typeof evidence.authorization.decisionId !== "string" ||
    evidence.authorization.decisionId.length < 1 ||
    !/^evidence:\/\//.test(
      evidence.authorization.evidenceRef ?? "",
    ) ||
    typeof evidence.authorization.policyVersion !== "string" ||
    evidence.authorization.policyVersion.length < 1 ||
    !PRINCIPAL.test(
      evidence.authorization.humanPrincipalId ?? "",
    ) ||
    !SHA256.test(
      evidence.authorization.principalScopeHash ?? "",
    )
  ) {
    return false;
  }
  const value = structuredClone(evidence);
  delete value.evidenceId;
  try {
    return (
      evidence.evidenceId ===
      `evr_${c11Sha256(value).slice(7, 39)}`
    );
  } catch {
    return false;
  }
}

function principalIsCurrent(scope, evidence, principal) {
  if (
    principal?.trustSource !==
      "C06_HUMAN_AND_SERVER_GROUP_RESOLUTION" ||
    principal.tenantId !== scope.tenantId ||
    principal.humanPrincipalId !== scope.humanPrincipalId ||
    !Array.isArray(principal.principalRefs) ||
    principal.principalRefs.length < 1 ||
    !principal.principalRefs.includes(
      `human:${scope.humanPrincipalId}`,
    ) ||
    !SHA256.test(principal.principalScopeHash ?? "")
  ) {
    return false;
  }
  return (
    evidence.authorization.humanPrincipalId ===
      scope.humanPrincipalId &&
    evidence.authorization.principalScopeHash ===
      principal.principalScopeHash
  );
}

function sourceChainMatches(document, evidence) {
  if (
    document.tenantId !== evidence.tenantId ||
    document.documentId !== evidence.documentId ||
    document.documentVersion !== evidence.documentVersion ||
    document.revision !== evidence.catalogRevision ||
    document.contentSha256 !== evidence.contentSha256 ||
    !Array.isArray(document.nodes)
  ) {
    return false;
  }
  const nodes = new Map(
    document.nodes.map((node) => [node.nodeId, node]),
  );
  const chain = [];
  const seen = new Set();
  let current = nodes.get(evidence.chunk.nodeId);
  while (current) {
    if (seen.has(current.nodeId)) return false;
    seen.add(current.nodeId);
    chain.push(current);
    current = current.parentNodeId === null
      ? null
      : nodes.get(current.parentNodeId);
  }
  const byType = new Map(
    chain.map((node) => [node.nodeType, node]),
  );
  const original = byType.get("ORIGINAL");
  const page = byType.get("PAGE");
  const section = byType.get("SECTION") ?? null;
  const table = byType.get("TABLE") ?? null;
  const chunk = byType.get("CHUNK");
  const expectedNodes = [original, page, section, table, chunk]
    .filter(Boolean);
  if (
    !original ||
    !page ||
    !chunk ||
    expectedNodes.some(
      (node) =>
        node.availabilityState !== "PUBLISHED" ||
        node.deletedAt !== null ||
        node.sourceSha256 !== document.contentSha256,
    )
  ) {
    return false;
  }
  return (
    original.nodeId === evidence.original.nodeId &&
    original.textSha256 === evidence.original.contentSha256 &&
    evidence.original.contentSha256 === document.contentSha256 &&
    page.nodeId === evidence.page.nodeId &&
    page.location?.page === evidence.page.page &&
    (
      evidence.section === null
        ? section === null
        : section?.nodeId === evidence.section.nodeId
    ) &&
    (
      evidence.table === null
        ? table === null
        : table?.nodeId === evidence.table.nodeId
    ) &&
    chunk.nodeId === evidence.chunk.nodeId &&
    chunk.ordinal === evidence.chunk.ordinal &&
    chunk.textSha256 === evidence.chunk.textSha256 &&
    c11Sha256(chunk.location) ===
      c11Sha256(evidence.chunk.location)
  );
}

function sourceIsCurrent(document, at) {
  return (
    document?.state === "PUBLISHED" &&
    document.metadata &&
    Date.parse(document.metadata.validFrom) <= Date.parse(at) &&
    Date.parse(at) < Date.parse(document.metadata.validUntil)
  );
}

function aclAllows(document, principal) {
  const allowed = new Set(
    document.metadata?.acl?.readPrincipalRefs ?? [],
  );
  return principal.principalRefs.some((reference) =>
    allowed.has(reference),
  );
}

export function createC01CitationReader({
  evidenceReader,
  catalogReader,
  principalReader,
  clock = () => new Date().toISOString(),
}) {
  if (
    typeof evidenceReader?.readCurrent !== "function" ||
    typeof catalogReader?.readCurrent !== "function" ||
    typeof principalReader?.resolveCurrent !== "function" ||
    typeof clock !== "function"
  ) {
    fail(
      "INVALID_CONFIGURATION",
      "C01 citation dependencies are incomplete.",
    );
  }

  return Object.freeze({
    async read(scope, command) {
      if (
        !SYNTHETIC_TENANT.test(scope?.tenantId ?? "") ||
        !PRINCIPAL.test(scope?.humanPrincipalId ?? "") ||
        command?.operationId !== "CITATION_VIEW" ||
        typeof command?.resourceId !== "string"
      ) {
        fail("INVALID_INPUT", "C01 citation request is invalid.");
      }
      let evidence;
      try {
        evidence = await evidenceReader.readCurrent(scope, command);
      } catch {
        return unavailable(
          scope,
          command,
          null,
          "DEPENDENCY_UNAVAILABLE",
        );
      }
      if (evidence === null || evidence === undefined) {
        return unavailable(
          scope,
          command,
          null,
          "EVIDENCE_NOT_FOUND",
        );
      }
      if (
        !evidenceShapeIsValid(evidence) ||
        evidence.tenantId !== scope.tenantId
      ) {
        return unavailable(
          scope,
          command,
          evidence,
          "EVIDENCE_MISMATCH",
          evidence.catalogRevision,
        );
      }
      let principal;
      try {
        principal = await principalReader.resolveCurrent(scope);
      } catch {
        return unavailable(
          scope,
          command,
          evidence,
          "ACCESS_DENIED",
          evidence.catalogRevision,
        );
      }
      if (!principalIsCurrent(scope, evidence, principal)) {
        return unavailable(
          scope,
          command,
          evidence,
          "ACCESS_DENIED",
          evidence.catalogRevision,
        );
      }
      let document;
      try {
        document = await catalogReader.readCurrent(scope, {
          documentId: evidence.documentId,
          documentVersion: evidence.documentVersion,
        });
      } catch {
        return unavailable(
          scope,
          command,
          evidence,
          "DEPENDENCY_UNAVAILABLE",
          evidence.catalogRevision,
        );
      }
      if (!sourceIsCurrent(document, clock())) {
        return unavailable(
          scope,
          command,
          evidence,
          "SOURCE_NOT_CURRENT",
          document?.revision ?? evidence.catalogRevision,
        );
      }
      if (!aclAllows(document, principal)) {
        return unavailable(
          scope,
          command,
          evidence,
          "ACCESS_DENIED",
          document.revision,
        );
      }
      if (
        !sourceChainMatches(document, evidence) ||
        Date.parse(document.metadata.validFrom) >
          Date.parse(evidence.asOf) ||
        Date.parse(evidence.asOf) >=
          Date.parse(document.metadata.validUntil)
      ) {
        return unavailable(
          scope,
          command,
          evidence,
          "EVIDENCE_MISMATCH",
          document.revision,
        );
      }
      const item = Object.freeze({
        evidenceRef: `evidence://c11/${evidence.evidenceId}`,
        resourceRef:
          `synthetic://c10/document/${scope.tenantId}/` +
          `${evidence.documentId}/${evidence.documentVersion}/` +
          `${document.revision}`,
        locatorRef:
          `synthetic://c10/node/${evidence.chunk.nodeId}`,
        titleRef:
          `synthetic://c10/title/${evidence.documentId}/` +
          `${evidence.documentVersion}`,
        status: "AVAILABLE",
        reasonCode: "CURRENT_AUTHORIZED_SOURCE",
        ownerPrincipalId: scope.humanPrincipalId,
      });
      return Object.freeze({
        schemaVersion: "c01-portal-view.v1",
        tenantId: scope.tenantId,
        operationId: command.operationId,
        resourceId: command.resourceId,
        resourceVersion: document.revision,
        items: Object.freeze([item]),
        evidenceRefs: Object.freeze([item.evidenceRef]),
      });
    },
  });
}

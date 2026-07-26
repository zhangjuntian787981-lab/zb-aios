import { createHash } from "node:crypto";

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const PRINCIPAL_ID = new RegExp(`^prn_${UUID_V7}$`);
const DELEGATION_ID = new RegExp(`^dlg_${UUID_V7}$`);
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const DOCUMENT_ID = /^[a-z][a-z0-9_-]{0,127}$/;
const REFERENCE = /^(?:evidence|fixture|policy|profile|synthetic|test):\/\/\S+$/;
const CLASSIFICATIONS = new Set([
  "PUBLIC",
  "INTERNAL",
  "CONFIDENTIAL",
  "RESTRICTED",
]);
const STATES = new Set([
  "QUARANTINED",
  "INSPECTED",
  "REJECTED",
  "PARSED_CANDIDATE",
  "PUBLISHED",
  "WITHDRAWN",
  "EXPIRED",
  "DELETED",
]);
const COMMANDS = new Set([
  "UPLOAD",
  "INSPECT",
  "PARSE",
  "PUBLISH",
  "WITHDRAW",
  "EXPIRE",
  "DELETE",
]);
const MUTATION_SURFACE = "MANAGE";
const READ_SURFACE = "READ";

export class KnowledgeCatalogError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "KnowledgeCatalogError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new KnowledgeCatalogError(code, message);
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
    fail("INVALID_INPUT", `${field} has unsupported fields.`);
  }
  if (required.some((key) => !keys.includes(key))) {
    fail("INVALID_INPUT", `${field} is incomplete.`);
  }
}

function nonEmptyString(value, field, maxLength = 256) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > maxLength
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function safePositiveInteger(value, field, { allowZero = false } = {}) {
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

export function c10Sha256(value) {
  const input =
    typeof value === "string" || value instanceof Uint8Array
      ? value
      : canonicalize(value);
  return `sha256:${createHash("sha256").update(input).digest("hex")}`;
}

function canonicalInstant(value, field) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
    new Date(value).toISOString() !== value
  ) {
    fail("INVALID_INPUT", `${field} must be a canonical UTC instant.`);
  }
  return value;
}

function reference(value, field) {
  nonEmptyString(value, field, 512);
  if (!REFERENCE.test(value)) {
    fail(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      `${field} must be a frozen P1 reference.`,
    );
  }
}

function validateTenantScope(scope) {
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
      "C10 requires a C07 verified Synthetic Tenant scope.",
    );
  }
  for (const field of [
    "correlationId",
    "decisionId",
    "evidenceRef",
    "policyVersion",
  ]) {
    nonEmptyString(scope[field], `scope.${field}`, 512);
  }
}

function validateContext(context) {
  exactKeys(
    context,
    ["tenantScope", "c06ServerContext", "authorizationRequest"],
    "C10 request context",
  );
  validateTenantScope(context.tenantScope);
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
      "C06 and C07 server contexts are not bound to one Synthetic Tenant.",
    );
  }
  exactKeys(
    context.authorizationRequest,
    ["sessionToken", "delegationId", "correlationId"],
    "authorization request",
  );
  nonEmptyString(
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
  nonEmptyString(
    context.authorizationRequest.correlationId,
    "authorizationRequest.correlationId",
    128,
  );
}

function fixtureBytes(fixture) {
  if (fixture.content_encoding === "UTF8_LITERAL") {
    nonEmptyString(fixture.content_utf8, "fixture.content_utf8", 100_000);
    return Buffer.from(fixture.content_utf8, "utf8");
  }
  if (fixture.content_encoding === "UTF8_REPEAT") {
    nonEmptyString(fixture.prefix_utf8, "fixture.prefix_utf8", 10_000);
    nonEmptyString(fixture.repeat_utf8, "fixture.repeat_utf8", 32);
    safePositiveInteger(fixture.repeat_count, "fixture.repeat_count");
    return Buffer.from(
      `${fixture.prefix_utf8}${fixture.repeat_utf8.repeat(
        fixture.repeat_count,
      )}`,
      "utf8",
    );
  }
  fail(
    "INVALID_BENCHMARK",
    "Synthetic fixture encoding is unsupported.",
  );
}

export function createC10SyntheticBenchmark(document) {
  if (
    document?.schema_version !== "1.0.0" ||
    document?.work_package_id !== "C10" ||
    document?.data_classification !== "SYNTHETIC_ONLY" ||
    document?.enterprise_connectors !== "C0_DISABLED" ||
    !Number.isSafeInteger(document?.max_file_bytes) ||
    document.max_file_bytes < 1 ||
    typeof document?.parser_version !== "string" ||
    !Array.isArray(document?.fixtures) ||
    document.fixtures.length < 5
  ) {
    fail("INVALID_BENCHMARK", "C10 synthetic benchmark is invalid.");
  }
  const fixtures = new Map();
  for (const fixture of document.fixtures) {
    reference(fixture.fixture_ref, "fixture.fixture_ref");
    if (!fixture.fixture_ref.startsWith("fixture://c10/")) {
      fail("INVALID_BENCHMARK", "Fixture is outside the C10 namespace.");
    }
    if (fixtures.has(fixture.fixture_ref)) {
      fail("INVALID_BENCHMARK", "Fixture references must be unique.");
    }
    nonEmptyString(fixture.filename, "fixture.filename", 255);
    nonEmptyString(
      fixture.declared_media_type,
      "fixture.declared_media_type",
      128,
    );
    if (!SHA256.test(fixture.content_sha256 ?? "")) {
      fail("INVALID_BENCHMARK", "Fixture SHA-256 is invalid.");
    }
    const content = fixtureBytes(fixture);
    if (
      content.byteLength !== fixture.content_size ||
      c10Sha256(content) !== fixture.content_sha256
    ) {
      fail("INVALID_BENCHMARK", "Fixture content does not match its hash.");
    }
    fixtures.set(
      fixture.fixture_ref,
      Object.freeze({
        fixture: Object.freeze(clone(fixture)),
        content,
      }),
    );
  }
  return Object.freeze({
    maxFileBytes: document.max_file_bytes,
    parserVersion: document.parser_version,
    resolve(fixtureRef) {
      const found = fixtures.get(fixtureRef);
      if (!found) {
        fail(
          "SYNTHETIC_BOUNDARY_VIOLATION",
          "Only the frozen C10 benchmark can be ingested before P3.",
        );
      }
      return Object.freeze({
        fixture: found.fixture,
        content: Buffer.from(found.content),
      });
    },
    refs: Object.freeze([...fixtures.keys()]),
  });
}

function extensionOf(filename) {
  const index = filename.lastIndexOf(".");
  return index < 0 ? "" : filename.slice(index).toLowerCase();
}

function detectMediaType(filename, content) {
  const extension = extensionOf(filename);
  if (
    extension === ".docm" ||
    (content[0] === 0x50 &&
      content[1] === 0x4b &&
      content.toString("utf8").includes("vbaProject.bin"))
  ) {
    return "application/vnd.ms-word.document.macroenabled.12";
  }
  if (extension === ".md") return "text/markdown";
  if (extension === ".csv") return "text/csv";
  if (extension === ".txt") return "text/plain";
  return "application/octet-stream";
}

export function inspectSyntheticDocument({
  filename,
  declaredMediaType,
  content,
  maxFileBytes,
}) {
  nonEmptyString(filename, "filename", 255);
  nonEmptyString(declaredMediaType, "declaredMediaType", 128);
  if (!(content instanceof Uint8Array)) {
    fail("INVALID_INPUT", "content must be bytes.");
  }
  safePositiveInteger(maxFileBytes, "maxFileBytes");
  const text = Buffer.from(content).toString("utf8");
  const detectedMediaType = detectMediaType(filename, content);
  const findings = [];
  if (content.byteLength > maxFileBytes) findings.push("FILE_TOO_LARGE");
  if (detectedMediaType !== declaredMediaType.toLowerCase()) {
    findings.push("FILE_TYPE_MISMATCH");
  }
  if (
    extensionOf(filename) === ".docm" ||
    text.includes("vbaProject.bin")
  ) {
    findings.push("MACRO_DETECTED");
  }
  if (text.includes("SYNTHETIC_VIRUS_MARKER")) {
    findings.push("VIRUS_MARKER");
  }
  if (
    /<!--[\s\S]{0,512}(?:AI_INSTRUCTION|SYSTEM_PROMPT)[\s\S]{0,512}-->/i.test(
      text,
    ) ||
    /[\u200b\u200c\u200d\u2060\u202a-\u202e]/u.test(text) ||
    /(?:display\s*:\s*none|color\s*:\s*white)[\s\S]{0,128}(?:prompt|instruction)/i.test(
      text,
    )
  ) {
    findings.push("HIDDEN_INSTRUCTION");
  }
  if (
    !["text/markdown", "text/csv", "text/plain"].includes(
      detectedMediaType,
    )
  ) {
    findings.push("UNSUPPORTED_FILE_TYPE");
  }
  return Object.freeze({
    scannerVersion: "c10-deterministic-inspector-v1",
    contentSize: content.byteLength,
    detectedMediaType,
    declaredMediaType: declaredMediaType.toLowerCase(),
    fileTypeMatched: detectedMediaType === declaredMediaType.toLowerCase(),
    sizeWithinLimit: content.byteLength <= maxFileBytes,
    macroDetected: findings.includes("MACRO_DETECTED"),
    antivirusStatus: findings.includes("VIRUS_MARKER")
      ? "INFECTED"
      : "CLEAN",
    hiddenInstructionRisk: findings.includes("HIDDEN_INSTRUCTION"),
    findings: Object.freeze(findings),
    outcome: findings.length === 0 ? "PASS" : "REJECT",
  });
}

function nodeId(documentId, documentVersion, kind, ordinal) {
  return `knn_${c10Sha256([
    documentId,
    documentVersion,
    kind,
    ordinal,
  ]).slice(7, 39)}`;
}

function textNode({
  documentId,
  documentVersion,
  kind,
  ordinal,
  parentNodeId,
  location,
  text,
  sourceSha256,
}) {
  return Object.freeze({
    nodeId: nodeId(documentId, documentVersion, kind, ordinal),
    nodeType: kind,
    parentNodeId,
    ordinal,
    location: Object.freeze(location),
    textSha256: c10Sha256(text),
    sourceSha256,
    authorityStatus: "CANDIDATE",
    availabilityState: "CANDIDATE",
    deletedAt: null,
  });
}

function markdownNodes({
  documentId,
  documentVersion,
  contentSha256,
  pages,
  rootId,
}) {
  const nodes = [];
  let ordinal = 1;
  pages.forEach((pageText, pageIndex) => {
    const pageNumber = pageIndex + 1;
    const page = textNode({
      documentId,
      documentVersion,
      kind: "PAGE",
      ordinal: ordinal++,
      parentNodeId: rootId,
      location: { page: pageNumber },
      text: pageText,
      sourceSha256: contentSha256,
    });
    nodes.push(page);
    const lines = pageText.split("\n");
    let section = null;
    let paragraph = [];
    let paragraphStart = 1;
    let tableLines = [];
    let tableStart = 1;

    const emitParagraph = (lineEnd) => {
      const text = paragraph.join("\n").trim();
      if (text && text !== "SYNTHETIC-C10") {
        nodes.push(
          textNode({
            documentId,
            documentVersion,
            kind: "CHUNK",
            ordinal: ordinal++,
            parentNodeId: section?.nodeId ?? page.nodeId,
            location: {
              page: pageNumber,
              lineStart: paragraphStart,
              lineEnd,
              chunkKind: "PARAGRAPH",
            },
            text,
            sourceSha256: contentSha256,
          }),
        );
      }
      paragraph = [];
    };

    const emitTable = (lineEnd) => {
      if (tableLines.length === 0) return;
      const tableText = tableLines.join("\n");
      const table = textNode({
        documentId,
        documentVersion,
        kind: "TABLE",
        ordinal: ordinal++,
        parentNodeId: section?.nodeId ?? page.nodeId,
        location: {
          page: pageNumber,
          lineStart: tableStart,
          lineEnd,
        },
        text: tableText,
        sourceSha256: contentSha256,
      });
      nodes.push(table);
      tableLines
        .filter((line) => !/^\|\s*:?-{3,}/.test(line))
        .forEach((row, rowIndex) => {
          nodes.push(
            textNode({
              documentId,
              documentVersion,
              kind: "CHUNK",
              ordinal: ordinal++,
              parentNodeId: table.nodeId,
              location: {
                page: pageNumber,
                tableNodeId: table.nodeId,
                row: rowIndex + 1,
                chunkKind: "TABLE_ROW",
              },
              text: row,
              sourceSha256: contentSha256,
            }),
          );
        });
      tableLines = [];
    };

    lines.forEach((line, lineIndex) => {
      const lineNumber = lineIndex + 1;
      const heading = /^(#{1,6})\s+(.+)$/.exec(line);
      const tableLine = /^\|.*\|$/.test(line);
      if (heading) {
        emitParagraph(lineNumber - 1);
        emitTable(lineNumber - 1);
        section = textNode({
          documentId,
          documentVersion,
          kind: "SECTION",
          ordinal: ordinal++,
          parentNodeId: page.nodeId,
          location: {
            page: pageNumber,
            lineStart: lineNumber,
            headingLevel: heading[1].length,
          },
          text: heading[2],
          sourceSha256: contentSha256,
        });
        nodes.push(section);
        return;
      }
      if (tableLine) {
        emitParagraph(lineNumber - 1);
        if (tableLines.length === 0) tableStart = lineNumber;
        tableLines.push(line);
        return;
      }
      if (!line.trim()) {
        emitParagraph(lineNumber - 1);
        emitTable(lineNumber - 1);
        return;
      }
      emitTable(lineNumber - 1);
      if (paragraph.length === 0) paragraphStart = lineNumber;
      paragraph.push(line);
    });
    emitParagraph(lines.length);
    emitTable(lines.length);
  });
  return nodes;
}

function csvNodes({
  documentId,
  documentVersion,
  contentSha256,
  pages,
  rootId,
}) {
  const nodes = [];
  let ordinal = 1;
  pages.forEach((pageText, pageIndex) => {
    const pageNumber = pageIndex + 1;
    const page = textNode({
      documentId,
      documentVersion,
      kind: "PAGE",
      ordinal: ordinal++,
      parentNodeId: rootId,
      location: { page: pageNumber },
      text: pageText,
      sourceSha256: contentSha256,
    });
    nodes.push(page);
    const rows = pageText
      .split("\n")
      .filter((line) => line && line !== "SYNTHETIC-C10");
    const table = textNode({
      documentId,
      documentVersion,
      kind: "TABLE",
      ordinal: ordinal++,
      parentNodeId: page.nodeId,
      location: { page: pageNumber, rowStart: 1, rowEnd: rows.length },
      text: rows.join("\n"),
      sourceSha256: contentSha256,
    });
    nodes.push(table);
    rows.forEach((row, rowIndex) => {
      nodes.push(
        textNode({
          documentId,
          documentVersion,
          kind: "CHUNK",
          ordinal: ordinal++,
          parentNodeId: table.nodeId,
          location: {
            page: pageNumber,
            tableNodeId: table.nodeId,
            row: rowIndex + 1,
            chunkKind: "TABLE_ROW",
          },
          text: row,
          sourceSha256: contentSha256,
        }),
      );
    });
  });
  return nodes;
}

export function validateKnowledgeProvenance(
  nodes,
  expectedContentSha256,
) {
  if (!Array.isArray(nodes) || nodes.length < 3) {
    fail("INVALID_PROVENANCE", "Source chain is incomplete.");
  }
  if (!SHA256.test(expectedContentSha256 ?? "")) {
    fail("INVALID_PROVENANCE", "Source hash is invalid.");
  }
  const byId = new Map();
  for (const node of nodes) {
    if (
      !node ||
      typeof node.nodeId !== "string" ||
      byId.has(node.nodeId) ||
      !["ORIGINAL", "PAGE", "SECTION", "TABLE", "CHUNK"].includes(
        node.nodeType,
      ) ||
      !Number.isSafeInteger(node.ordinal) ||
      node.ordinal < 0 ||
      !SHA256.test(node.textSha256 ?? "") ||
      node.sourceSha256 !== expectedContentSha256 ||
      node.authorityStatus !== "CANDIDATE" ||
      node.availabilityState !== "CANDIDATE" ||
      node.deletedAt !== null ||
      !node.location ||
      typeof node.location !== "object" ||
      Array.isArray(node.location)
    ) {
      fail("INVALID_PROVENANCE", "Source node is invalid.");
    }
    byId.set(node.nodeId, node);
  }
  const roots = nodes.filter((node) => node.nodeType === "ORIGINAL");
  if (
    roots.length !== 1 ||
    roots[0].parentNodeId !== null ||
    roots[0].textSha256 !== expectedContentSha256
  ) {
    fail("INVALID_PROVENANCE", "Exactly one original is required.");
  }
  const allowedParents = {
    PAGE: new Set(["ORIGINAL"]),
    SECTION: new Set(["PAGE"]),
    TABLE: new Set(["PAGE", "SECTION"]),
    CHUNK: new Set(["PAGE", "SECTION", "TABLE"]),
  };
  for (const node of nodes) {
    if (node.nodeType === "ORIGINAL") continue;
    const parent = byId.get(node.parentNodeId);
    if (!parent || !allowedParents[node.nodeType].has(parent.nodeType)) {
      fail("INVALID_PROVENANCE", "Source node parent is invalid.");
    }
    const seen = new Set([node.nodeId]);
    let cursor = parent;
    while (cursor) {
      if (seen.has(cursor.nodeId)) {
        fail("INVALID_PROVENANCE", "Source chain contains a cycle.");
      }
      seen.add(cursor.nodeId);
      cursor = cursor.parentNodeId
        ? byId.get(cursor.parentNodeId)
        : null;
    }
    if (!seen.has(roots[0].nodeId)) {
      fail("INVALID_PROVENANCE", "Source chain does not reach the original.");
    }
  }
  if (
    !nodes.some((node) => node.nodeType === "PAGE") ||
    !nodes.some((node) => node.nodeType === "CHUNK")
  ) {
    fail("INVALID_PROVENANCE", "Page and Chunk nodes are required.");
  }
  return true;
}

export function parseSyntheticCandidate({
  documentId,
  documentVersion,
  content,
  contentSha256,
  mediaType,
  parserVersion,
}) {
  if (!DOCUMENT_ID.test(documentId ?? "")) {
    fail("INVALID_INPUT", "documentId is invalid.");
  }
  safePositiveInteger(documentVersion, "documentVersion");
  if (!(content instanceof Uint8Array)) {
    fail("INVALID_INPUT", "content must be bytes.");
  }
  if (c10Sha256(content) !== contentSha256) {
    fail("CONTENT_HASH_MISMATCH", "Parser input hash changed.");
  }
  nonEmptyString(parserVersion, "parserVersion", 128);
  const text = Buffer.from(content).toString("utf8");
  const pages = text.split("\f");
  const root = textNode({
    documentId,
    documentVersion,
    kind: "ORIGINAL",
    ordinal: 0,
    parentNodeId: null,
    location: { byteStart: 0, byteEnd: content.byteLength },
    text: content,
    sourceSha256: contentSha256,
  });
  const descendants =
    mediaType === "text/csv"
      ? csvNodes({
          documentId,
          documentVersion,
          contentSha256,
          pages,
          rootId: root.nodeId,
        })
      : markdownNodes({
          documentId,
          documentVersion,
          contentSha256,
          pages,
          rootId: root.nodeId,
        });
  const nodes = Object.freeze([root, ...descendants]);
  validateKnowledgeProvenance(nodes, contentSha256);
  return Object.freeze({
    parserVersion,
    authorityStatus: "CANDIDATE",
    pageCount: nodes.filter((node) => node.nodeType === "PAGE").length,
    sectionCount: nodes.filter((node) => node.nodeType === "SECTION")
      .length,
    tableCount: nodes.filter((node) => node.nodeType === "TABLE").length,
    chunkCount: nodes.filter((node) => node.nodeType === "CHUNK").length,
    nodes,
    parseSha256: c10Sha256(nodes),
  });
}

function validateAcl(acl, documentId) {
  exactKeys(
    acl,
    ["resourceId", "readPrincipalRefs", "managePrincipalRefs"],
    "metadata.acl",
  );
  if (acl.resourceId !== documentId) {
    fail("REQUIRED_METADATA_MISSING", "ACL resource is not the document.");
  }
  for (const field of ["readPrincipalRefs", "managePrincipalRefs"]) {
    if (
      !Array.isArray(acl[field]) ||
      acl[field].length === 0 ||
      acl[field].some(
        (entry) =>
          typeof entry !== "string" ||
          !/^(?:human|group|workload):[A-Za-z0-9._-]{1,128}$/.test(entry),
      )
    ) {
      fail("REQUIRED_METADATA_MISSING", `${field} is required.`);
    }
  }
}

export function validatePublicationMetadata(metadata, documentId) {
  exactKeys(
    metadata,
    [
      "ownerPrincipalId",
      "sourceRef",
      "version",
      "validFrom",
      "validUntil",
      "classification",
      "acl",
    ],
    "publication metadata",
  );
  if (!PRINCIPAL_ID.test(metadata.ownerPrincipalId ?? "")) {
    fail("REQUIRED_METADATA_MISSING", "Owner is required.");
  }
  reference(metadata.sourceRef, "metadata.sourceRef");
  nonEmptyString(metadata.version, "metadata.version", 128);
  canonicalInstant(metadata.validFrom, "metadata.validFrom");
  canonicalInstant(metadata.validUntil, "metadata.validUntil");
  if (Date.parse(metadata.validUntil) <= Date.parse(metadata.validFrom)) {
    fail("REQUIRED_METADATA_MISSING", "Validity interval is invalid.");
  }
  if (!CLASSIFICATIONS.has(metadata.classification)) {
    fail("REQUIRED_METADATA_MISSING", "Classification is required.");
  }
  validateAcl(metadata.acl, documentId);
  return Object.freeze(clone(metadata));
}

function validateAuthorizationEvidence(
  evidence,
  { tenantId, documentId, surface },
) {
  if (
    evidence?.trustSource !== "C06_BOUND_DECISION_EVIDENCE" ||
    evidence?.tenantId !== tenantId ||
    evidence?.resourceId !== documentId ||
    evidence?.surface !== surface ||
    typeof evidence?.decisionId !== "string" ||
    !evidence.decisionId ||
    typeof evidence?.evidenceRef !== "string" ||
    !evidence.evidenceRef ||
    typeof evidence?.policyVersion !== "string" ||
    !evidence.policyVersion
  ) {
    fail(
      "AUTHORIZATION_UNAVAILABLE",
      "C06 decision is not bound to this C10 operation.",
    );
  }
}

function validateDocumentCoordinates(documentId, documentVersion) {
  if (!DOCUMENT_ID.test(documentId ?? "")) {
    fail("INVALID_INPUT", "documentId is invalid.");
  }
  safePositiveInteger(documentVersion, "documentVersion");
}

function validateCommonCommand(command, allowed) {
  exactKeys(command, allowed, "C10 command");
  validateDocumentCoordinates(
    command.documentId,
    command.documentVersion,
  );
  nonEmptyString(command.idempotencyKey, "idempotencyKey", 128);
  safePositiveInteger(command.expectedRevision, "expectedRevision", {
    allowZero: true,
  });
}

function withNodeAvailability(nodes, state, at) {
  const availability =
    state === "PARSED_CANDIDATE" ? "CANDIDATE" : state;
  return nodes.map((node) => ({
    ...clone(node),
    availabilityState: availability,
    deletedAt: state === "DELETED" ? at : null,
  }));
}

export function transitionKnowledgeDocument({
  current,
  previousVersion,
  command,
}) {
  if (!COMMANDS.has(command?.type)) {
    fail("INVALID_INPUT", "C10 command type is invalid.");
  }
  canonicalInstant(command.at, "command.at");
  if (command.type === "UPLOAD") {
    if (current) fail("VERSION_CONFLICT", "Document version already exists.");
    if (
      command.documentVersion > 1 &&
      (!previousVersion ||
        previousVersion.documentVersion !== command.documentVersion - 1)
    ) {
      fail("VERSION_CONFLICT", "Document versions must be contiguous.");
    }
    return Object.freeze({
      tenantId: command.tenantId,
      tenantKind: "SYNTHETIC",
      documentId: command.documentId,
      documentVersion: command.documentVersion,
      revision: 1,
      state: "QUARANTINED",
      fixtureRef: command.fixtureRef,
      sourceRef: command.sourceRef,
      filename: command.filename,
      declaredMediaType: command.declaredMediaType,
      detectedMediaType: null,
      contentSha256: command.contentSha256,
      contentSize: command.contentSize,
      quarantineRef: command.quarantineRef,
      inspection: null,
      parserVersion: null,
      parseSha256: null,
      nodes: [],
      metadata: null,
      authorizationEvidence: clone(command.authorizationEvidence),
      createdAt: command.at,
      updatedAt: command.at,
      publishedAt: null,
      withdrawnAt: null,
      expiredAt: null,
      deletedAt: null,
    });
  }
  if (!current) fail("NOT_FOUND", "Document version does not exist.");
  if (current.revision !== command.expectedRevision) {
    fail("VERSION_CONFLICT", "Document revision is stale.");
  }
  if (
    current.tenantId !== command.tenantId ||
    current.documentId !== command.documentId ||
    current.documentVersion !== command.documentVersion
  ) {
    fail("TENANT_SCOPE_VIOLATION", "Document coordinates changed.");
  }
  const next = clone(current);
  next.revision += 1;
  next.updatedAt = command.at;
  next.authorizationEvidence = clone(command.authorizationEvidence);
  if (command.type === "INSPECT") {
    if (current.state !== "QUARANTINED") {
      fail("INVALID_STATE", "Only quarantined documents can be inspected.");
    }
    next.inspection = clone(command.inspection);
    next.detectedMediaType = command.inspection.detectedMediaType;
    next.state =
      command.inspection.outcome === "PASS" ? "INSPECTED" : "REJECTED";
  } else if (command.type === "PARSE") {
    if (current.state !== "INSPECTED") {
      fail("INVALID_STATE", "Only inspected documents can be parsed.");
    }
    if (current.inspection?.outcome !== "PASS") {
      fail("INSPECTION_FAILED", "Rejected input cannot reach a parser.");
    }
    validateKnowledgeProvenance(command.nodes, current.contentSha256);
    next.state = "PARSED_CANDIDATE";
    next.parserVersion = command.parserVersion;
    next.parseSha256 = command.parseSha256;
    next.nodes = withNodeAvailability(
      command.nodes,
      "PARSED_CANDIDATE",
      command.at,
    );
  } else if (command.type === "PUBLISH") {
    if (current.state !== "PARSED_CANDIDATE") {
      fail("INVALID_STATE", "Only parsed candidates can be published.");
    }
    next.metadata = clone(command.metadata);
    next.state = "PUBLISHED";
    next.publishedAt = command.at;
    next.nodes = withNodeAvailability(
      current.nodes,
      "PUBLISHED",
      command.at,
    );
  } else if (command.type === "WITHDRAW") {
    if (current.state !== "PUBLISHED") {
      fail("INVALID_STATE", "Only a published document can be withdrawn.");
    }
    next.state = "WITHDRAWN";
    next.withdrawnAt = command.at;
    next.nodes = withNodeAvailability(
      current.nodes,
      "WITHDRAWN",
      command.at,
    );
  } else if (command.type === "EXPIRE") {
    if (
      current.state !== "PUBLISHED" ||
      Date.parse(command.at) < Date.parse(current.metadata?.validUntil ?? "")
    ) {
      fail("INVALID_STATE", "Document is not eligible for expiration.");
    }
    next.state = "EXPIRED";
    next.expiredAt = command.at;
    next.nodes = withNodeAvailability(
      current.nodes,
      "EXPIRED",
      command.at,
    );
  } else if (command.type === "DELETE") {
    if (current.state === "DELETED") {
      fail("INVALID_STATE", "Document is already deleted.");
    }
    next.state = "DELETED";
    next.deletedAt = command.at;
    next.nodes = withNodeAvailability(
      current.nodes,
      "DELETED",
      command.at,
    );
  }
  if (!STATES.has(next.state)) {
    fail("INVALID_STATE", "C10 transition produced an invalid state.");
  }
  return Object.freeze(next);
}

function documentKey(tenantId, documentId, documentVersion) {
  return `${tenantId}\u0000${documentId}\u0000${documentVersion}`;
}

function receiptKey(tenantId, idempotencyKey) {
  return `${tenantId}\u0000${idempotencyKey}`;
}

export function createMemoryC10QuarantineStore() {
  const objects = new Map();

  function key(tenantId, contentSha256) {
    return `${tenantId}\u0000${contentSha256}`;
  }

  function validate(tenantId, contentSha256) {
    if (
      !SYNTHETIC_TENANT_ID.test(tenantId ?? "") ||
      !SHA256.test(contentSha256 ?? "")
    ) {
      fail(
        "TENANT_SCOPE_VIOLATION",
        "Quarantine coordinates are invalid.",
      );
    }
  }

  return Object.freeze({
    async put({ tenantId, contentSha256, content }) {
      validate(tenantId, contentSha256);
      if (
        !(content instanceof Uint8Array) ||
        c10Sha256(content) !== contentSha256
      ) {
        fail("CONTENT_HASH_MISMATCH", "Quarantine input hash changed.");
      }
      const objectKey = key(tenantId, contentSha256);
      const existing = objects.get(objectKey);
      if (existing && c10Sha256(existing) !== contentSha256) {
        fail("CONTENT_HASH_MISMATCH", "Quarantine object is corrupt.");
      }
      if (!existing) objects.set(objectKey, Buffer.from(content));
      return `quarantine://c10/${tenantId}/${contentSha256.slice(7)}`;
    },
    async read({ tenantId, quarantineRef, contentSha256 }) {
      validate(tenantId, contentSha256);
      const expected =
        `quarantine://c10/${tenantId}/${contentSha256.slice(7)}`;
      if (quarantineRef !== expected) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "Quarantine reference crossed Tenant scope.",
        );
      }
      const content = objects.get(key(tenantId, contentSha256));
      if (!content) {
        fail("QUARANTINE_NOT_FOUND", "Quarantine object is unavailable.");
      }
      if (c10Sha256(content) !== contentSha256) {
        fail("CONTENT_HASH_MISMATCH", "Quarantine object is corrupt.");
      }
      return Buffer.from(content);
    },
    async erase({ tenantId, quarantineRef, contentSha256 }) {
      validate(tenantId, contentSha256);
      const expected =
        `quarantine://c10/${tenantId}/${contentSha256.slice(7)}`;
      if (quarantineRef !== expected) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "Quarantine reference crossed Tenant scope.",
        );
      }
      objects.delete(key(tenantId, contentSha256));
    },
    has({ tenantId, contentSha256 }) {
      validate(tenantId, contentSha256);
      return objects.has(key(tenantId, contentSha256));
    },
  });
}

export function createMemoryKnowledgeCatalogStore({ snapshot } = {}) {
  const documents = new Map(snapshot?.documents ?? []);
  const histories = new Map(snapshot?.histories ?? []);
  const receipts = new Map(snapshot?.receipts ?? []);
  let queue = Promise.resolve();

  async function serialized(operation) {
    const result = queue.then(operation);
    queue = result.catch(() => undefined);
    return result;
  }

  function scoped(scope, record) {
    if (record && record.tenantId !== scope.tenantId) {
      fail("TENANT_SCOPE_VIOLATION", "Store returned another Tenant.");
    }
    return record;
  }

  return Object.freeze({
    async apply(scope, envelope) {
      validateTenantScope(scope);
      return serialized(async () => {
        const storedReceipt = receipts.get(
          receiptKey(scope.tenantId, envelope.idempotencyKey),
        );
        if (storedReceipt) {
          if (storedReceipt.requestHash !== envelope.requestHash) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "Idempotency key was reused with another request.",
            );
          }
          return {
            ...clone(storedReceipt.result),
            replayed: true,
          };
        }
        const key = documentKey(
          scope.tenantId,
          envelope.command.documentId,
          envelope.command.documentVersion,
        );
        const current = documents.get(key) ?? null;
        const previousVersion =
          envelope.command.documentVersion > 1
            ? documents.get(
                documentKey(
                  scope.tenantId,
                  envelope.command.documentId,
                  envelope.command.documentVersion - 1,
                ),
              ) ?? null
            : null;
        const next = transitionKnowledgeDocument({
          current,
          previousVersion,
          command: envelope.command,
        });
        documents.set(key, clone(next));
        const history = histories.get(key) ?? [];
        history.push(clone(next));
        histories.set(key, history);
        const result = Object.freeze({
          replayed: false,
          document: clone(next),
        });
        receipts.set(receiptKey(scope.tenantId, envelope.idempotencyKey), {
          requestHash: envelope.requestHash,
          result: clone(result),
        });
        return result;
      });
    },
    async readCurrent(scope, { documentId, documentVersion }) {
      validateTenantScope(scope);
      validateDocumentCoordinates(documentId, documentVersion);
      return clone(
        scoped(
          scope,
          documents.get(
            documentKey(scope.tenantId, documentId, documentVersion),
          ) ?? null,
        ),
      );
    },
    async readAsOf(scope, { documentId, documentVersion, asOf }) {
      validateTenantScope(scope);
      if (!DOCUMENT_ID.test(documentId ?? "")) {
        fail("INVALID_INPUT", "documentId is invalid.");
      }
      canonicalInstant(asOf, "asOf");
      const versions = documentVersion
        ? [documentVersion]
        : [...documents.values()]
            .filter(
              (record) =>
                record.tenantId === scope.tenantId &&
                record.documentId === documentId,
            )
            .map((record) => record.documentVersion)
            .sort((left, right) => right - left);
      for (const version of versions) {
        safePositiveInteger(version, "documentVersion");
        const history =
          histories.get(documentKey(scope.tenantId, documentId, version)) ??
          [];
        const candidate = [...history]
          .filter((record) => Date.parse(record.updatedAt) <= Date.parse(asOf))
          .sort((left, right) => right.revision - left.revision)[0];
        if (
          candidate?.state === "PUBLISHED" &&
          Date.parse(candidate.metadata.validFrom) <= Date.parse(asOf) &&
          Date.parse(asOf) < Date.parse(candidate.metadata.validUntil)
        ) {
          return clone(candidate);
        }
      }
      return null;
    },
    exportSnapshot() {
      return clone({
        documents: [...documents.entries()],
        histories: [...histories.entries()],
        receipts: [...receipts.entries()],
      });
    },
  });
}

async function enforce(c06Authorizer, context, documentId, surface) {
  let evidence;
  try {
    evidence = await c06Authorizer.enforce(
      context.c06ServerContext,
      {
        ...context.authorizationRequest,
        resourceId: documentId,
      },
      { surface },
    );
  } catch (error) {
    if (error?.code === "ACCESS_DENIED") {
      fail("ACCESS_DENIED", "C06 denied the C10 operation.");
    }
    fail("AUTHORIZATION_UNAVAILABLE", "C06 authorization is unavailable.");
  }
  validateAuthorizationEvidence(evidence, {
    tenantId: context.tenantScope.tenantId,
    documentId,
    surface,
  });
  return evidence;
}

function envelope(command, idempotencyKey) {
  const stableRequest = { ...command };
  delete stableRequest.at;
  delete stableRequest.authorizationEvidence;
  const requestHash = c10Sha256(stableRequest);
  return Object.freeze({ idempotencyKey, requestHash, command });
}

export function createKnowledgeCatalog({
  store,
  c06Authorizer,
  benchmark,
  quarantineStore = createMemoryC10QuarantineStore(),
  clock = () => new Date().toISOString(),
}) {
  if (
    typeof store?.apply !== "function" ||
    typeof store?.readCurrent !== "function" ||
    typeof store?.readAsOf !== "function" ||
    typeof c06Authorizer?.enforce !== "function" ||
    typeof benchmark?.resolve !== "function" ||
    !Number.isSafeInteger(benchmark?.maxFileBytes) ||
    typeof benchmark?.parserVersion !== "string" ||
    typeof quarantineStore?.put !== "function" ||
    typeof quarantineStore?.read !== "function" ||
    typeof quarantineStore?.erase !== "function" ||
    typeof clock !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C10 dependencies are incomplete.");
  }

  async function commandContext(context, documentId, surface) {
    validateContext(context);
    return enforce(c06Authorizer, context, documentId, surface);
  }

  async function current(context, command, surface = MUTATION_SURFACE) {
    const authorizationEvidence = await commandContext(
      context,
      command.documentId,
      surface,
    );
    const record = await store.readCurrent(context.tenantScope, command);
    return { authorizationEvidence, record };
  }

  return Object.freeze({
    async upload(context, command) {
      validateCommonCommand(command, [
        "idempotencyKey",
        "documentId",
        "documentVersion",
        "expectedRevision",
        "fixtureRef",
        "filename",
        "declaredMediaType",
        "sourceRef",
      ]);
      if (command.expectedRevision !== 0) {
        fail("INVALID_INPUT", "Upload expectedRevision must be zero.");
      }
      reference(command.fixtureRef, "fixtureRef");
      reference(command.sourceRef, "sourceRef");
      nonEmptyString(command.filename, "filename", 255);
      nonEmptyString(command.declaredMediaType, "declaredMediaType", 128);
      const { content } = benchmark.resolve(command.fixtureRef);
      const authorizationEvidence = await commandContext(
        context,
        command.documentId,
        MUTATION_SURFACE,
      );
      const at = canonicalInstant(clock(), "clock");
      const contentSha256 = c10Sha256(content);
      const quarantineRef =
        `quarantine://c10/${context.tenantScope.tenantId}/` +
        contentSha256.slice(7);
      const normalized = Object.freeze({
        type: "UPLOAD",
        tenantId: context.tenantScope.tenantId,
        documentId: command.documentId,
        documentVersion: command.documentVersion,
        expectedRevision: 0,
        fixtureRef: command.fixtureRef,
        sourceRef: command.sourceRef,
        filename: command.filename,
        declaredMediaType: command.declaredMediaType.toLowerCase(),
        contentSha256,
        contentSize: content.byteLength,
        quarantineRef,
        authorizationEvidence,
        at,
      });
      const result = await store.apply(
        context.tenantScope,
        envelope(normalized, command.idempotencyKey),
      );
      await quarantineStore.put({
        tenantId: context.tenantScope.tenantId,
        contentSha256,
        content,
      });
      const latest = await store.readCurrent(
        context.tenantScope,
        command,
      );
      if (latest?.state === "DELETED") {
        await quarantineStore.erase({
          tenantId: context.tenantScope.tenantId,
          quarantineRef,
          contentSha256,
        });
      }
      return result;
    },
    async inspect(context, command) {
      validateCommonCommand(command, [
        "idempotencyKey",
        "documentId",
        "documentVersion",
        "expectedRevision",
      ]);
      const { authorizationEvidence, record } = await current(
        context,
        command,
      );
      if (!record) fail("NOT_FOUND", "Document version does not exist.");
      benchmark.resolve(record.fixtureRef);
      const content = await quarantineStore.read({
        tenantId: context.tenantScope.tenantId,
        quarantineRef: record.quarantineRef,
        contentSha256: record.contentSha256,
      });
      if (
        c10Sha256(content) !== record.contentSha256 ||
        content.byteLength !== record.contentSize
      ) {
        fail("CONTENT_HASH_MISMATCH", "Quarantined content changed.");
      }
      const inspection = inspectSyntheticDocument({
        filename: record.filename,
        declaredMediaType: record.declaredMediaType,
        content,
        maxFileBytes: benchmark.maxFileBytes,
      });
      const normalized = Object.freeze({
        type: "INSPECT",
        tenantId: context.tenantScope.tenantId,
        documentId: command.documentId,
        documentVersion: command.documentVersion,
        expectedRevision: command.expectedRevision,
        inspection,
        authorizationEvidence,
        at: canonicalInstant(clock(), "clock"),
      });
      return store.apply(
        context.tenantScope,
        envelope(normalized, command.idempotencyKey),
      );
    },
    async parse(context, command) {
      validateCommonCommand(command, [
        "idempotencyKey",
        "documentId",
        "documentVersion",
        "expectedRevision",
      ]);
      const { authorizationEvidence, record } = await current(
        context,
        command,
      );
      if (!record) fail("NOT_FOUND", "Document version does not exist.");
      if (record.inspection?.outcome !== "PASS") {
        fail("INSPECTION_FAILED", "Rejected input cannot reach a parser.");
      }
      benchmark.resolve(record.fixtureRef);
      const content = await quarantineStore.read({
        tenantId: context.tenantScope.tenantId,
        quarantineRef: record.quarantineRef,
        contentSha256: record.contentSha256,
      });
      const parsed = parseSyntheticCandidate({
        documentId: command.documentId,
        documentVersion: command.documentVersion,
        content,
        contentSha256: record.contentSha256,
        mediaType: record.detectedMediaType,
        parserVersion: benchmark.parserVersion,
      });
      const normalized = Object.freeze({
        type: "PARSE",
        tenantId: context.tenantScope.tenantId,
        documentId: command.documentId,
        documentVersion: command.documentVersion,
        expectedRevision: command.expectedRevision,
        parserVersion: parsed.parserVersion,
        parseSha256: parsed.parseSha256,
        nodes: parsed.nodes,
        authorizationEvidence,
        at: canonicalInstant(clock(), "clock"),
      });
      return store.apply(
        context.tenantScope,
        envelope(normalized, command.idempotencyKey),
      );
    },
    async publish(context, command) {
      validateCommonCommand(command, [
        "idempotencyKey",
        "documentId",
        "documentVersion",
        "expectedRevision",
        "metadata",
      ]);
      const metadata = validatePublicationMetadata(
        command.metadata,
        command.documentId,
      );
      const authorizationEvidence = await commandContext(
        context,
        command.documentId,
        MUTATION_SURFACE,
      );
      const normalized = Object.freeze({
        type: "PUBLISH",
        tenantId: context.tenantScope.tenantId,
        documentId: command.documentId,
        documentVersion: command.documentVersion,
        expectedRevision: command.expectedRevision,
        metadata,
        authorizationEvidence,
        at: canonicalInstant(clock(), "clock"),
      });
      return store.apply(
        context.tenantScope,
        envelope(normalized, command.idempotencyKey),
      );
    },
    async withdraw(context, command) {
      validateCommonCommand(command, [
        "idempotencyKey",
        "documentId",
        "documentVersion",
        "expectedRevision",
      ]);
      const authorizationEvidence = await commandContext(
        context,
        command.documentId,
        MUTATION_SURFACE,
      );
      const normalized = Object.freeze({
        type: "WITHDRAW",
        tenantId: context.tenantScope.tenantId,
        documentId: command.documentId,
        documentVersion: command.documentVersion,
        expectedRevision: command.expectedRevision,
        authorizationEvidence,
        at: canonicalInstant(clock(), "clock"),
      });
      return store.apply(
        context.tenantScope,
        envelope(normalized, command.idempotencyKey),
      );
    },
    async expire(context, command) {
      validateCommonCommand(command, [
        "idempotencyKey",
        "documentId",
        "documentVersion",
        "expectedRevision",
      ]);
      const authorizationEvidence = await commandContext(
        context,
        command.documentId,
        MUTATION_SURFACE,
      );
      const normalized = Object.freeze({
        type: "EXPIRE",
        tenantId: context.tenantScope.tenantId,
        documentId: command.documentId,
        documentVersion: command.documentVersion,
        expectedRevision: command.expectedRevision,
        authorizationEvidence,
        at: canonicalInstant(clock(), "clock"),
      });
      return store.apply(
        context.tenantScope,
        envelope(normalized, command.idempotencyKey),
      );
    },
    async delete(context, command) {
      validateCommonCommand(command, [
        "idempotencyKey",
        "documentId",
        "documentVersion",
        "expectedRevision",
      ]);
      const authorizationEvidence = await commandContext(
        context,
        command.documentId,
        MUTATION_SURFACE,
      );
      const normalized = Object.freeze({
        type: "DELETE",
        tenantId: context.tenantScope.tenantId,
        documentId: command.documentId,
        documentVersion: command.documentVersion,
        expectedRevision: command.expectedRevision,
        authorizationEvidence,
        at: canonicalInstant(clock(), "clock"),
      });
      const result = await store.apply(
        context.tenantScope,
        envelope(normalized, command.idempotencyKey),
      );
      await quarantineStore.erase({
        tenantId: context.tenantScope.tenantId,
        quarantineRef: result.document.quarantineRef,
        contentSha256: result.document.contentSha256,
      });
      return result;
    },
    async readAsOf(context, query) {
      exactKeys(
        query,
        ["documentId", "documentVersion", "asOf"],
        "C10 as-of query",
        ["documentId", "asOf"],
      );
      if (!DOCUMENT_ID.test(query.documentId ?? "")) {
        fail("INVALID_INPUT", "documentId is invalid.");
      }
      if (query.documentVersion !== undefined) {
        safePositiveInteger(query.documentVersion, "documentVersion");
      }
      canonicalInstant(query.asOf, "asOf");
      await commandContext(
        context,
        query.documentId,
        READ_SURFACE,
      );
      return store.readAsOf(context.tenantScope, query);
    },
  });
}

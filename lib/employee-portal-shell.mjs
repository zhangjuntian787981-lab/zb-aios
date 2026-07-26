const RENDERERS = new Set([
  "LIBRECHAT_ADAPTER",
  "MINIMAL_REPLACEMENT",
]);
const EVIDENCE_REF =
  /^evidence:\/\/[A-Za-z0-9][A-Za-z0-9._~:/-]*$/;
const SURFACES = Object.freeze([
  Object.freeze({
    surfaceId: "home",
    readOperationId: "PORTAL_HOME_VIEW",
    writeOperationIds: Object.freeze([]),
    streamOperationId: null,
  }),
  Object.freeze({
    surfaceId: "threads",
    readOperationId: "THREAD_VIEW",
    writeOperationIds: Object.freeze([
      "THREAD_CREATE",
      "CHAT_SUBMIT",
    ]),
    streamOperationId: null,
  }),
  Object.freeze({
    surfaceId: "runs",
    readOperationId: "RUN_VIEW",
    writeOperationIds: Object.freeze([]),
    streamOperationId: "RUN_STREAM_VIEW",
  }),
  Object.freeze({
    surfaceId: "files",
    readOperationId: "FILE_STATUS_VIEW",
    writeOperationIds: Object.freeze([
      "FILE_QUARANTINE_REQUEST",
    ]),
    streamOperationId: null,
  }),
  Object.freeze({
    surfaceId: "resources",
    readOperationId: "RESOURCE_DIRECTORY_VIEW",
    writeOperationIds: Object.freeze([]),
    streamOperationId: null,
  }),
  Object.freeze({
    surfaceId: "agent-skills",
    readOperationId: "AGENT_SKILL_DIRECTORY_VIEW",
    writeOperationIds: Object.freeze([]),
    streamOperationId: null,
  }),
  Object.freeze({
    surfaceId: "memory",
    readOperationId: "MEMORY_VIEW",
    writeOperationIds: Object.freeze(["MEMORY_CONFIRM"]),
    streamOperationId: null,
  }),
  Object.freeze({
    surfaceId: "approvals",
    readOperationId: "APPROVAL_VIEW",
    writeOperationIds: Object.freeze(["APPROVAL_DECIDE"]),
    streamOperationId: null,
  }),
  Object.freeze({
    surfaceId: "citations",
    readOperationId: "CITATION_VIEW",
    writeOperationIds: Object.freeze([]),
    streamOperationId: null,
  }),
]);

export class EmployeePortalShellError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "EmployeePortalShellError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new EmployeePortalShellError(code, message);
}

function validateAuthority(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    value.authorityOwner !== "PRODUCT_CORE" ||
    !EVIDENCE_REF.test(value.authorizationEvidenceRef ?? "")
  ) {
    fail(
      "UNTRUSTED_BFF_RESPONSE",
      "C01 shell accepts only a Product Core-authorized response.",
    );
  }
}

export function createEmployeePortalShell({ renderer, bffClient }) {
  if (
    !RENDERERS.has(renderer) ||
    typeof bffClient?.read !== "function" ||
    typeof bffClient?.mutate !== "function" ||
    typeof bffClient?.stream !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C01 shell configuration is invalid.");
  }

  return Object.freeze({
    renderer,

    listSurfaces() {
      return SURFACES;
    },

    async load(request) {
      const view = await bffClient.read(structuredClone(request));
      validateAuthority(view);
      return Object.freeze(structuredClone(view));
    },

    async submit(request) {
      const receipt = await bffClient.mutate(
        structuredClone(request),
      );
      validateAuthority(receipt);
      return Object.freeze(structuredClone(receipt));
    },

    async *stream(request) {
      for await (
        const event of bffClient.stream(structuredClone(request))
      ) {
        validateAuthority(event);
        yield Object.freeze(structuredClone(event));
      }
    },
  });
}

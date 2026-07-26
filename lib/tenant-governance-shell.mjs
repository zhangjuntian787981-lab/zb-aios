const EVIDENCE_REF =
  /^evidence:\/\/[A-Za-z0-9][A-Za-z0-9._~:/-]*$/;

const PAGES = Object.freeze([
  Object.freeze({
    pageId: "tenant-config",
    readOperationId: "TENANT_CONFIG_VIEW",
    writeOperationId: "TENANT_CONFIG_CHANGE",
  }),
  Object.freeze({
    pageId: "principal-roles",
    readOperationId: "PRINCIPAL_ROLE_VIEW",
    writeOperationId: "PRINCIPAL_ROLE_CHANGE",
  }),
  Object.freeze({
    pageId: "knowledge-releases",
    readOperationId: "KNOWLEDGE_RELEASE_VIEW",
    writeOperationId: "KNOWLEDGE_RELEASE_CHANGE",
  }),
  Object.freeze({
    pageId: "skill-releases",
    readOperationId: "SKILL_RELEASE_VIEW",
    writeOperationId: "SKILL_RELEASE_CHANGE",
  }),
  Object.freeze({
    pageId: "quotas",
    readOperationId: "QUOTA_VIEW",
    writeOperationId: "QUOTA_CHANGE",
  }),
  Object.freeze({
    pageId: "formal-artifacts",
    readOperationId: "FORMAL_ARTIFACT_VIEW",
    writeOperationId: "FORMAL_ARTIFACT_PUBLISH",
  }),
  Object.freeze({
    pageId: "audit",
    readOperationId: "AUDIT_VIEW",
    writeOperationId: null,
  }),
  Object.freeze({
    pageId: "connectors",
    readOperationId: "CONNECTOR_STAGE_VIEW",
    writeOperationId: "CONNECTOR_STAGE_CHANGE",
  }),
  Object.freeze({
    pageId: "observability",
    readOperationId: "OBSERVABILITY_VIEW",
    writeOperationId: null,
  }),
]);
const KNOWN_OPERATIONS = new Set(
  PAGES.flatMap(({ readOperationId, writeOperationId }) =>
    writeOperationId === null
      ? [readOperationId]
      : [readOperationId, writeOperationId],
  ),
);

export class TenantGovernanceShellError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TenantGovernanceShellError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new TenantGovernanceShellError(code, message);
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
      "C02 shell accepts only a Product Core-authorized response.",
    );
  }
}

function validateAllowedActions(value) {
  if (
    !Array.isArray(value) ||
    new Set(value).size !== value.length ||
    value.some(
      (operationId) =>
        typeof operationId !== "string" ||
        !KNOWN_OPERATIONS.has(operationId),
    )
  ) {
    fail(
      "UNTRUSTED_BFF_RESPONSE",
      "C02 allowed actions are not server-authorized.",
    );
  }
}

export function createTenantGovernanceShell({ bffClient }) {
  if (
    typeof bffClient?.read !== "function" ||
    typeof bffClient?.mutate !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C02 BFF client is incomplete.");
  }

  return Object.freeze({
    listPages() {
      return PAGES;
    },

    async load(request) {
      const view = await bffClient.read(structuredClone(request));
      validateAuthority(view);
      validateAllowedActions(view.allowedActions);
      return Object.freeze(structuredClone(view));
    },

    allowedActions(view) {
      validateAuthority(view);
      validateAllowedActions(view.allowedActions);
      return Object.freeze(structuredClone(view.allowedActions));
    },

    async submit(request) {
      const receipt = await bffClient.mutate(structuredClone(request));
      validateAuthority(receipt);
      if (
        receipt.status !== "COMMITTED" ||
        !/^evidence:\/\/c18\//.test(receipt.auditRef ?? "")
      ) {
        fail(
          "UNTRUSTED_BFF_RESPONSE",
          "C02 mutation receipt is not auditable.",
        );
      }
      return Object.freeze(structuredClone(receipt));
    },
  });
}

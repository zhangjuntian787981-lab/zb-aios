import { createHash } from "node:crypto";

const ACCOUNT_STATES = new Set(["ACTIVE", "SUSPENDED", "TERMINATED"]);
const SYNTHETIC_TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PROVIDER_CONNECTION_ID =
  /^idp_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export class ScimIdentityProvisionerError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ScimIdentityProvisionerError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new ScimIdentityProvisionerError(code, message);
}

function exactKeys(value, allowed, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_INPUT", `${field} must be an object.`);
  }
  if (
    Object.keys(value).length !== allowed.length ||
    Object.keys(value).some((key) => !allowed.includes(key))
  ) {
    fail("INVALID_INPUT", `${field} fields are invalid.`);
  }
}

function text(value, field, maximum, pattern) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    (pattern && !pattern.test(value))
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function normalizeInput(input) {
  exactKeys(
    input,
    [
      "fixtureUserId",
      "sourceEventId",
      "sourceRevision",
      "desiredState",
      "correlationId",
    ],
    "input",
  );
  text(input.fixtureUserId, "fixtureUserId", 128);
  text(input.sourceEventId, "sourceEventId", 128);
  if (
    !Number.isSafeInteger(input.sourceRevision) ||
    input.sourceRevision < 1
  ) {
    fail("INVALID_INPUT", "sourceRevision is invalid.");
  }
  if (!ACCOUNT_STATES.has(input.desiredState)) {
    fail("INVALID_INPUT", "desiredState is invalid.");
  }
  text(input.correlationId, "correlationId", 128);
  return structuredClone(input);
}

function normalizeMapping(
  value,
  { tenantId, providerConnectionId, fixtureUserId },
) {
  exactKeys(
    value,
    [
      "tenantId",
      "providerConnectionId",
      "fixtureUserId",
      "directoryObjectId",
      "loginSubject",
      "profile",
    ],
    "resolved account",
  );
  if (
    value.tenantId !== tenantId ||
    value.providerConnectionId !== providerConnectionId ||
    value.fixtureUserId !== fixtureUserId
  ) {
    fail(
      "IDENTITY_BINDING_CONFLICT",
      "Resolved account is outside the fixed identity namespace.",
    );
  }
  text(
    value.directoryObjectId,
    "directoryObjectId",
    256,
    /^[A-Za-z0-9._:@/+~-]+$/,
  );
  text(
    value.loginSubject,
    "loginSubject",
    128,
    /^[A-Za-z0-9._@+-]+$/,
  );
  exactKeys(
    value.profile,
    ["givenName", "familyName", "email"],
    "resolved account profile",
  );
  text(value.profile.givenName, "profile.givenName", 128);
  text(value.profile.familyName, "profile.familyName", 128);
  text(
    value.profile.email,
    "profile.email",
    254,
    /^[^\s@]+@[^\s@]+$/,
  );
  return structuredClone(value);
}

function idempotencyKey(tenantId, providerConnectionId, sourceEventId) {
  const digest = createHash("sha256")
    .update(
      JSON.stringify({
        tenantId,
        providerConnectionId,
        sourceEventId,
      }),
      "utf8",
    )
    .digest("hex");
  return `c04-scim-${digest}`;
}

function validateCoreResult(value, desiredState) {
  if (
    !value ||
    typeof value !== "object" ||
    typeof value.accountId !== "string" ||
    value.accountId.length === 0 ||
    !ACCOUNT_STATES.has(value.state) ||
    typeof value.applied !== "boolean" ||
    typeof value.duplicate !== "boolean" ||
    (value.stale !== undefined && typeof value.stale !== "boolean") ||
    (value.stale === true && value.applied !== false)
  ) {
    fail("CORE_RESULT_INVALID", "C04 Core returned an invalid result.");
  }
  if (value.stale !== true && value.state !== desiredState) {
    fail(
      "CORE_RESULT_MISMATCH",
      "C04 Core result did not match the requested account state.",
    );
  }
}

function validateScimResult(value, mapping, command) {
  if (
    !value ||
    typeof value !== "object" ||
    value.externalId !== mapping.directoryObjectId ||
    typeof value.resourceId !== "string" ||
    value.resourceId.length === 0 ||
    value.sourceRevision !== command.sourceRevision ||
    value.state !== command.desiredState ||
    typeof value.applied !== "boolean" ||
    typeof value.stale !== "boolean"
  ) {
    fail(
      "SCIM_RESULT_MISMATCH",
      "SCIM result did not match the committed C04 account snapshot.",
    );
  }
}

function freeze(value) {
  Object.freeze(value);
  for (const child of Object.values(value)) {
    if (
      child &&
      typeof child === "object" &&
      !Object.isFrozen(child)
    ) {
      freeze(child);
    }
  }
  return value;
}

function frozenClone(value) {
  const clone = structuredClone(value);
  freeze(clone);
  return clone;
}

export function createScimIdentityProvisioner({
  tenantId,
  providerConnectionId,
  coreContext,
  identityFederation,
  scimAdapter,
  resolveSyntheticAccount,
}) {
  text(tenantId, "tenantId", 80, SYNTHETIC_TENANT_ID);
  text(
    providerConnectionId,
    "providerConnectionId",
    80,
    PROVIDER_CONNECTION_ID,
  );
  if (!coreContext || typeof coreContext !== "object") {
    fail("INVALID_CONFIGURATION", "coreContext is required.");
  }
  if (
    typeof identityFederation?.execute !== "function" ||
    typeof scimAdapter?.apply !== "function" ||
    typeof resolveSyntheticAccount !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "Provisioning Ports are incomplete.");
  }
  const trustedContext = frozenClone(coreContext);

  return Object.freeze({
    async apply(input) {
      const command = normalizeInput(input);
      const mapping = normalizeMapping(
        await resolveSyntheticAccount({
          tenantId,
          providerConnectionId,
          fixtureUserId: command.fixtureUserId,
        }),
        {
          tenantId,
          providerConnectionId,
          fixtureUserId: command.fixtureUserId,
        },
      );
      const core = await identityFederation.execute(trustedContext, {
        kind: "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT",
        idempotencyKey: idempotencyKey(
          tenantId,
          providerConnectionId,
          command.sourceEventId,
        ),
        tenantId,
        providerConnectionId,
        fixtureUserId: command.fixtureUserId,
        sourceEventId: command.sourceEventId,
        sourceRevision: command.sourceRevision,
        desiredState: command.desiredState,
        correlationId: command.correlationId,
      });
      validateCoreResult(core, command.desiredState);
      if (core.stale === true) {
        return {
          core: structuredClone(core),
          scim: null,
        };
      }
      const scim = await scimAdapter.apply({
        externalId: mapping.directoryObjectId,
        userName: mapping.loginSubject,
        sourceRevision: command.sourceRevision,
        desiredState: command.desiredState,
        profile: mapping.profile,
      });
      validateScimResult(scim, mapping, command);
      return {
        core: structuredClone(core),
        scim: structuredClone(scim),
      };
    },
  });
}

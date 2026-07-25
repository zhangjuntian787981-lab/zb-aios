const CORE_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const ACCOUNT_STATES = new Set(["ACTIVE", "SUSPENDED", "TERMINATED"]);
const CHECKPOINT_STATUSES = new Set(["PENDING", "CONFIRMED"]);

export class KeycloakScimProvisioningError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "KeycloakScimProvisioningError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new KeycloakScimProvisioningError(code, message);
}

function exactKeys(value, allowed, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_INPUT", `${field} must be an object.`);
  }
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    fail("INVALID_INPUT", `${field} has unsupported fields.`);
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

function normalizeOrigin(value) {
  text(value, "origin", 512);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail("INVALID_CONFIGURATION", "SCIM origin is invalid.");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash ||
    value !== parsed.origin
  ) {
    fail(
      "INVALID_CONFIGURATION",
      "SCIM origin must be an exact HTTPS origin.",
    );
  }
  return parsed.origin;
}

function normalizeCommand(command) {
  exactKeys(
    command,
    [
      "externalId",
      "userName",
      "sourceRevision",
      "desiredState",
      "profile",
    ],
    "command",
  );
  text(
    command.externalId,
    "externalId",
    256,
    /^[A-Za-z0-9._:@/+~-]+$/,
  );
  text(command.userName, "userName", 128, /^[A-Za-z0-9._@+-]+$/);
  if (
    !Number.isSafeInteger(command.sourceRevision) ||
    command.sourceRevision < 1
  ) {
    fail("INVALID_INPUT", "sourceRevision must be a positive integer.");
  }
  if (!ACCOUNT_STATES.has(command.desiredState)) {
    fail("INVALID_INPUT", "desiredState is invalid.");
  }
  exactKeys(
    command.profile,
    ["givenName", "familyName", "email"],
    "command.profile",
  );
  text(command.profile.givenName, "profile.givenName", 128);
  text(command.profile.familyName, "profile.familyName", 128);
  text(
    command.profile.email,
    "profile.email",
    254,
    /^[^\s@]+@[^\s@]+$/,
  );
  return structuredClone(command);
}

function validateCheckpoint(value, externalId) {
  if (value === null) return;
  exactKeys(
    value,
    [
      "externalId",
      "userName",
      "sourceRevision",
      "desiredState",
      "profile",
      "status",
      "resourceId",
    ],
    "checkpoint",
  );
  if (
    value.externalId !== externalId ||
    typeof value.userName !== "string" ||
    !Number.isSafeInteger(value.sourceRevision) ||
    value.sourceRevision < 1 ||
    !ACCOUNT_STATES.has(value.desiredState) ||
    !CHECKPOINT_STATUSES.has(value.status) ||
    (value.resourceId !== null && typeof value.resourceId !== "string")
  ) {
    fail("CHECKPOINT_INVALID", "Provisioning checkpoint is invalid.");
  }
  exactKeys(
    value.profile,
    ["givenName", "familyName", "email"],
    "checkpoint.profile",
  );
}

function samePayload(checkpoint, command) {
  return (
    checkpoint.userName === command.userName &&
    checkpoint.desiredState === command.desiredState &&
    checkpoint.profile.givenName === command.profile.givenName &&
    checkpoint.profile.familyName === command.profile.familyName &&
    checkpoint.profile.email === command.profile.email
  );
}

function reserve(current, command) {
  validateCheckpoint(current, command.externalId);
  if (current?.userName && current.userName !== command.userName) {
    fail(
      "IDENTITY_BINDING_CONFLICT",
      "externalId cannot be rebound to another userName.",
    );
  }
  if (current && command.sourceRevision < current.sourceRevision) {
    return {
      next: current,
      value: { action: "NOOP", checkpoint: current, stale: true },
    };
  }
  if (current && command.sourceRevision === current.sourceRevision) {
    if (!samePayload(current, command)) {
      fail(
        "PROVISIONING_VERSION_CONFLICT",
        "sourceRevision is bound to different content.",
      );
    }
    return {
      next: current,
      value: {
        action: current.status === "CONFIRMED" ? "NOOP" : "APPLY",
        checkpoint: current,
        stale: false,
      },
    };
  }
  if (
    current?.desiredState === "TERMINATED" &&
    command.desiredState !== "TERMINATED"
  ) {
    fail(
      "TERMINATED_ACCOUNT",
      "A terminated account incarnation cannot be restored.",
    );
  }
  const next = {
    ...command,
    status: "PENDING",
    resourceId: current?.resourceId ?? null,
  };
  return {
    next,
    value: { action: "APPLY", checkpoint: next, stale: false },
  };
}

function confirm(current, command, resourceId) {
  validateCheckpoint(current, command.externalId);
  if (
    !current ||
    current.sourceRevision !== command.sourceRevision ||
    !samePayload(current, command)
  ) {
    fail(
      "PROVISIONING_SUPERSEDED",
      "Provisioning changed before confirmation.",
    );
  }
  return {
    next: { ...current, status: "CONFIRMED", resourceId },
    value: null,
  };
}

function parseJson(body, operation) {
  try {
    return JSON.parse(body);
  } catch {
    fail("SCIM_PROTOCOL_ERROR", `${operation} returned invalid JSON.`);
  }
}

function decodeTokenClaims(accessToken) {
  if (typeof accessToken !== "string" || accessToken.length > 20_000) {
    fail("TOKEN_INVALID", "SCIM access token is invalid.");
  }
  const parts = accessToken.split(".");
  if (parts.length !== 3) {
    fail("TOKEN_INVALID", "SCIM access token must be a JWT.");
  }
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    fail("TOKEN_INVALID", "SCIM access token claims are invalid.");
  }
}

function scimFilterValue(value) {
  return value.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

function userBody(command, resourceId) {
  return {
    schemas: [CORE_USER_SCHEMA],
    ...(resourceId ? { id: resourceId } : {}),
    userName: command.userName,
    externalId: command.externalId,
    name: {
      givenName: command.profile.givenName,
      familyName: command.profile.familyName,
    },
    emails: [
      {
        value: command.profile.email,
        type: "work",
        primary: true,
      },
    ],
    active: command.desiredState === "ACTIVE",
  };
}

function verifyUser(resource, command) {
  if (
    !resource ||
    typeof resource !== "object" ||
    typeof resource.id !== "string" ||
    resource.id.length === 0 ||
    resource.userName !== command.userName ||
    resource.externalId !== command.externalId ||
    resource.active !== (command.desiredState === "ACTIVE") ||
    resource.name?.givenName !== command.profile.givenName ||
    resource.name?.familyName !== command.profile.familyName ||
    resource.emails?.[0]?.value !== command.profile.email ||
    !resource.schemas?.includes(CORE_USER_SCHEMA)
  ) {
    fail(
      "SCIM_READBACK_MISMATCH",
      "SCIM readback did not match the requested account snapshot.",
    );
  }
  return resource;
}

export function createKeycloakScimProvisioningAdapter({
  origin,
  realm,
  audience,
  getAccessToken,
  request,
  checkpointStore,
}) {
  const exactOrigin = normalizeOrigin(origin);
  text(realm, "realm", 128, /^[A-Za-z0-9._-]+$/);
  const issuer = `${exactOrigin}/realms/${realm}`;
  const scimBase = `${issuer}/scim/v2`;
  if (audience !== scimBase) {
    fail(
      "INVALID_CONFIGURATION",
      "SCIM audience must exactly match the realm SCIM base URL.",
    );
  }
  if (
    typeof getAccessToken !== "function" ||
    typeof request !== "function" ||
    !checkpointStore ||
    typeof checkpointStore.transact !== "function" ||
    typeof checkpointStore.runExclusive !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "SCIM adapter Ports are incomplete.");
  }

  async function token() {
    let result;
    try {
      result = await getAccessToken({
        tokenEndpoint: `${issuer}/protocol/openid-connect/token`,
        audience,
      });
    } catch {
      fail("TOKEN_REQUEST_FAILED", "SCIM access token request failed.");
    }
    exactKeys(result, ["accessToken"], "token result");
    const claims = decodeTokenClaims(result.accessToken);
    const tokenAudiences = Array.isArray(claims.aud)
      ? claims.aud
      : [claims.aud];
    if (
      claims.iss !== issuer ||
      !tokenAudiences.includes(audience) ||
      !Number.isInteger(claims.exp) ||
      claims.exp * 1000 <= Date.now()
    ) {
      fail(
        "TOKEN_SCOPE_MISMATCH",
        "SCIM access token issuer, audience, or expiry is invalid.",
      );
    }
    return result.accessToken;
  }

  async function call(
    accessToken,
    path,
    { method = "GET", body, allowed = [200] } = {},
  ) {
    const target = new URL(path, `${scimBase}/`);
    if (
      target.origin !== exactOrigin ||
      !target.pathname.startsWith(`${new URL(scimBase).pathname}/`)
    ) {
      fail("NETWORK_BOUNDARY_VIOLATION", "SCIM request target is invalid.");
    }
    let response;
    try {
      response = await request({
        url: target.href,
        method,
        headers: {
          accept: "application/scim+json",
          authorization: `Bearer ${accessToken}`,
          ...(body === undefined
            ? {}
            : { "content-type": "application/scim+json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      fail("SCIM_TRANSPORT_FAILED", "SCIM transport request failed.");
    }
    if (
      !response ||
      typeof response.status !== "number" ||
      typeof response.body !== "string"
    ) {
      fail("SCIM_PROTOCOL_ERROR", "SCIM transport returned an invalid result.");
    }
    if (!allowed.includes(response.status)) {
      fail(
        response.status === 409
          ? "SCIM_UNIQUENESS_CONFLICT"
          : "SCIM_REQUEST_FAILED",
        `SCIM request failed with HTTP ${response.status}.`,
      );
    }
    return response.body ? parseJson(response.body, "SCIM request") : null;
  }

  async function findByExternalId(accessToken, externalId) {
    const filter = `externalId eq "${scimFilterValue(externalId)}"`;
    const query = new URLSearchParams({ filter, count: "2" });
    const result = await call(accessToken, `Users?${query}`);
    if (
      !result ||
      !Array.isArray(result.Resources) ||
      !Number.isInteger(result.totalResults)
    ) {
      fail("SCIM_PROTOCOL_ERROR", "SCIM search response is invalid.");
    }
    if (result.totalResults > 1 || result.Resources.length > 1) {
      fail(
        "SCIM_EXTERNAL_ID_CONFLICT",
        "SCIM externalId resolved to multiple users.",
      );
    }
    return result.Resources[0] ?? null;
  }

  async function readById(accessToken, resourceId) {
    text(resourceId, "resourceId", 128, /^[A-Za-z0-9._~-]+$/);
    return call(accessToken, `Users/${encodeURIComponent(resourceId)}`);
  }

  async function upsert(accessToken, command) {
    let current = await findByExternalId(accessToken, command.externalId);
    if (current && current.userName !== command.userName) {
      fail(
        "IDENTITY_BINDING_CONFLICT",
        "SCIM externalId is bound to another userName.",
      );
    }
    if (!current) {
      try {
        current = await call(accessToken, "Users", {
          method: "POST",
          body: userBody(command),
          allowed: [201],
        });
      } catch (error) {
        if (error?.code !== "SCIM_UNIQUENESS_CONFLICT") throw error;
        current = await findByExternalId(accessToken, command.externalId);
        if (!current) throw error;
      }
    }
    if (current.userName !== command.userName) {
      fail(
        "IDENTITY_BINDING_CONFLICT",
        "SCIM externalId is bound to another userName.",
      );
    }
    await call(accessToken, `Users/${encodeURIComponent(current.id)}`, {
      method: "PUT",
      body: userBody(command, current.id),
    });
    return verifyUser(
      await readById(accessToken, current.id),
      command,
    );
  }

  return Object.freeze({
    async apply(input) {
      const command = normalizeCommand(input);
      return checkpointStore.runExclusive(
        command.externalId,
        async () => {
          const reservation = await checkpointStore.transact(
            command.externalId,
            (current) => reserve(current, command),
          );
          if (
            !reservation ||
            !["APPLY", "NOOP"].includes(reservation.action)
          ) {
            fail(
              "CHECKPOINT_INVALID",
              "Provisioning checkpoint reservation is invalid.",
            );
          }
          validateCheckpoint(reservation.checkpoint, command.externalId);
          const accessToken = await token();
          if (reservation.action === "NOOP") {
            const remote = await findByExternalId(
              accessToken,
              command.externalId,
            );
            if (!remote) {
              fail(
                "SCIM_READBACK_MISMATCH",
                "Checkpointed SCIM user no longer exists.",
              );
            }
            verifyUser(remote, reservation.checkpoint);
            return {
              externalId: command.externalId,
              resourceId: remote.id,
              sourceRevision: reservation.checkpoint.sourceRevision,
              state: reservation.checkpoint.desiredState,
              applied: false,
              stale: reservation.stale === true,
            };
          }
          const remote = await upsert(accessToken, command);
          await checkpointStore.transact(
            command.externalId,
            (current) => confirm(current, command, remote.id),
          );
          return {
            externalId: command.externalId,
            resourceId: remote.id,
            sourceRevision: command.sourceRevision,
            state: command.desiredState,
            applied: true,
            stale: false,
          };
        },
      );
    },
  });
}

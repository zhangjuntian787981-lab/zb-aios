const SHA256 = /^sha256:[a-f0-9]{64}$/;
const UUID_V7 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7.source.slice(1, -1)}$`);
const REFERENCE = /^(?:fixture|policy|profile|synthetic|test):\/\/\S+$/;
const SECRET = /^[A-Za-z0-9._~-]{43,128}$/;
const ACCOUNT_STATES = ["ACTIVE", "SUSPENDED", "TERMINATED"];
const TENANT_STATES = [
  "PROVISIONING",
  "ACTIVE",
  "SUSPENDED",
  "DELETING",
  "DELETED",
];
const PROJECT = "IDENTITY_TENANT_PROJECT";
const PROVISION = "IDENTITY_PROVISIONING_APPLY";
const ROTATE = "IDENTITY_PROVIDER_ROTATE";
const REVOKE = "IDENTITY_SESSION_REVOKE";
const READ = "IDENTITY_READ";

export class IdentityFederationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "IdentityFederationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new IdentityFederationError(code, message);
}

function exactKeys(value, allowed, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_COMMAND", `${field} must be an object.`);
  }
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    fail("INVALID_COMMAND", `${field} has unsupported fields.`);
  }
}

function nonEmptyString(value, field, maxLength = 256) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength
  ) {
    fail("INVALID_COMMAND", `${field} is invalid.`);
  }
}

function reference(value, field) {
  nonEmptyString(value, field, 512);
  if (!REFERENCE.test(value)) {
    fail(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      `${field} must use a P1 synthetic reference.`,
    );
  }
}

function syntheticTenantId(value) {
  nonEmptyString(value, "tenantId", 80);
  if (!SYNTHETIC_TENANT_ID.test(value)) {
    fail(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      "P1 identity accepts only Synthetic Tenant IDs.",
    );
  }
}

function positiveInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 1) {
    fail("INVALID_COMMAND", `${field} must be a positive integer.`);
  }
}

function keyIds(value, field) {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > 32 ||
    new Set(value).size !== value.length ||
    value.some(
      (keyId) =>
        typeof keyId !== "string" ||
        keyId.length === 0 ||
        keyId.length > 128 ||
        !/^[A-Za-z0-9._~:-]+$/.test(keyId),
    )
  ) {
    fail("INVALID_COMMAND", `${field} is invalid.`);
  }
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("INVALID_COMMAND", "Invalid number.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  fail("INVALID_COMMAND", "Only JSON values are supported.");
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(
    typeof value === "string" ? value : canonicalize(value),
  );
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return `sha256:${Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")}`;
}

function base64Url(bytes) {
  const binary = Array.from(bytes, (byte) =>
    String.fromCharCode(byte),
  ).join("");
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

async function pkceChallenge(verifier) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return base64Url(new Uint8Array(digest));
}

function uuidV7() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let milliseconds = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(milliseconds & 0xffn);
    milliseconds >>= 8n;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join("-");
}

function randomSecret() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

function isoMillis(value, field) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    fail("INVALID_COMMAND", `${field} must be an ISO date-time.`);
  }
  return milliseconds;
}

function safeClone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function createMemoryTransaction(draft) {
  function providerConfigurationKey(providerConnectionId, version) {
    return `${providerConnectionId}\u0000${version}`;
  }

  function accountKey(tenantId, providerConnectionId, directoryObjectId) {
    return `${tenantId}\u0000${providerConnectionId}\u0000${directoryObjectId}`;
  }

  function subjectKey(tenantId, providerConnectionId, issuer, subject) {
    return `${tenantId}\u0000${providerConnectionId}\u0000${issuer}\u0000${subject}`;
  }

  return Object.freeze({
    loadProjectionForUpdate(tenantId) {
      return safeClone(draft.projections.get(tenantId) ?? null);
    },
    putProjection(value) {
      const current = draft.projections.get(value.tenantId);
      if (
        current &&
        (current.tenantKind !== value.tenantKind ||
          current.fixtureRef.fixtureId !== value.fixtureRef.fixtureId ||
          current.fixtureRef.sha256 !== value.fixtureRef.sha256 ||
          current.providerConnectionId !== value.providerConnectionId)
      ) {
        fail(
          "SYNTHETIC_BOUNDARY_VIOLATION",
          "Tenant identity projection bindings are immutable.",
        );
      }
      draft.projections.set(value.tenantId, safeClone(value));
    },
    loadProvider(providerConnectionId) {
      return safeClone(draft.providers.get(providerConnectionId) ?? null);
    },
    putProvider(value) {
      const current = draft.providers.get(value.providerConnectionId);
      if (
        current &&
        (current.tenantId !== value.tenantId ||
          current.protocol !== value.protocol ||
          current.issuer !== value.issuer ||
          current.clientId !== value.clientId ||
          current.configurationVersion !== value.configurationVersion ||
          canonicalize(current.redirectRoutes) !==
            canonicalize(value.redirectRoutes) ||
          canonicalize(current.allowedAlgorithms) !==
            canonicalize(value.allowedAlgorithms) ||
          canonicalize(current.allowedKeyIds) !==
            canonicalize(value.allowedKeyIds) ||
          canonicalize(current.requiredAuthenticationMethods) !==
            canonicalize(value.requiredAuthenticationMethods) ||
          current.maxAuthenticationAgeSeconds !==
            value.maxAuthenticationAgeSeconds ||
          canonicalize(current.upstreamProtocols) !==
            canonicalize(value.upstreamProtocols))
      ) {
        fail(
          "PROVIDER_BINDING_IMMUTABLE",
          "Provider identity and configuration version are immutable.",
        );
      }
      if (!current) {
        const configuration = {
          providerConnectionId: value.providerConnectionId,
          tenantId: value.tenantId,
          configurationVersion: value.configurationVersion,
          redirectRoutes: safeClone(value.redirectRoutes),
          allowedAlgorithms: safeClone(value.allowedAlgorithms),
          allowedKeyIds: safeClone(value.allowedKeyIds),
          requiredAuthenticationMethods: safeClone(
            value.requiredAuthenticationMethods,
          ),
          maxAuthenticationAgeSeconds: value.maxAuthenticationAgeSeconds,
          upstreamProtocols: safeClone(value.upstreamProtocols),
          state: "CURRENT",
          activatedAt: value.createdAt,
          graceUntil: null,
          retiredAt: null,
          retirementMode: null,
        };
        draft.providerConfigurations.set(
          providerConfigurationKey(
            value.providerConnectionId,
            value.configurationVersion,
          ),
          configuration,
        );
        draft.providers.set(value.providerConnectionId, {
          ...safeClone(value),
          configurationState: "CURRENT",
          activatedAt: value.createdAt,
          graceUntil: null,
          retiredAt: null,
          retirementMode: null,
        });
        return;
      }
      draft.providers.set(value.providerConnectionId, {
        ...safeClone(current),
        status: value.status,
        updatedAt: value.updatedAt,
      });
    },
    loadProviderConfiguration(providerConnectionId, configurationVersion) {
      const provider = draft.providers.get(providerConnectionId);
      const configuration = draft.providerConfigurations.get(
        providerConfigurationKey(
          providerConnectionId,
          configurationVersion,
        ),
      );
      return provider && configuration
        ? safeClone({ ...provider, ...configuration })
        : null;
    },
    rotateProviderConfiguration({
      providerConnectionId,
      expectedVersion,
      nextConfiguration,
      graceUntil,
      emergency,
      updatedAt,
    }) {
      const provider = draft.providers.get(providerConnectionId);
      const currentKey = providerConfigurationKey(
        providerConnectionId,
        expectedVersion,
      );
      const current = draft.providerConfigurations.get(currentKey);
      const nextKey = providerConfigurationKey(
        providerConnectionId,
        nextConfiguration.configurationVersion,
      );
      if (
        !provider ||
        provider.configurationVersion !== expectedVersion ||
        current?.state !== "CURRENT" ||
        draft.providerConfigurations.has(nextKey)
      ) {
        fail(
          "PROVIDER_CONFIGURATION_CONFLICT",
          "Provider configuration changed concurrently.",
        );
      }
      if (emergency) {
        for (const [key, configuration] of draft.providerConfigurations) {
          if (
            configuration.providerConnectionId === providerConnectionId &&
            ["CURRENT", "GRACE"].includes(configuration.state)
          ) {
            draft.providerConfigurations.set(key, {
              ...configuration,
              state: "RETIRED",
              retiredAt: updatedAt,
              retirementMode: "EMERGENCY",
            });
          }
        }
      } else {
        draft.providerConfigurations.set(currentKey, {
          ...current,
          state: "GRACE",
          graceUntil,
          retiredAt: null,
          retirementMode: null,
        });
      }
      draft.providerConfigurations.set(
        nextKey,
        safeClone(nextConfiguration),
      );
      draft.providers.set(providerConnectionId, {
        ...provider,
        ...safeClone(nextConfiguration),
        configurationState: "CURRENT",
        updatedAt,
      });
    },
    retireProviderConfiguration({
      providerConnectionId,
      configurationVersion,
      retiredAt,
    }) {
      const key = providerConfigurationKey(
        providerConnectionId,
        configurationVersion,
      );
      const configuration = draft.providerConfigurations.get(key);
      if (!configuration || configuration.state !== "GRACE") {
        fail(
          "PROVIDER_CONFIGURATION_CONFLICT",
          "Only a grace configuration can be retired.",
        );
      }
      if (
        isoMillis(retiredAt, "retiredAt") <
        isoMillis(configuration.graceUntil, "provider.graceUntil")
      ) {
        fail(
          "PROVIDER_CONFIGURATION_CONFLICT",
          "A grace configuration cannot be retired before grace expires.",
        );
      }
      draft.providerConfigurations.set(key, {
        ...configuration,
        state: "RETIRED",
        retiredAt,
        retirementMode: "NORMAL",
      });
    },
    findAccountByDirectory(
      tenantId,
      providerConnectionId,
      directoryObjectId,
    ) {
      const accountId = draft.accountByDirectory.get(
        accountKey(tenantId, providerConnectionId, directoryObjectId),
      );
      return safeClone(draft.accounts.get(accountId) ?? null);
    },
    findAccountBySubject(tenantId, providerConnectionId, issuer, subject) {
      const accountId = draft.accountBySubject.get(
        subjectKey(tenantId, providerConnectionId, issuer, subject),
      );
      return safeClone(draft.accounts.get(accountId) ?? null);
    },
    loadAccountForUpdate(accountId) {
      return safeClone(draft.accounts.get(accountId) ?? null);
    },
    putAccount(value) {
      const current = draft.accounts.get(value.accountId);
      if (
        current &&
        (current.tenantId !== value.tenantId ||
          current.providerConnectionId !== value.providerConnectionId ||
          current.issuer !== value.issuer ||
          current.subject !== value.subject ||
          current.directoryObjectId !== value.directoryObjectId ||
          current.incarnation !== value.incarnation)
      ) {
        fail(
          "ACCOUNT_BINDING_IMMUTABLE",
          "Federation and provisioning bindings are immutable.",
        );
      }
      if (current?.state === "TERMINATED" && value.state !== "TERMINATED") {
        fail(
          "TERMINATED_ACCOUNT",
          "A terminated account incarnation cannot be restored.",
        );
      }

      const directoryKey = accountKey(
        value.tenantId,
        value.providerConnectionId,
        value.directoryObjectId,
      );
      const loginKey = subjectKey(
        value.tenantId,
        value.providerConnectionId,
        value.issuer,
        value.subject,
      );
      const directoryOwner = draft.accountByDirectory.get(directoryKey);
      const subjectOwner = draft.accountBySubject.get(loginKey);
      if (
        (directoryOwner && directoryOwner !== value.accountId) ||
        (subjectOwner && subjectOwner !== value.accountId)
      ) {
        fail(
          "IDENTITY_BINDING_CONFLICT",
          "Synthetic identity is already bound to another account.",
        );
      }
      draft.accounts.set(value.accountId, safeClone(value));
      draft.accountByDirectory.set(directoryKey, value.accountId);
      draft.accountBySubject.set(loginKey, value.accountId);
    },
    listAccounts(tenantId) {
      return Array.from(draft.accounts.values())
        .filter((account) => account.tenantId === tenantId)
        .map(safeClone);
    },
    loadSourceReceipt(tenantId, sourceEventId) {
      return safeClone(
        draft.sourceReceipts.get(`${tenantId}\u0000${sourceEventId}`) ?? null,
      );
    },
    putSourceReceipt(tenantId, sourceEventId, value) {
      const key = `${tenantId}\u0000${sourceEventId}`;
      if (draft.sourceReceipts.has(key)) {
        fail("IDEMPOTENCY_CONFLICT", "Source event receipt already exists.");
      }
      draft.sourceReceipts.set(key, safeClone(value));
    },
    insertLoginTransaction(value) {
      if (draft.loginTransactions.has(value.transactionId)) {
        fail("ID_COLLISION", "Login transaction ID already exists.");
      }
      const configuration = draft.providerConfigurations.get(
        providerConfigurationKey(
          value.providerConnectionId,
          value.providerConfigurationVersion,
        ),
      );
      if (configuration?.state !== "CURRENT") {
        fail(
          "PROVIDER_CONFIGURATION_CONFLICT",
          "New logins require the current provider configuration.",
        );
      }
      draft.loginTransactions.set(value.transactionId, safeClone(value));
    },
    loadLoginTransactionForUpdate(transactionId) {
      return safeClone(draft.loginTransactions.get(transactionId) ?? null);
    },
    putLoginTransaction(value) {
      const current = draft.loginTransactions.get(value.transactionId);
      if (
        !current ||
        current.tenantId !== value.tenantId ||
        current.providerConnectionId !== value.providerConnectionId ||
        current.providerConfigurationVersion !==
          value.providerConfigurationVersion ||
        current.stateHash !== value.stateHash ||
        current.nonceHash !== value.nonceHash ||
        current.pkceVerifierHash !== value.pkceVerifierHash ||
        current.redirectUri !== value.redirectUri
      ) {
        fail(
          "LOGIN_TRANSACTION_INVALID",
          "Login transaction bindings are immutable.",
        );
      }
      draft.loginTransactions.set(value.transactionId, safeClone(value));
    },
    insertSession(value) {
      if (
        draft.sessions.has(value.sessionId) ||
        draft.sessionByTokenHash.has(value.tokenHash)
      ) {
        fail("ID_COLLISION", "Session identifier already exists.");
      }
      draft.sessions.set(value.sessionId, safeClone(value));
      draft.sessionByTokenHash.set(value.tokenHash, value.sessionId);
    },
    loadSessionByIdForUpdate(sessionId) {
      return safeClone(draft.sessions.get(sessionId) ?? null);
    },
    putSession(value) {
      const current = draft.sessions.get(value.sessionId);
      if (
        !current ||
        current.tenantId !== value.tenantId ||
        current.accountId !== value.accountId ||
        current.providerConfigurationVersion !==
          value.providerConfigurationVersion ||
        current.tokenHash !== value.tokenHash ||
        (current.status === "REVOKED" && value.status !== "REVOKED")
      ) {
        fail("SESSION_INVALID", "Session identity is immutable.");
      }
      draft.sessions.set(value.sessionId, safeClone(value));
    },
    revokeSessionsForAccount(accountId, revokedAt) {
      for (const session of draft.sessions.values()) {
        if (session.accountId === accountId && session.status === "ACTIVE") {
          session.status = "REVOKED";
          session.revokedAt = revokedAt;
        }
      }
    },
    revokeSessionsForTenant(tenantId, revokedAt) {
      for (const session of draft.sessions.values()) {
        if (session.tenantId === tenantId && session.status === "ACTIVE") {
          session.status = "REVOKED";
          session.revokedAt = revokedAt;
        }
      }
    },
    appendEvent(event) {
      if (draft.events.some(({ id }) => id === event.id)) {
        fail("ID_COLLISION", "Identity event ID already exists.");
      }
      draft.events.push(safeClone(event));
    },
    appendOutbox(event) {
      if (draft.outbox.some(({ id }) => id === event.id)) {
        fail("ID_COLLISION", "Identity outbox ID already exists.");
      }
      draft.outbox.push(safeClone(event));
    },
  });
}

export function createMemoryIdentityStore() {
  let state = {
    projections: new Map(),
    providers: new Map(),
    providerConfigurations: new Map(),
    accounts: new Map(),
    accountByDirectory: new Map(),
    accountBySubject: new Map(),
    sourceReceipts: new Map(),
    loginTransactions: new Map(),
    sessions: new Map(),
    sessionByTokenHash: new Map(),
    events: [],
    outbox: [],
    commandReceipts: new Map(),
  };
  let queue = Promise.resolve();

  function serial(work) {
    const result = queue.then(work, work);
    queue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  return Object.freeze({
    runCommand({ idempotencyKey, commandHash }, reducer) {
      return serial(async () => {
        const receipt = state.commandReceipts.get(idempotencyKey);
        if (receipt) {
          if (receipt.commandHash !== commandHash) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "The idempotency key was used for another identity command.",
            );
          }
          return { duplicate: true, value: safeClone(receipt.value) };
        }
        const draft = structuredClone(state);
        const value = await reducer(createMemoryTransaction(draft));
        draft.commandReceipts.set(idempotencyKey, {
          commandHash,
          value: safeClone(value),
        });
        state = draft;
        return { duplicate: false, value: safeClone(value) };
      });
    },
    transact(reducer) {
      return serial(async () => {
        const draft = structuredClone(state);
        const value = await reducer(createMemoryTransaction(draft));
        state = draft;
        return safeClone(value);
      });
    },
    async readTenantSnapshot(tenantId) {
      await queue;
      const projection = state.projections.get(tenantId);
      if (!projection) return null;
      const provider = state.providers.get(projection.providerConnectionId);
      return safeClone({
        projection,
        provider,
        accounts: Array.from(state.accounts.values()).filter(
          (account) => account.tenantId === tenantId,
        ),
        sessions: Array.from(state.sessions.values()).filter(
          (session) => session.tenantId === tenantId,
        ),
        events: state.events.filter(
          ({ data }) => data?.tenant_id === tenantId,
        ),
        outbox: state.outbox.filter(
          ({ data }) => data?.tenant_id === tenantId,
        ),
      });
    },
    async readSessionSnapshot(tokenHash) {
      await queue;
      const sessionId = state.sessionByTokenHash.get(tokenHash);
      const session = state.sessions.get(sessionId);
      if (!session) return null;
      const account = state.accounts.get(session.accountId);
      const projection = state.projections.get(session.tenantId);
      const provider = projection
        ? state.providers.get(projection.providerConnectionId)
        : null;
      return safeClone({ session, account, projection, provider });
    },
  });
}

function validateFixtureRef(value) {
  exactKeys(value, ["fixtureId", "sha256"], "fixtureRef");
  nonEmptyString(value.fixtureId, "fixtureRef.fixtureId", 128);
  if (!SHA256.test(value.sha256 ?? "")) {
    fail("INVALID_COMMAND", "fixtureRef.sha256 is invalid.");
  }
}

function syntheticHttpsUrl(value, field) {
  nonEmptyString(value, field, 512);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail("INVALID_IDENTITY_CATALOG", `${field} must be a URL.`);
  }
  if (
    parsed.protocol !== "https:" ||
    !parsed.hostname.endsWith(".example") ||
    parsed.username ||
    parsed.password
  ) {
    fail(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      `${field} must use a credential-free .example HTTPS URL.`,
    );
  }
  return parsed;
}

export function createSyntheticIdentityCatalog(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    fail(
      "INVALID_IDENTITY_CATALOG",
      "At least one synthetic identity fixture is required.",
    );
  }
  const fixtures = new Map();
  for (const entry of entries) {
    exactKeys(entry, ["fixtureId", "sha256", "provider", "users"], "catalog");
    validateFixtureRef({
      fixtureId: entry.fixtureId,
      sha256: entry.sha256,
    });
    exactKeys(
      entry.provider,
      [
        "issuer",
        "clientId",
        "redirectRoutes",
        "configurationVersion",
        "allowedAlgorithms",
        "allowedKeyIds",
        "requiredAuthenticationMethods",
        "maxAuthenticationAgeSeconds",
        "upstreamProtocols",
      ],
      "provider",
    );
    syntheticHttpsUrl(entry.provider.issuer, "provider.issuer");
    nonEmptyString(entry.provider.clientId, "provider.clientId", 128);
    positiveInteger(
      entry.provider.configurationVersion,
      "provider.configurationVersion",
    );
    if (entry.provider.configurationVersion !== 1) {
      fail(
        "INVALID_IDENTITY_CATALOG",
        "A synthetic provider must start at configuration version one.",
      );
    }
    positiveInteger(
      entry.provider.maxAuthenticationAgeSeconds,
      "provider.maxAuthenticationAgeSeconds",
    );
    if (
      !entry.provider.redirectRoutes ||
      typeof entry.provider.redirectRoutes !== "object" ||
      Array.isArray(entry.provider.redirectRoutes) ||
      Object.keys(entry.provider.redirectRoutes).length === 0
    ) {
      fail(
        "INVALID_IDENTITY_CATALOG",
        "Provider redirect routes are required.",
      );
    }
    for (const [route, redirectUri] of Object.entries(
      entry.provider.redirectRoutes,
    )) {
      nonEmptyString(route, "provider redirect route", 64);
      syntheticHttpsUrl(redirectUri, `redirectRoutes.${route}`);
    }
    for (const [field, values] of [
      ["allowedAlgorithms", entry.provider.allowedAlgorithms],
      ["allowedKeyIds", entry.provider.allowedKeyIds],
      [
        "requiredAuthenticationMethods",
        entry.provider.requiredAuthenticationMethods,
      ],
      ["upstreamProtocols", entry.provider.upstreamProtocols],
    ]) {
      if (
        !Array.isArray(values) ||
        values.length === 0 ||
        values.some((value) => typeof value !== "string" || !value)
      ) {
        fail("INVALID_IDENTITY_CATALOG", `provider.${field} is invalid.`);
      }
    }
    if (
      !entry.provider.upstreamProtocols.every((protocol) =>
        ["OIDC", "SAML"].includes(protocol),
      )
    ) {
      fail("INVALID_IDENTITY_CATALOG", "Unknown upstream protocol.");
    }
    if (!Array.isArray(entry.users) || entry.users.length === 0) {
      fail("INVALID_IDENTITY_CATALOG", "Synthetic users are required.");
    }
    const users = new Map();
    for (const user of entry.users) {
      exactKeys(
        user,
        ["fixtureUserId", "directoryObjectId", "loginSubject", "profileRef"],
        "synthetic user",
      );
      nonEmptyString(user.fixtureUserId, "fixtureUserId", 128);
      nonEmptyString(user.directoryObjectId, "directoryObjectId", 128);
      nonEmptyString(user.loginSubject, "loginSubject", 255);
      reference(user.profileRef, "profileRef");
      if (users.has(user.fixtureUserId)) {
        fail("INVALID_IDENTITY_CATALOG", "Fixture user IDs must be unique.");
      }
      users.set(user.fixtureUserId, safeClone(user));
    }
    if (fixtures.has(entry.fixtureId)) {
      fail("INVALID_IDENTITY_CATALOG", "Fixture IDs must be unique.");
    }
    fixtures.set(entry.fixtureId, {
      sha256: entry.sha256,
      provider: safeClone(entry.provider),
      users,
    });
  }

  function fixture(fixtureRef) {
    validateFixtureRef(fixtureRef);
    const value = fixtures.get(fixtureRef.fixtureId);
    if (value?.sha256 !== fixtureRef.sha256) {
      fail(
        "UNKNOWN_SYNTHETIC_IDENTITY_FIXTURE",
        "Identity fixture is not in the frozen catalog.",
      );
    }
    return value;
  }

  return Object.freeze({
    resolveFixture(fixtureRef) {
      const value = fixture(fixtureRef);
      return {
        fixtureRef: safeClone(fixtureRef),
        provider: safeClone(value.provider),
      };
    },
    resolveUser(fixtureRef, fixtureUserId) {
      nonEmptyString(fixtureUserId, "fixtureUserId", 128);
      const user = fixture(fixtureRef).users.get(fixtureUserId);
      if (!user) {
        fail(
          "UNKNOWN_SYNTHETIC_IDENTITY",
          "User is not in the frozen synthetic identity catalog.",
        );
      }
      return safeClone(user);
    },
  });
}

function validateCommon(command) {
  nonEmptyString(command.idempotencyKey, "idempotencyKey", 128);
  nonEmptyString(command.correlationId, "correlationId", 128);
}

function validateCommand(command) {
  if (command?.kind === "APPLY_TENANT_LIFECYCLE_EVENT") {
    exactKeys(
      command,
      [
        "kind",
        "idempotencyKey",
        "tenantId",
        "sourceEventId",
        "sourceLifecycleVersion",
        "sourceGeneration",
        "sourceOperationId",
        "sourceState",
        "correlationId",
      ],
      "command",
    );
    validateCommon(command);
    syntheticTenantId(command.tenantId);
    nonEmptyString(command.sourceEventId, "sourceEventId", 128);
    positiveInteger(
      command.sourceLifecycleVersion,
      "sourceLifecycleVersion",
    );
    positiveInteger(command.sourceGeneration, "sourceGeneration");
    nonEmptyString(command.sourceOperationId, "sourceOperationId", 80);
    if (!TENANT_STATES.includes(command.sourceState)) {
      fail("INVALID_COMMAND", "Unknown source Tenant state.");
    }
    return;
  }
  if (command?.kind === "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT") {
    exactKeys(
      command,
      [
        "kind",
        "idempotencyKey",
        "tenantId",
        "providerConnectionId",
        "fixtureUserId",
        "sourceEventId",
        "sourceRevision",
        "desiredState",
        "correlationId",
      ],
      "command",
    );
    validateCommon(command);
    syntheticTenantId(command.tenantId);
    nonEmptyString(
      command.providerConnectionId,
      "providerConnectionId",
      80,
    );
    nonEmptyString(command.fixtureUserId, "fixtureUserId", 128);
    nonEmptyString(command.sourceEventId, "sourceEventId", 128);
    positiveInteger(command.sourceRevision, "sourceRevision");
    if (!ACCOUNT_STATES.includes(command.desiredState)) {
      fail("INVALID_COMMAND", "Unknown desired account state.");
    }
    return;
  }
  if (command?.kind === "ROTATE_SYNTHETIC_PROVIDER_KEYS") {
    exactKeys(
      command,
      [
        "kind",
        "idempotencyKey",
        "tenantId",
        "providerConnectionId",
        "expectedConfigurationVersion",
        "allowedKeyIds",
        "emergency",
        "correlationId",
      ],
      "command",
    );
    validateCommon(command);
    syntheticTenantId(command.tenantId);
    nonEmptyString(
      command.providerConnectionId,
      "providerConnectionId",
      80,
    );
    positiveInteger(
      command.expectedConfigurationVersion,
      "expectedConfigurationVersion",
    );
    keyIds(command.allowedKeyIds, "allowedKeyIds");
    if (typeof command.emergency !== "boolean") {
      fail("INVALID_COMMAND", "emergency must be a boolean.");
    }
    return;
  }
  if (command?.kind === "RETIRE_SYNTHETIC_PROVIDER_CONFIGURATION") {
    exactKeys(
      command,
      [
        "kind",
        "idempotencyKey",
        "tenantId",
        "providerConnectionId",
        "configurationVersion",
        "correlationId",
      ],
      "command",
    );
    validateCommon(command);
    syntheticTenantId(command.tenantId);
    nonEmptyString(
      command.providerConnectionId,
      "providerConnectionId",
      80,
    );
    positiveInteger(
      command.configurationVersion,
      "configurationVersion",
    );
    return;
  }
  if (command?.kind === "REVOKE_SESSION") {
    exactKeys(
      command,
      [
        "kind",
        "idempotencyKey",
        "tenantId",
        "sessionId",
        "reasonRef",
        "correlationId",
      ],
      "command",
    );
    validateCommon(command);
    syntheticTenantId(command.tenantId);
    nonEmptyString(command.sessionId, "sessionId", 80);
    reference(command.reasonRef, "reasonRef");
    return;
  }
  if (command?.kind === "CREATE_ENTERPRISE_IDENTITY") {
    fail("P3_REQUIRED", "Enterprise identity onboarding is disabled before P3.");
  }
  fail("INVALID_COMMAND", "Unknown identity command.");
}

function capabilityFor(command) {
  if (command.kind === "APPLY_TENANT_LIFECYCLE_EVENT") return PROJECT;
  if (command.kind === "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT") return PROVISION;
  if (
    command.kind === "ROTATE_SYNTHETIC_PROVIDER_KEYS" ||
    command.kind === "RETIRE_SYNTHETIC_PROVIDER_CONFIGURATION"
  ) {
    return ROTATE;
  }
  return REVOKE;
}

function safeProvider(provider) {
  return {
    providerConnectionId: provider.providerConnectionId,
    protocol: provider.protocol,
    issuer: provider.issuer,
    clientId: provider.clientId,
    policy: provider.policy,
    configurationVersion: provider.configurationVersion,
    configurationState: provider.configurationState ?? "CURRENT",
    status: provider.status,
    upstreamProtocols: safeClone(provider.upstreamProtocols),
  };
}

function safeAccount(account) {
  return {
    accountId: account.accountId,
    tenantId: account.tenantId,
    providerConnectionId: account.providerConnectionId,
    state: account.state,
    lifecycleVersion: account.lifecycleVersion,
    sourceRevision: account.sourceRevision,
    revocationEpoch: account.revocationEpoch,
    incarnation: account.incarnation,
    profileRef: account.profileRef,
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
  };
}

export function createIdentityFederation({
  store,
  tenantRegistry,
  tenantRegistryContext,
  identityCatalog,
  authorize,
  federationBroker,
  clock = () => new Date().toISOString(),
  idFactory = uuidV7,
  secretFactory = randomSecret,
  loginTtlSeconds = 300,
  sessionTtlSeconds = 3600,
}) {
  if (
    !store?.runCommand ||
    !store?.transact ||
    !store?.readTenantSnapshot ||
    !store?.readSessionSnapshot
  ) {
    fail("INVALID_STORE", "Identity Store is required.");
  }
  if (!tenantRegistry?.snapshot || !tenantRegistry?.admitNewRequest) {
    fail("INVALID_TENANT_REGISTRY", "Tenant Registry port is required.");
  }
  if (!tenantRegistryContext || typeof tenantRegistryContext !== "object") {
    fail(
      "INVALID_TENANT_REGISTRY",
      "A trusted Tenant Registry reader context is required.",
    );
  }
  if (!identityCatalog?.resolveFixture || !identityCatalog?.resolveUser) {
    fail("INVALID_IDENTITY_CATALOG", "Synthetic identity catalog is required.");
  }
  if (typeof authorize !== "function") {
    fail("INVALID_AUTHORIZER", "A fail-closed authorizer is required.");
  }
  if (
    !federationBroker?.startAuthorization ||
    !federationBroker?.exchangeAndVerify
  ) {
    fail("INVALID_FEDERATION_BROKER", "Federation Broker port is required.");
  }
  for (const [field, value, maximum] of [
    ["loginTtlSeconds", loginTtlSeconds, 900],
    ["sessionTtlSeconds", sessionTtlSeconds, 86400],
  ]) {
    if (!Number.isSafeInteger(value) || value < 60 || value > maximum) {
      fail("INVALID_CONFIGURATION", `${field} is outside its safe range.`);
    }
  }

  function newUuid() {
    const value = idFactory();
    if (!UUID_V7.test(value)) {
      fail("INVALID_ID_FACTORY", "ID factory must return a UUIDv7.");
    }
    return value;
  }

  function newSecret() {
    const value = secretFactory();
    if (!SECRET.test(value)) {
      fail(
        "INVALID_SECRET_FACTORY",
        "Secret factory must return at least 256 bits of URL-safe entropy.",
      );
    }
    return value;
  }

  function now() {
    const value = clock();
    isoMillis(value, "clock");
    return value;
  }

  async function isAuthorized(context, capability) {
    try {
      return (await authorize(context, capability)) === true;
    } catch {
      return false;
    }
  }

  function identityEvent({
    subject,
    tenantId,
    correlationId,
    type,
    actorId,
    data,
  }) {
    return {
      specversion: "1.0",
      id: `evt_${newUuid()}`,
      source: "/aios-core/identity-federation",
      type,
      subject,
      time: now(),
      datacontenttype: "application/json",
      tenantkind: "SYNTHETIC",
      correlationid: correlationId,
      synthetic: true,
      data: {
        tenant_id: tenantId,
        actor_id: actorId,
        authorization_status: "NOT_EVALUATED",
        ...data,
      },
    };
  }

  async function c03Snapshot(tenantId) {
    let value;
    try {
      value = await tenantRegistry.snapshot(
        tenantRegistryContext,
        tenantId,
      );
    } catch {
      fail("TENANT_UNAVAILABLE", "Tenant lifecycle verification failed.");
    }
    if (
      value?.tenantKind !== "SYNTHETIC" ||
      value.synthetic !== true ||
      value.tenantId !== tenantId
    ) {
      fail(
        "SYNTHETIC_BOUNDARY_VIOLATION",
        "Tenant lifecycle context is not synthetic.",
      );
    }
    return value;
  }

  async function admitTenant(serverContext, tenantId) {
    if (serverContext?.synthetic !== true) {
      fail("TENANT_NOT_ACTIVE", "Tenant admission failed closed.");
    }
    let value;
    try {
      value = await tenantRegistry.admitNewRequest({
        tenantId,
        expectedTenantKind: "SYNTHETIC",
      });
    } catch {
      fail("TENANT_NOT_ACTIVE", "Tenant is not accepting identity requests.");
    }
    if (
      value?.tenantId !== tenantId ||
      value.tenantKind !== "SYNTHETIC" ||
      value.trustSource !== "VERIFIED_SERVER_CONTEXT"
    ) {
      fail("TENANT_NOT_ACTIVE", "Tenant admission failed closed.");
    }
    return value;
  }

  async function applyTenantLifecycle(
    tx,
    context,
    command,
    sourceHash,
    tenant,
  ) {
    const receipt = await tx.loadSourceReceipt(
      command.tenantId,
      command.sourceEventId,
    );
    if (receipt) {
      if (receipt.payloadHash !== sourceHash) {
        fail(
          "IDEMPOTENCY_CONFLICT",
          "Source event ID was reused for different content.",
        );
      }
      return { ...receipt.result, duplicate: true };
    }

    const current = await tx.loadProjectionForUpdate(command.tenantId);
    if (
      command.sourceGeneration < tenant.generation ||
      command.sourceLifecycleVersion < tenant.lifecycleVersion ||
      (current && command.sourceGeneration < current.generation)
    ) {
      const result = {
        tenantId: command.tenantId,
        projectionState: current?.state ?? "NOT_CREATED",
        generation: current?.generation ?? tenant.generation,
        applied: false,
        stale: true,
      };
      await tx.putSourceReceipt(command.tenantId, command.sourceEventId, {
        payloadHash: sourceHash,
        result,
      });
      return result;
    }
    if (
      command.sourceLifecycleVersion !== tenant.lifecycleVersion ||
      command.sourceGeneration !== tenant.generation ||
      command.sourceOperationId !== tenant.operationId ||
      command.sourceState !== tenant.state
    ) {
      fail(
        "TENANT_EVENT_MISMATCH",
        "Lifecycle event does not match authoritative Tenant state.",
      );
    }

    const timestamp = now();
    let projection;
    let provider = current
      ? await tx.loadProvider(current.providerConnectionId)
      : null;
    let eventType;
    const catalog = identityCatalog.resolveFixture(tenant.fixtureRef);

    if (!provider) {
      provider = {
        providerConnectionId: `idp_${newUuid()}`,
        tenantId: tenant.tenantId,
        tenantKind: "SYNTHETIC",
        protocol: "OIDC",
        issuer: catalog.provider.issuer,
        clientId: catalog.provider.clientId,
        redirectRoutes: catalog.provider.redirectRoutes,
        configurationVersion: catalog.provider.configurationVersion,
        allowedAlgorithms: catalog.provider.allowedAlgorithms,
        allowedKeyIds: catalog.provider.allowedKeyIds,
        requiredAuthenticationMethods:
          catalog.provider.requiredAuthenticationMethods,
        maxAuthenticationAgeSeconds:
          catalog.provider.maxAuthenticationAgeSeconds,
        upstreamProtocols: catalog.provider.upstreamProtocols,
        policy: "SCIM_REQUIRED",
        status: "ACTIVE",
        createdAt: timestamp,
        updatedAt: timestamp,
      };
    } else if (
      provider.issuer !== catalog.provider.issuer ||
      provider.clientId !== catalog.provider.clientId
    ) {
      fail(
        "PROVIDER_BINDING_IMMUTABLE",
        "Provider changes require a new frozen connection.",
      );
    }

    if (
      tenant.state === "PROVISIONING" ||
      (tenant.state === "ACTIVE" && !current) ||
      (tenant.state === "ACTIVE" &&
        current?.state !== "DELETED" &&
        tenant.generation > current.generation)
    ) {
      provider = { ...provider, status: "ACTIVE", updatedAt: timestamp };
      projection = {
        tenantId: tenant.tenantId,
        tenantKind: "SYNTHETIC",
        fixtureRef: safeClone(tenant.fixtureRef),
        providerConnectionId: provider.providerConnectionId,
        state: "READY",
        generation: tenant.generation,
        operationId: tenant.operationId,
        revocationEpoch: (current?.revocationEpoch ?? 0) + 1,
        updatedAt: timestamp,
      };
      if (current) {
        await tx.revokeSessionsForTenant(tenant.tenantId, timestamp);
      }
      eventType = "product.identity.tenant-projection-ready.v1";
    } else if (tenant.state === "SUSPENDED") {
      projection = current
        ? {
            ...current,
            state: "SUSPENDED",
            generation: tenant.generation,
            operationId: tenant.operationId,
            revocationEpoch: current.revocationEpoch + 1,
            updatedAt: timestamp,
          }
        : {
            tenantId: tenant.tenantId,
            tenantKind: "SYNTHETIC",
            fixtureRef: safeClone(tenant.fixtureRef),
            providerConnectionId: provider.providerConnectionId,
            state: "SUSPENDED",
            generation: tenant.generation,
            operationId: tenant.operationId,
            revocationEpoch: 1,
            updatedAt: timestamp,
          };
      if (current) {
        await tx.revokeSessionsForTenant(tenant.tenantId, timestamp);
      }
      eventType = "product.identity.tenant-suspended.v1";
    } else if (tenant.state === "DELETING" || tenant.state === "DELETED") {
      projection = current
        ? {
            ...current,
            state: "DELETED",
            generation: tenant.generation,
            operationId: tenant.operationId,
            revocationEpoch: current.revocationEpoch + 1,
            updatedAt: timestamp,
          }
        : {
            tenantId: tenant.tenantId,
            tenantKind: "SYNTHETIC",
            fixtureRef: safeClone(tenant.fixtureRef),
            providerConnectionId: provider.providerConnectionId,
            state: "DELETED",
            generation: tenant.generation,
            operationId: tenant.operationId,
            revocationEpoch: 1,
            updatedAt: timestamp,
          };
      provider = { ...provider, status: "DELETED", updatedAt: timestamp };
      for (const account of await tx.listAccounts(tenant.tenantId)) {
        if (account.state !== "TERMINATED") {
          await tx.putAccount({
            ...account,
            state: "TERMINATED",
            lifecycleVersion: account.lifecycleVersion + 1,
            revocationEpoch: account.revocationEpoch + 1,
            updatedAt: timestamp,
          });
        }
      }
      if (current) {
        await tx.revokeSessionsForTenant(tenant.tenantId, timestamp);
      }
      eventType = "product.identity.tenant-deleted.v1";
    } else if (tenant.state === "ACTIVE" && current) {
      projection = current;
      const result = {
        tenantId: tenant.tenantId,
        providerConnectionId: current.providerConnectionId,
        projectionState: current.state,
        generation: current.generation,
        applied: false,
      };
      await tx.putSourceReceipt(command.tenantId, command.sourceEventId, {
        payloadHash: sourceHash,
        result,
      });
      return result;
    } else {
      fail(
        "INVALID_TENANT_LIFECYCLE",
        "Tenant lifecycle state cannot be projected.",
      );
    }

    await tx.putProvider(provider);
    await tx.putProjection(projection);
    const event = identityEvent({
      subject: tenant.tenantId,
      tenantId: tenant.tenantId,
      correlationId: command.correlationId,
      type: eventType,
      actorId: context.actorId,
      data: {
        generation: projection.generation,
        operation_id: projection.operationId,
        projection_state: projection.state,
        revocation_epoch: projection.revocationEpoch,
        provider_connection_id: projection.providerConnectionId,
        source_event_id: command.sourceEventId,
      },
    });
    await tx.appendEvent(event);
    await tx.appendOutbox(event);
    const result = {
      tenantId: tenant.tenantId,
      providerConnectionId: projection.providerConnectionId,
      projectionState: projection.state,
      generation: projection.generation,
      applied: true,
    };
    await tx.putSourceReceipt(command.tenantId, command.sourceEventId, {
      payloadHash: sourceHash,
      result,
    });
    return result;
  }

  async function applyAccountSnapshot(
    tx,
    context,
    command,
    sourceHash,
  ) {
    const sourceReceipt = await tx.loadSourceReceipt(
      command.tenantId,
      command.sourceEventId,
    );
    if (sourceReceipt) {
      if (sourceReceipt.payloadHash !== sourceHash) {
        fail(
          "IDEMPOTENCY_CONFLICT",
          "Source event ID was reused for different content.",
        );
      }
      return { ...sourceReceipt.result, duplicate: true };
    }

    const projection = await tx.loadProjectionForUpdate(command.tenantId);
    const provider = projection
      ? await tx.loadProvider(projection.providerConnectionId)
      : null;
    const terminalSync = command.desiredState === "TERMINATED";
    const acceptableProjection =
      projection?.state === "READY" ||
      (terminalSync &&
        ["SUSPENDED", "DELETED"].includes(projection?.state));
    const acceptableProvider =
      provider?.status === "ACTIVE" ||
      (terminalSync && provider?.status === "DELETED");
    if (
      !acceptableProjection ||
      !acceptableProvider ||
      provider.providerConnectionId !== command.providerConnectionId
    ) {
      fail(
        "IDENTITY_PROJECTION_NOT_READY",
        "Synthetic identity provider is not ready.",
      );
    }
    const user = identityCatalog.resolveUser(
      projection.fixtureRef,
      command.fixtureUserId,
    );
    const payloadHash = await sha256({
      fixtureUserId: command.fixtureUserId,
      directoryObjectId: user.directoryObjectId,
      loginSubject: user.loginSubject,
      profileRef: user.profileRef,
      sourceRevision: command.sourceRevision,
      desiredState: command.desiredState,
    });
    const byDirectory = await tx.findAccountByDirectory(
      command.tenantId,
      command.providerConnectionId,
      user.directoryObjectId,
    );
    const bySubject = await tx.findAccountBySubject(
      command.tenantId,
      command.providerConnectionId,
      provider.issuer,
      user.loginSubject,
    );
    if (
      byDirectory &&
      bySubject &&
      byDirectory.accountId !== bySubject.accountId
    ) {
      fail(
        "IDENTITY_BINDING_CONFLICT",
        "Provisioning and federation bindings disagree.",
      );
    }
    const current = byDirectory ?? bySubject;
    if (
      current &&
      (current.directoryObjectId !== user.directoryObjectId ||
        current.subject !== user.loginSubject)
    ) {
      fail(
        "IDENTITY_BINDING_CONFLICT",
        "Synthetic identity mappings cannot be relinked.",
      );
    }

    if (current && command.sourceRevision < current.sourceRevision) {
      const result = {
        accountId: current.accountId,
        state: current.state,
        lifecycleVersion: current.lifecycleVersion,
        revocationEpoch: current.revocationEpoch,
        applied: false,
        stale: true,
      };
      await tx.putSourceReceipt(command.tenantId, command.sourceEventId, {
        payloadHash: sourceHash,
        result,
      });
      return result;
    }
    if (current && command.sourceRevision === current.sourceRevision) {
      if (current.sourcePayloadHash !== payloadHash) {
        fail(
          "PROVISIONING_VERSION_CONFLICT",
          "The source revision is bound to different content.",
        );
      }
      const result = {
        accountId: current.accountId,
        state: current.state,
        lifecycleVersion: current.lifecycleVersion,
        revocationEpoch: current.revocationEpoch,
        applied: false,
      };
      await tx.putSourceReceipt(command.tenantId, command.sourceEventId, {
        payloadHash: sourceHash,
        result,
      });
      return result;
    }
    if (current?.state === "TERMINATED" && command.desiredState !== "TERMINATED") {
      fail(
        "TERMINATED_ACCOUNT",
        "A terminated account incarnation cannot be restored.",
      );
    }

    const timestamp = now();
    const account = current
      ? {
          ...current,
          state: command.desiredState,
          lifecycleVersion: current.lifecycleVersion + 1,
          sourceRevision: command.sourceRevision,
          sourcePayloadHash: payloadHash,
          revocationEpoch: current.revocationEpoch + 1,
          profileRef: user.profileRef,
          updatedAt: timestamp,
        }
      : {
          accountId: `sia_${newUuid()}`,
          tenantId: command.tenantId,
          tenantKind: "SYNTHETIC",
          providerConnectionId: command.providerConnectionId,
          issuer: provider.issuer,
          subject: user.loginSubject,
          directoryObjectId: user.directoryObjectId,
          fixtureUserId: user.fixtureUserId,
          state: command.desiredState,
          lifecycleVersion: 1,
          sourceRevision: command.sourceRevision,
          sourcePayloadHash: payloadHash,
          revocationEpoch: 1,
          incarnation: 1,
          profileRef: user.profileRef,
          createdAt: timestamp,
          updatedAt: timestamp,
        };
    await tx.putAccount(account);
    if (current) {
      await tx.revokeSessionsForAccount(account.accountId, timestamp);
    }
    const eventType =
      account.state === "TERMINATED"
        ? "product.identity.account-terminated.v1"
        : current
          ? "product.identity.account-updated.v1"
          : "product.identity.account-provisioned.v1";
    const event = identityEvent({
      subject: account.accountId,
      tenantId: account.tenantId,
      correlationId: command.correlationId,
      type: eventType,
      actorId: context.actorId,
      data: {
        account_id: account.accountId,
        account_state: account.state,
        lifecycle_version: account.lifecycleVersion,
        source_revision: account.sourceRevision,
        revocation_epoch: account.revocationEpoch,
        provider_connection_id: account.providerConnectionId,
        source_event_id: command.sourceEventId,
      },
    });
    await tx.appendEvent(event);
    await tx.appendOutbox(event);
    const result = {
      accountId: account.accountId,
      state: account.state,
      lifecycleVersion: account.lifecycleVersion,
      revocationEpoch: account.revocationEpoch,
      applied: true,
    };
    await tx.putSourceReceipt(command.tenantId, command.sourceEventId, {
      payloadHash: sourceHash,
      result,
    });
    return result;
  }

  async function rotateProviderKeys(tx, context, command) {
    const projection = await tx.loadProjectionForUpdate(command.tenantId);
    const provider = projection
      ? await tx.loadProvider(projection.providerConnectionId)
      : null;
    if (
      projection?.state !== "READY" ||
      provider?.status !== "ACTIVE" ||
      provider.providerConnectionId !== command.providerConnectionId
    ) {
      fail(
        "IDENTITY_PROJECTION_NOT_READY",
        "Synthetic identity provider is not ready.",
      );
    }
    if (
      provider.configurationVersion !==
      command.expectedConfigurationVersion
    ) {
      fail(
        "PROVIDER_CONFIGURATION_CONFLICT",
        "Provider configuration changed concurrently.",
      );
    }
    const currentKeyIds = [...provider.allowedKeyIds].sort();
    const nextKeyIds = [...command.allowedKeyIds].sort();
    if (
      currentKeyIds.length === nextKeyIds.length &&
      currentKeyIds.every(
        (keyId, index) => keyId === nextKeyIds[index],
      )
    ) {
      fail(
        "PROVIDER_CONFIGURATION_CONFLICT",
        "A key rotation must change the allowed key set.",
      );
    }
    if (
      command.emergency &&
      currentKeyIds.every((keyId) => nextKeyIds.includes(keyId))
    ) {
      fail(
        "PROVIDER_CONFIGURATION_CONFLICT",
        "An emergency rotation must remove an existing key.",
      );
    }
    const timestamp = now();
    const nextConfiguration = {
      providerConnectionId: provider.providerConnectionId,
      tenantId: provider.tenantId,
      configurationVersion: provider.configurationVersion + 1,
      redirectRoutes: safeClone(provider.redirectRoutes),
      allowedAlgorithms: safeClone(provider.allowedAlgorithms),
      allowedKeyIds: nextKeyIds,
      requiredAuthenticationMethods: safeClone(
        provider.requiredAuthenticationMethods,
      ),
      maxAuthenticationAgeSeconds:
        provider.maxAuthenticationAgeSeconds,
      upstreamProtocols: safeClone(provider.upstreamProtocols),
      state: "CURRENT",
      activatedAt: timestamp,
      graceUntil: null,
      retiredAt: null,
      retirementMode: null,
    };
    const graceUntil = command.emergency
      ? null
      : new Date(
          isoMillis(timestamp, "clock") + loginTtlSeconds * 1000,
        ).toISOString();
    await tx.rotateProviderConfiguration({
      providerConnectionId: provider.providerConnectionId,
      expectedVersion: provider.configurationVersion,
      nextConfiguration,
      graceUntil,
      emergency: command.emergency,
      updatedAt: timestamp,
    });
    if (command.emergency) {
      await tx.revokeSessionsForTenant(command.tenantId, timestamp);
    }
    const event = identityEvent({
      subject: provider.providerConnectionId,
      tenantId: command.tenantId,
      correlationId: command.correlationId,
      type: "product.identity.provider-configuration-rotated.v1",
      actorId: context.actorId,
      data: {
        provider_connection_id: provider.providerConnectionId,
        previous_configuration_version: provider.configurationVersion,
        configuration_version: nextConfiguration.configurationVersion,
        allowed_key_ids: safeClone(nextKeyIds),
        emergency: command.emergency,
        grace_until: graceUntil,
      },
    });
    await tx.appendEvent(event);
    await tx.appendOutbox(event);
    return {
      providerConnectionId: provider.providerConnectionId,
      previousConfigurationVersion: provider.configurationVersion,
      configurationVersion: nextConfiguration.configurationVersion,
      emergency: command.emergency,
      graceUntil,
      applied: true,
    };
  }

  async function retireProviderConfiguration(tx, context, command) {
    const projection = await tx.loadProjectionForUpdate(command.tenantId);
    const provider = projection
      ? await tx.loadProvider(projection.providerConnectionId)
      : null;
    const configuration = provider
      ? await tx.loadProviderConfiguration(
          provider.providerConnectionId,
          command.configurationVersion,
        )
      : null;
    const timestamp = now();
    if (
      projection?.state !== "READY" ||
      provider?.status !== "ACTIVE" ||
      provider.providerConnectionId !== command.providerConnectionId ||
      configuration?.state !== "GRACE" ||
      isoMillis(configuration.graceUntil, "provider.graceUntil") >
        isoMillis(timestamp, "clock")
    ) {
      fail(
        "PROVIDER_CONFIGURATION_CONFLICT",
        "Only an expired grace configuration can be retired.",
      );
    }
    await tx.retireProviderConfiguration({
      providerConnectionId: provider.providerConnectionId,
      configurationVersion: command.configurationVersion,
      retiredAt: timestamp,
    });
    const event = identityEvent({
      subject: provider.providerConnectionId,
      tenantId: command.tenantId,
      correlationId: command.correlationId,
      type: "product.identity.provider-configuration-retired.v1",
      actorId: context.actorId,
      data: {
        provider_connection_id: provider.providerConnectionId,
        configuration_version: command.configurationVersion,
      },
    });
    await tx.appendEvent(event);
    await tx.appendOutbox(event);
    return {
      providerConnectionId: provider.providerConnectionId,
      configurationVersion: command.configurationVersion,
      state: "RETIRED",
      applied: true,
    };
  }

  async function revokeSession(tx, context, command) {
    const session = await tx.loadSessionByIdForUpdate(command.sessionId);
    if (!session || session.tenantId !== command.tenantId) {
      fail("SESSION_INVALID", "Session is invalid.");
    }
    if (session.status === "REVOKED") {
      return {
        sessionId: session.sessionId,
        status: session.status,
        applied: false,
      };
    }
    const updated = {
      ...session,
      status: "REVOKED",
      revokedAt: now(),
    };
    await tx.putSession(updated);
    const event = identityEvent({
      subject: updated.sessionId,
      tenantId: updated.tenantId,
      correlationId: command.correlationId,
      type: "product.identity.session-revoked.v1",
      actorId: context.actorId,
      data: {
        account_id: updated.accountId,
        session_id: updated.sessionId,
        reason_ref: command.reasonRef,
      },
    });
    await tx.appendEvent(event);
    await tx.appendOutbox(event);
    return { sessionId: updated.sessionId, status: updated.status, applied: true };
  }

  async function execute(context, command) {
    validateCommand(command);
    if (!(await isAuthorized(context, capabilityFor(command)))) {
      fail("UNAUTHORIZED", "Identity command is not authorized.");
    }
    nonEmptyString(context.actorId, "context.actorId", 128);
    const commandHash = await sha256({
      actorId: context.actorId,
      command,
    });
    const sourceCommand = { ...command };
    delete sourceCommand.idempotencyKey;
    const sourceHash = await sha256(sourceCommand);
    let tenant = null;
    if (
      command.kind === "APPLY_TENANT_LIFECYCLE_EVENT" ||
      command.kind === "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT" ||
      command.kind === "ROTATE_SYNTHETIC_PROVIDER_KEYS" ||
      command.kind === "RETIRE_SYNTHETIC_PROVIDER_CONFIGURATION"
    ) {
      tenant = await c03Snapshot(command.tenantId);
    }
    if (command.kind === "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT") {
      const allowedStates =
        command.desiredState === "TERMINATED"
          ? ["ACTIVE", "SUSPENDED", "DELETING", "DELETED"]
          : ["ACTIVE"];
      if (!allowedStates.includes(tenant.state)) {
        fail(
          "TENANT_NOT_ACTIVE",
          "Tenant state does not allow this provisioning snapshot.",
        );
      }
    }
    if (
      (
        command.kind === "ROTATE_SYNTHETIC_PROVIDER_KEYS" ||
        command.kind === "RETIRE_SYNTHETIC_PROVIDER_CONFIGURATION"
      ) &&
      tenant.state !== "ACTIVE"
    ) {
      fail(
        "TENANT_NOT_ACTIVE",
        "Tenant state does not allow provider configuration changes.",
      );
    }
    const stored = await store.runCommand(
      {
        idempotencyKey: command.idempotencyKey,
        commandHash,
      },
      async (tx) => {
        if (command.kind === "APPLY_TENANT_LIFECYCLE_EVENT") {
          return applyTenantLifecycle(
            tx,
            context,
            command,
            sourceHash,
            tenant,
          );
        }
        if (command.kind === "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT") {
          return applyAccountSnapshot(tx, context, command, sourceHash);
        }
        if (command.kind === "ROTATE_SYNTHETIC_PROVIDER_KEYS") {
          return rotateProviderKeys(tx, context, command);
        }
        if (
          command.kind === "RETIRE_SYNTHETIC_PROVIDER_CONFIGURATION"
        ) {
          return retireProviderConfiguration(tx, context, command);
        }
        return revokeSession(tx, context, command);
      },
    );
    return {
      ...stored.value,
      duplicate: stored.duplicate || stored.value.duplicate === true,
    };
  }

  async function startLogin(serverContext, request) {
    exactKeys(
      request,
      ["tenantId", "providerConnectionId", "returnRoute"],
      "login request",
    );
    syntheticTenantId(request.tenantId);
    nonEmptyString(
      request.providerConnectionId,
      "providerConnectionId",
      80,
    );
    nonEmptyString(request.returnRoute, "returnRoute", 64);
    await admitTenant(serverContext, request.tenantId);
    const snapshot = await store.readTenantSnapshot(request.tenantId);
    if (
      snapshot?.projection.state !== "READY" ||
      snapshot.provider?.status !== "ACTIVE" ||
      snapshot.provider.providerConnectionId !== request.providerConnectionId
    ) {
      fail("PROVIDER_NOT_READY", "Synthetic identity provider is not ready.");
    }
    const redirectUri =
      snapshot.provider.redirectRoutes[request.returnRoute];
    if (!redirectUri) {
      fail("AUTHENTICATION_FAILED", "Login request is invalid.");
    }
    const transactionId = `lgn_${newUuid()}`;
    const state = newSecret();
    const nonce = newSecret();
    const codeVerifier = newSecret();
    const challenge = await pkceChallenge(codeVerifier);
    const issuedAt = now();
    const expiresAt = new Date(
      isoMillis(issuedAt, "clock") + loginTtlSeconds * 1000,
    ).toISOString();
    const authorization = await federationBroker.startAuthorization({
      protocol: "OIDC",
      issuer: snapshot.provider.issuer,
      clientId: snapshot.provider.clientId,
      redirectUri,
      state,
      nonce,
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
      configurationVersion: snapshot.provider.configurationVersion,
    });
    syntheticHttpsUrl(
      authorization?.authorizationUrl,
      "authorizationUrl",
    );
    await store.transact(async (tx) => {
      await tx.insertLoginTransaction({
        transactionId,
        tenantId: request.tenantId,
        providerConnectionId: request.providerConnectionId,
        providerConfigurationVersion:
          snapshot.provider.configurationVersion,
        stateHash: await sha256(state),
        nonceHash: await sha256(nonce),
        pkceVerifierHash: await sha256(codeVerifier),
        redirectUri,
        returnRoute: request.returnRoute,
        issuedAt,
        expiresAt,
        claimedAt: null,
        claimHash: null,
        consumedAt: null,
      });
    });
    return {
      transactionId,
      authorizationUrl: authorization.authorizationUrl,
      state,
      codeVerifier,
      expiresAt,
    };
  }

  function authenticationFailure() {
    fail("AUTHENTICATION_FAILED", "Authentication failed.");
  }

  async function validateAssertion(assertion, transaction, provider) {
    if (
      !assertion ||
      assertion.protocol !== "OIDC" ||
      assertion.signatureVerified !== true ||
      assertion.synthetic !== true ||
      assertion.issuer !== provider.issuer ||
      assertion.configurationVersion !== provider.configurationVersion ||
      !provider.allowedAlgorithms.includes(assertion.algorithm) ||
      !provider.allowedKeyIds.includes(assertion.keyId)
    ) {
      authenticationFailure();
    }
    nonEmptyString(assertion.subject, "assertion.subject", 255);
    const audiences = Array.isArray(assertion.audience)
      ? assertion.audience
      : [assertion.audience];
    if (!audiences.includes(provider.clientId)) authenticationFailure();
    if (
      (audiences.length > 1 &&
        assertion.authorizedParty !== provider.clientId) ||
      (assertion.authorizedParty &&
        assertion.authorizedParty !== provider.clientId)
    ) {
      authenticationFailure();
    }
    if ((await sha256(assertion.nonce)) !== transaction.nonceHash) {
      authenticationFailure();
    }
    const current = isoMillis(now(), "clock");
    const issuedAt = isoMillis(assertion.issuedAt, "assertion.issuedAt");
    const expiresAt = isoMillis(assertion.expiresAt, "assertion.expiresAt");
    const authenticationTime = isoMillis(
      assertion.authenticationTime,
      "assertion.authenticationTime",
    );
    const notBefore = assertion.notBefore
      ? isoMillis(assertion.notBefore, "assertion.notBefore")
      : issuedAt;
    if (
      issuedAt > current + 60_000 ||
      notBefore > current + 60_000 ||
      expiresAt <= current ||
      authenticationTime > current + 60_000 ||
      current - authenticationTime >
        provider.maxAuthenticationAgeSeconds * 1000
    ) {
      authenticationFailure();
    }
    if (
      !Array.isArray(assertion.authenticationMethods) ||
      !provider.requiredAuthenticationMethods.every((method) =>
        assertion.authenticationMethods.includes(method),
      )
    ) {
      fail("MFA_REQUIRED", "Required authentication strength was not met.");
    }
  }

  async function completeLogin(serverContext, request) {
    exactKeys(
      request,
      ["transactionId", "state", "authorizationCode", "codeVerifier"],
      "login callback",
    );
    nonEmptyString(request.transactionId, "transactionId", 80);
    nonEmptyString(request.state, "state", 128);
    nonEmptyString(request.authorizationCode, "authorizationCode", 2048);
    nonEmptyString(request.codeVerifier, "codeVerifier", 128);

    const claimSecret = newSecret();
    const claimHash = await sha256(claimSecret);
    const initial = await store.transact(async (tx) => {
      const transaction = await tx.loadLoginTransactionForUpdate(
        request.transactionId,
      );
      if (!transaction) authenticationFailure();
      if (transaction.claimedAt || transaction.consumedAt) {
        fail("LOGIN_REPLAY_DETECTED", "Login transaction was already consumed.");
      }
      if (isoMillis(transaction.expiresAt, "expiresAt") <= isoMillis(now(), "clock")) {
        fail("LOGIN_TRANSACTION_EXPIRED", "Login transaction expired.");
      }
      if (
        (await sha256(request.state)) !== transaction.stateHash ||
        (await sha256(request.codeVerifier)) !== transaction.pkceVerifierHash
      ) {
        authenticationFailure();
      }
      const claimed = {
        ...transaction,
        claimedAt: now(),
        claimHash,
      };
      await tx.putLoginTransaction(claimed);
      return claimed;
    });
    await admitTenant(serverContext, initial.tenantId);
    const snapshot = await store.readTenantSnapshot(initial.tenantId);
    const currentProvider = snapshot?.provider;
    if (
      snapshot?.projection.state !== "READY" ||
      currentProvider?.status !== "ACTIVE" ||
      currentProvider.providerConnectionId !== initial.providerConnectionId
    ) {
      fail("PROVIDER_NOT_READY", "Synthetic identity provider is not ready.");
    }
    const provider = await store.transact((tx) =>
      tx.loadProviderConfiguration(
        initial.providerConnectionId,
        initial.providerConfigurationVersion,
      ),
    );
    if (
      !provider ||
      !["CURRENT", "GRACE"].includes(provider.state) ||
      (
        provider.state === "GRACE" &&
        isoMillis(provider.graceUntil, "provider.graceUntil") <=
          isoMillis(now(), "clock")
      )
    ) {
      fail(
        "PROVIDER_CONFIGURATION_RETIRED",
        "The login transaction provider configuration is no longer valid.",
      );
    }
    let assertion;
    try {
      assertion = await federationBroker.exchangeAndVerify({
        protocol: "OIDC",
        issuer: provider.issuer,
        clientId: provider.clientId,
        redirectUri: initial.redirectUri,
        authorizationCode: request.authorizationCode,
        codeVerifier: request.codeVerifier,
        configurationVersion: provider.configurationVersion,
      });
    } catch {
      authenticationFailure();
    }
    await validateAssertion(assertion, initial, provider);
    const sessionToken = newSecret();
    const tokenHash = await sha256(sessionToken);
    const completed = await store.transact(async (tx) => {
      const transaction = await tx.loadLoginTransactionForUpdate(
        request.transactionId,
      );
      if (
        !transaction ||
        transaction.consumedAt ||
        transaction.claimHash !== claimHash
      ) {
        fail("LOGIN_REPLAY_DETECTED", "Login transaction was already consumed.");
      }
      if (
        isoMillis(transaction.expiresAt, "expiresAt") <=
        isoMillis(now(), "clock")
      ) {
        fail("LOGIN_TRANSACTION_EXPIRED", "Login transaction expired.");
      }
      if (
        (await sha256(request.state)) !== transaction.stateHash ||
        (await sha256(request.codeVerifier)) !== transaction.pkceVerifierHash
      ) {
        authenticationFailure();
      }
      const transactionProvider = await tx.loadProviderConfiguration(
        transaction.providerConnectionId,
        transaction.providerConfigurationVersion,
      );
      if (
        !transactionProvider ||
        !["CURRENT", "GRACE"].includes(transactionProvider.state) ||
        (
          transactionProvider.state === "GRACE" &&
          isoMillis(
            transactionProvider.graceUntil,
            "provider.graceUntil",
          ) <= isoMillis(now(), "clock")
        )
      ) {
        fail(
          "PROVIDER_CONFIGURATION_RETIRED",
          "The login transaction provider configuration is no longer valid.",
        );
      }
      const projection = await tx.loadProjectionForUpdate(
        transaction.tenantId,
      );
      const account = await tx.findAccountBySubject(
        transaction.tenantId,
        transaction.providerConnectionId,
        provider.issuer,
        assertion.subject,
      );
      if (
        projection?.state !== "READY" ||
        !account ||
        account.state !== "ACTIVE"
      ) {
        authenticationFailure();
      }
      const issuedAt = now();
      const session = {
        sessionId: `ses_${newUuid()}`,
        tenantId: transaction.tenantId,
        tenantKind: "SYNTHETIC",
        accountId: account.accountId,
        providerConnectionId: transaction.providerConnectionId,
        providerConfigurationVersion:
          transaction.providerConfigurationVersion,
        tokenHash,
        accountRevocationEpoch: account.revocationEpoch,
        tenantRevocationEpoch: projection.revocationEpoch,
        status: "ACTIVE",
        authenticationTime: assertion.authenticationTime,
        authenticationMethods: safeClone(assertion.authenticationMethods),
        issuedAt,
        expiresAt: new Date(
          isoMillis(issuedAt, "clock") + sessionTtlSeconds * 1000,
        ).toISOString(),
        revokedAt: null,
      };
      await tx.insertSession(session);
      await tx.putLoginTransaction({
        ...transaction,
        consumedAt: issuedAt,
      });
      return { session, account };
    });
    try {
      await admitTenant(serverContext, completed.session.tenantId);
    } catch (error) {
      await store.transact(async (tx) => {
        const session = await tx.loadSessionByIdForUpdate(
          completed.session.sessionId,
        );
        if (session?.status === "ACTIVE") {
          await tx.putSession({
            ...session,
            status: "REVOKED",
            revokedAt: now(),
          });
        }
      });
      throw error;
    }
    const finalSnapshot = await store.readSessionSnapshot(tokenHash);
    if (!isActiveSessionSnapshot(finalSnapshot, completed.session.tenantId)) {
      authenticationFailure();
    }
    return {
      sessionToken,
      sessionId: completed.session.sessionId,
      tenantId: completed.session.tenantId,
      tenantKind: "SYNTHETIC",
      identityAccountId: completed.account.accountId,
      providerConnectionId: completed.session.providerConnectionId,
      providerConfigurationVersion:
        completed.session.providerConfigurationVersion,
      authenticationTime: completed.session.authenticationTime,
      authenticationMethods: safeClone(
        completed.session.authenticationMethods,
      ),
      expiresAt: completed.session.expiresAt,
      trustSource: "VERIFIED_SESSION",
      authorizationStatus: "NOT_EVALUATED",
    };
  }

  function isActiveSessionSnapshot(value, expectedTenantId) {
    return Boolean(
      value &&
        value.session.tenantId === expectedTenantId &&
        value.session.status === "ACTIVE" &&
        isoMillis(value.session.expiresAt, "expiresAt") > isoMillis(now(), "clock") &&
        value.account?.state === "ACTIVE" &&
        value.projection?.state === "READY" &&
        value.provider?.status === "ACTIVE" &&
        value.session.accountRevocationEpoch ===
          value.account.revocationEpoch &&
        value.session.tenantRevocationEpoch ===
          value.projection.revocationEpoch,
    );
  }

  async function resolveSession(serverContext, request) {
    exactKeys(
      request,
      ["sessionToken", "expectedTenantId"],
      "session request",
    );
    nonEmptyString(request.sessionToken, "sessionToken", 128);
    syntheticTenantId(request.expectedTenantId);
    const snapshot = await store.readSessionSnapshot(
      await sha256(request.sessionToken),
    );
    if (!isActiveSessionSnapshot(snapshot, request.expectedTenantId)) {
      fail("SESSION_INVALID", "Session is invalid.");
    }
    await admitTenant(serverContext, snapshot.session.tenantId);
    return {
      tenantId: snapshot.session.tenantId,
      tenantKind: "SYNTHETIC",
      identityAccountId: snapshot.account.accountId,
      providerConnectionId: snapshot.session.providerConnectionId,
      providerConfigurationVersion:
        snapshot.session.providerConfigurationVersion,
      sessionId: snapshot.session.sessionId,
      authenticationTime: snapshot.session.authenticationTime,
      authenticationMethods: safeClone(
        snapshot.session.authenticationMethods,
      ),
      trustSource: "VERIFIED_SESSION",
      authorizationStatus: "NOT_EVALUATED",
    };
  }

  async function snapshot(context, query) {
    exactKeys(query, ["tenantId"], "snapshot query");
    syntheticTenantId(query.tenantId);
    if (!(await isAuthorized(context, READ))) {
      fail("UNAUTHORIZED", "Identity snapshot is not authorized.");
    }
    const value = await store.readTenantSnapshot(query.tenantId);
    if (!value) fail("IDENTITY_PROJECTION_NOT_FOUND", "Projection was not found.");
    return {
      tenantId: value.projection.tenantId,
      tenantKind: value.projection.tenantKind,
      projectionState: value.projection.state,
      generation: value.projection.generation,
      operationId: value.projection.operationId,
      revocationEpoch: value.projection.revocationEpoch,
      provider: safeProvider(value.provider),
      accounts: value.accounts.map(safeAccount),
      sessions: value.sessions.map((session) => ({
        sessionId: session.sessionId,
        accountId: session.accountId,
        providerConfigurationVersion:
          session.providerConfigurationVersion,
        status: session.status,
        issuedAt: session.issuedAt,
        expiresAt: session.expiresAt,
        revokedAt: session.revokedAt,
      })),
      events: safeClone(value.events),
      outbox: safeClone(value.outbox),
      authorizationStatus: "NOT_EVALUATED",
    };
  }

  return Object.freeze({
    execute,
    startLogin,
    completeLogin,
    resolveSession,
    snapshot,
  });
}

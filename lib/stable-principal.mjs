const SHA256 = /^sha256:[a-f0-9]{64}$/;
const UUID_V7 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7.source.slice(1, -1)}$`);
const PRINCIPAL_ID = new RegExp(`^prn_${UUID_V7.source.slice(1, -1)}$`);
const IDENTITY_LINK_ID = new RegExp(`^lnk_${UUID_V7.source.slice(1, -1)}$`);
const DELEGATION_ID = new RegExp(`^dlg_${UUID_V7.source.slice(1, -1)}$`);
const IDENTITY_ACCOUNT_ID = new RegExp(
  `^sia_${UUID_V7.source.slice(1, -1)}$`,
);
const UTC_MILLISECOND_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const REFERENCE =
  /^(?:evidence|fixture|policy|profile|synthetic|test):\/\/\S+$/;
const PRINCIPAL_TYPES = Object.freeze(["HUMAN", "AGENT", "SERVICE"]);
const PRINCIPAL_STATES = Object.freeze([
  "ACTIVE",
  "SUSPENDED",
  "DEACTIVATED",
]);
const LINK_STATES = Object.freeze(["ACTIVE", "SUSPENDED", "RETIRED"]);
const MAX_DELEGATION_DEPTH = 8;

const CAPABILITIES = Object.freeze({
  CREATE_SYNTHETIC_PRINCIPAL: "PRINCIPAL_PROVISION",
  LINK_IDENTITY_ACCOUNT: "PRINCIPAL_LINK_MANAGE",
  RETIRE_IDENTITY_LINK: "PRINCIPAL_LINK_MANAGE",
  REASSIGN_IDENTITY_ACCOUNT: "PRINCIPAL_LINK_MANAGE",
  CHANGE_PRINCIPAL_STATE: "PRINCIPAL_LIFECYCLE_APPLY",
  SYNC_IDENTITY_ACCOUNT: "PRINCIPAL_LIFECYCLE_APPLY",
  CREATE_DELEGATION: "DELEGATION_MANAGE",
  REVOKE_DELEGATION: "DELEGATION_MANAGE",
});

export class StablePrincipalError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "StablePrincipalError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new StablePrincipalError(code, message);
}

function exactKeys(value, allowed, field = "command") {
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
      `${field} must use an approved P1 synthetic reference.`,
    );
  }
}

function syntheticTenantId(value) {
  nonEmptyString(value, "tenantId", 80);
  if (!SYNTHETIC_TENANT_ID.test(value)) {
    fail(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      "C05 accepts only Synthetic Tenant IDs before P3.",
    );
  }
}

function identifier(value, pattern, field) {
  nonEmptyString(value, field, 80);
  if (!pattern.test(value)) {
    fail("INVALID_COMMAND", `${field} is invalid.`);
  }
}

function generatedIdentifier(prefix, pattern, field, idFactory) {
  const value = `${prefix}${idFactory()}`;
  identifier(value, pattern, field);
  return value;
}

function positiveInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 1) {
    fail("INVALID_COMMAND", `${field} must be a positive safe integer.`);
  }
}

function isoMillis(value, field) {
  if (
    typeof value !== "string" ||
    !UTC_MILLISECOND_INSTANT.test(value)
  ) {
    fail(
      "INVALID_COMMAND",
      `${field} must be a canonical UTC millisecond instant.`,
    );
  }
  const milliseconds = Date.parse(value);
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  ) {
    fail(
      "INVALID_COMMAND",
      `${field} must be a canonical UTC millisecond instant.`,
    );
  }
  return milliseconds;
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
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalize(value)),
  );
  return `sha256:${Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")}`;
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

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function validateFixtureRef(value) {
  exactKeys(value, ["fixtureId", "sha256"], "fixtureRef");
  nonEmptyString(value.fixtureId, "fixtureRef.fixtureId", 128);
  if (!SHA256.test(value.sha256 ?? "")) {
    fail("INVALID_COMMAND", "fixtureRef.sha256 is invalid.");
  }
}

export function createSyntheticPrincipalCatalog(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    fail(
      "INVALID_PRINCIPAL_CATALOG",
      "At least one synthetic principal fixture is required.",
    );
  }
  const fixtures = new Map();
  for (const entry of entries) {
    exactKeys(
      entry,
      ["fixtureId", "sha256", "principals", "identityCorrections"],
      "catalog entry",
    );
    validateFixtureRef({
      fixtureId: entry.fixtureId,
      sha256: entry.sha256,
    });
    if (!Array.isArray(entry.principals) || entry.principals.length === 0) {
      fail(
        "INVALID_PRINCIPAL_CATALOG",
        "Each fixture requires synthetic principals.",
      );
    }
    const principals = new Map();
    const profileOwners = new Map();
    const identityCorrections = new Map();
    for (const principal of entry.principals) {
      exactKeys(
        principal,
        ["fixturePrincipalRef", "principalType", "identityProfileRefs"],
        "catalog principal",
      );
      reference(principal.fixturePrincipalRef, "fixturePrincipalRef");
      if (!PRINCIPAL_TYPES.includes(principal.principalType)) {
        fail("INVALID_PRINCIPAL_CATALOG", "Unknown principal type.");
      }
      if (!Array.isArray(principal.identityProfileRefs)) {
        fail(
          "INVALID_PRINCIPAL_CATALOG",
          "identityProfileRefs must be an array.",
        );
      }
      if (
        principal.principalType === "HUMAN" &&
        principal.identityProfileRefs.length === 0
      ) {
        fail(
          "INVALID_PRINCIPAL_CATALOG",
          "A HUMAN principal requires an explicit identity profile mapping.",
        );
      }
      if (
        principal.principalType !== "HUMAN" &&
        principal.identityProfileRefs.length !== 0
      ) {
        fail(
          "INVALID_PRINCIPAL_CATALOG",
          "AGENT and SERVICE principals cannot own human identity profiles.",
        );
      }
      if (
        new Set(principal.identityProfileRefs).size !==
        principal.identityProfileRefs.length
      ) {
        fail(
          "INVALID_PRINCIPAL_CATALOG",
          "identityProfileRefs cannot contain duplicates.",
        );
      }
      for (const profileRef of principal.identityProfileRefs) {
        reference(profileRef, "identityProfileRef");
        if (profileOwners.has(profileRef)) {
          fail(
            "INVALID_PRINCIPAL_CATALOG",
            "An identity profile cannot infer two Stable Principals.",
          );
        }
        profileOwners.set(profileRef, principal.fixturePrincipalRef);
      }
      if (principals.has(principal.fixturePrincipalRef)) {
        fail(
          "INVALID_PRINCIPAL_CATALOG",
          "fixturePrincipalRef must be unique inside a fixture.",
        );
      }
      principals.set(principal.fixturePrincipalRef, clone(principal));
    }
    if (!Array.isArray(entry.identityCorrections)) {
      fail(
        "INVALID_PRINCIPAL_CATALOG",
        "identityCorrections must be an array.",
      );
    }
    for (const correction of entry.identityCorrections) {
      exactKeys(
        correction,
        [
          "correctionRef",
          "mappingHash",
          "identityProfileRef",
          "sourceFixturePrincipalRef",
          "targetFixturePrincipalRef",
        ],
        "identity correction",
      );
      reference(correction.correctionRef, "correctionRef");
      reference(correction.identityProfileRef, "identityProfileRef");
      reference(
        correction.sourceFixturePrincipalRef,
        "sourceFixturePrincipalRef",
      );
      reference(
        correction.targetFixturePrincipalRef,
        "targetFixturePrincipalRef",
      );
      if (!SHA256.test(correction.mappingHash ?? "")) {
        fail(
          "INVALID_PRINCIPAL_CATALOG",
          "Identity correction mappingHash is invalid.",
        );
      }
      const source = principals.get(correction.sourceFixturePrincipalRef);
      const target = principals.get(correction.targetFixturePrincipalRef);
      if (
        !source ||
        !target ||
        source.principalType !== "HUMAN" ||
        target.principalType !== "HUMAN" ||
        source.fixturePrincipalRef === target.fixturePrincipalRef ||
        !source.identityProfileRefs.includes(correction.identityProfileRef)
      ) {
        fail(
          "INVALID_PRINCIPAL_CATALOG",
          "Identity correction mapping is invalid.",
        );
      }
      if (identityCorrections.has(correction.correctionRef)) {
        fail(
          "INVALID_PRINCIPAL_CATALOG",
          "Identity correction refs must be unique.",
        );
      }
      identityCorrections.set(correction.correctionRef, clone(correction));
    }
    if (fixtures.has(entry.fixtureId)) {
      fail("INVALID_PRINCIPAL_CATALOG", "Fixture IDs must be unique.");
    }
    fixtures.set(entry.fixtureId, {
      sha256: entry.sha256,
      principals,
      identityCorrections,
    });
  }

  function fixture(fixtureRef) {
    validateFixtureRef(fixtureRef);
    const value = fixtures.get(fixtureRef.fixtureId);
    if (value?.sha256 !== fixtureRef.sha256) {
      fail(
        "UNKNOWN_SYNTHETIC_PRINCIPAL_FIXTURE",
        "Principal fixture is not in the frozen catalog.",
      );
    }
    return value;
  }

  return Object.freeze({
    resolvePrincipal(fixtureRef, fixturePrincipalRef) {
      reference(fixturePrincipalRef, "fixturePrincipalRef");
      const value = fixture(fixtureRef).principals.get(fixturePrincipalRef);
      if (!value) {
        fail(
          "UNKNOWN_SYNTHETIC_PRINCIPAL",
          "Principal is not in the frozen synthetic catalog.",
        );
      }
      return clone(value);
    },
    resolveIdentityCorrection(fixtureRef, correctionRef) {
      reference(correctionRef, "correctionRef");
      const value = fixture(fixtureRef).identityCorrections.get(correctionRef);
      if (!value) {
        fail(
          "UNKNOWN_IDENTITY_CORRECTION",
          "Identity correction is not in the frozen synthetic catalog.",
        );
      }
      return clone(value);
    },
  });
}

function validateCommon(command) {
  nonEmptyString(command.idempotencyKey, "idempotencyKey", 128);
  syntheticTenantId(command.tenantId);
  nonEmptyString(command.correlationId, "correlationId", 128);
}

function validateCommand(command) {
  if (!command || typeof command !== "object" || Array.isArray(command)) {
    fail("INVALID_COMMAND", "Command must be an object.");
  }
  const common = ["kind", "idempotencyKey", "tenantId", "correlationId"];
  if (command.kind === "CREATE_SYNTHETIC_PRINCIPAL") {
    exactKeys(command, [...common, "fixturePrincipalRef"]);
    validateCommon(command);
    reference(command.fixturePrincipalRef, "fixturePrincipalRef");
    return;
  }
  if (command.kind === "LINK_IDENTITY_ACCOUNT") {
    exactKeys(command, [
      ...common,
      "principalId",
      "identityAccountId",
      "linkEvidenceRef",
    ]);
    validateCommon(command);
    identifier(command.principalId, PRINCIPAL_ID, "principalId");
    identifier(
      command.identityAccountId,
      IDENTITY_ACCOUNT_ID,
      "identityAccountId",
    );
    reference(command.linkEvidenceRef, "linkEvidenceRef");
    return;
  }
  if (command.kind === "RETIRE_IDENTITY_LINK") {
    exactKeys(command, [
      ...common,
      "identityLinkId",
      "expectedVersion",
      "reasonRef",
    ]);
    validateCommon(command);
    identifier(command.identityLinkId, IDENTITY_LINK_ID, "identityLinkId");
    positiveInteger(command.expectedVersion, "expectedVersion");
    reference(command.reasonRef, "reasonRef");
    return;
  }
  if (command.kind === "REASSIGN_IDENTITY_ACCOUNT") {
    exactKeys(command, [
      ...common,
      "identityLinkId",
      "targetPrincipalId",
      "expectedVersion",
      "reasonRef",
    ]);
    validateCommon(command);
    identifier(command.identityLinkId, IDENTITY_LINK_ID, "identityLinkId");
    identifier(
      command.targetPrincipalId,
      PRINCIPAL_ID,
      "targetPrincipalId",
    );
    positiveInteger(command.expectedVersion, "expectedVersion");
    reference(command.reasonRef, "reasonRef");
    return;
  }
  if (command.kind === "CHANGE_PRINCIPAL_STATE") {
    exactKeys(command, [
      ...common,
      "principalId",
      "expectedVersion",
      "desiredState",
      "reasonRef",
    ]);
    validateCommon(command);
    identifier(command.principalId, PRINCIPAL_ID, "principalId");
    positiveInteger(command.expectedVersion, "expectedVersion");
    if (!PRINCIPAL_STATES.includes(command.desiredState)) {
      fail("INVALID_COMMAND", "Unknown principal state.");
    }
    reference(command.reasonRef, "reasonRef");
    return;
  }
  if (command.kind === "SYNC_IDENTITY_ACCOUNT") {
    exactKeys(command, [...common, "identityAccountId"]);
    validateCommon(command);
    identifier(
      command.identityAccountId,
      IDENTITY_ACCOUNT_ID,
      "identityAccountId",
    );
    return;
  }
  if (command.kind === "CREATE_DELEGATION") {
    exactKeys(command, [
      ...common,
      "humanSubjectPrincipalId",
      "delegatorPrincipalId",
      "delegatePrincipalId",
      "parentDelegationId",
      "expiresAt",
      "purposeRef",
    ]);
    validateCommon(command);
    for (const [field, value] of [
      ["humanSubjectPrincipalId", command.humanSubjectPrincipalId],
      ["delegatorPrincipalId", command.delegatorPrincipalId],
      ["delegatePrincipalId", command.delegatePrincipalId],
    ]) {
      identifier(value, PRINCIPAL_ID, field);
    }
    if (command.parentDelegationId !== undefined) {
      identifier(
        command.parentDelegationId,
        DELEGATION_ID,
        "parentDelegationId",
      );
    }
    isoMillis(command.expiresAt, "expiresAt");
    reference(command.purposeRef, "purposeRef");
    return;
  }
  if (command.kind === "REVOKE_DELEGATION") {
    exactKeys(command, [
      ...common,
      "delegationId",
      "expectedVersion",
      "reasonRef",
    ]);
    validateCommon(command);
    identifier(command.delegationId, DELEGATION_ID, "delegationId");
    positiveInteger(command.expectedVersion, "expectedVersion");
    reference(command.reasonRef, "reasonRef");
    return;
  }
  fail("INVALID_COMMAND", "Unknown Stable Principal command.");
}

function fixtureKey(tenantId, fixturePrincipalRef) {
  return `${tenantId}\u0000${fixturePrincipalRef}`;
}

function accountKey(tenantId, identityAccountId) {
  return `${tenantId}\u0000${identityAccountId}`;
}

function receiptKey(tenantId, idempotencyKey) {
  return `${tenantId}\u0000${idempotencyKey}`;
}

function createMemoryTransaction(draft) {
  return Object.freeze({
    findPrincipalByFixture(tenantId, fixturePrincipalRef) {
      const principalId = draft.principalByFixture.get(
        fixtureKey(tenantId, fixturePrincipalRef),
      );
      return clone(draft.principals.get(principalId) ?? null);
    },
    loadPrincipalForUpdate(principalId) {
      return clone(draft.principals.get(principalId) ?? null);
    },
    insertPrincipal(principal) {
      const key = fixtureKey(
        principal.tenantId,
        principal.fixturePrincipalRef,
      );
      if (
        draft.principals.has(principal.principalId) ||
        draft.principalByFixture.has(key)
      ) {
        fail("ID_COLLISION", "Stable Principal identity already exists.");
      }
      draft.principals.set(principal.principalId, clone(principal));
      draft.principalByFixture.set(key, principal.principalId);
    },
    putPrincipal(principal) {
      const current = draft.principals.get(principal.principalId);
      if (!current) fail("PRINCIPAL_NOT_FOUND", "Principal was not found.");
      if (
        current.tenantId !== principal.tenantId ||
        current.tenantKind !== principal.tenantKind ||
        current.principalType !== principal.principalType ||
        current.fixturePrincipalRef !== principal.fixturePrincipalRef
      ) {
        fail("PRINCIPAL_IMMUTABLE", "Principal identity is immutable.");
      }
      draft.principals.set(principal.principalId, clone(principal));
    },
    loadCurrentIdentityLinkForAccount(tenantId, identityAccountId) {
      const identityLinkId = draft.currentLinkByAccount.get(
        accountKey(tenantId, identityAccountId),
      );
      return clone(draft.links.get(identityLinkId) ?? null);
    },
    loadIdentityLinkForUpdate(identityLinkId) {
      return clone(draft.links.get(identityLinkId) ?? null);
    },
    listIdentityLinks(tenantId) {
      return clone(
        Array.from(draft.links.values()).filter(
          (link) => link.tenantId === tenantId,
        ),
      );
    },
    insertIdentityLink(link) {
      const key = accountKey(link.tenantId, link.identityAccountId);
      if (
        draft.links.has(link.identityLinkId) ||
        (link.state !== "RETIRED" && draft.currentLinkByAccount.has(key))
      ) {
        fail(
          "IDENTITY_LINK_CONFLICT",
          "Identity Account already has a current Stable Principal.",
        );
      }
      draft.links.set(link.identityLinkId, clone(link));
      if (link.state !== "RETIRED") {
        draft.currentLinkByAccount.set(key, link.identityLinkId);
      }
    },
    putIdentityLink(link) {
      const current = draft.links.get(link.identityLinkId);
      if (!current) {
        fail("IDENTITY_LINK_NOT_FOUND", "Identity Link was not found.");
      }
      if (
        current.tenantId !== link.tenantId ||
        current.tenantKind !== link.tenantKind ||
        current.identityAccountId !== link.identityAccountId ||
        current.providerConnectionId !== link.providerConnectionId ||
        current.principalId !== link.principalId ||
        current.principalType !== link.principalType
      ) {
        fail("IDENTITY_LINK_IMMUTABLE", "Identity Link binding is immutable.");
      }
      const key = accountKey(link.tenantId, link.identityAccountId);
      if (current.state !== "RETIRED" && link.state === "RETIRED") {
        draft.currentLinkByAccount.delete(key);
      }
      draft.links.set(link.identityLinkId, clone(link));
    },
    loadDelegationForUpdate(delegationId) {
      return clone(draft.delegations.get(delegationId) ?? null);
    },
    listDelegations(tenantId) {
      return clone(
        Array.from(draft.delegations.values()).filter(
          (delegation) => delegation.tenantId === tenantId,
        ),
      );
    },
    insertDelegation(delegation) {
      if (draft.delegations.has(delegation.delegationId)) {
        fail("ID_COLLISION", "Delegation identifier already exists.");
      }
      draft.delegations.set(delegation.delegationId, clone(delegation));
    },
    putDelegation(delegation) {
      const current = draft.delegations.get(delegation.delegationId);
      if (!current) {
        fail("DELEGATION_NOT_FOUND", "Delegation was not found.");
      }
      const immutable = [
        "tenantId",
        "tenantKind",
        "humanSubjectPrincipalId",
        "humanSubjectKind",
        "delegatorPrincipalId",
        "delegatorKind",
        "delegatePrincipalId",
        "delegateKind",
        "parentDelegationId",
        "depth",
        "purposeRef",
        "humanSubjectSecurityEpoch",
        "delegatorSecurityEpoch",
        "delegateSecurityEpoch",
        "issuedAt",
        "expiresAt",
      ];
      if (immutable.some((field) => current[field] !== delegation[field])) {
        fail("DELEGATION_IMMUTABLE", "Delegation provenance is immutable.");
      }
      draft.delegations.set(delegation.delegationId, clone(delegation));
    },
    appendEvent(event) {
      if (draft.events.some(({ id }) => id === event.id)) {
        fail("ID_COLLISION", "Principal event ID already exists.");
      }
      draft.events.push(clone(event));
    },
    appendOutbox(event) {
      if (draft.outbox.some(({ id }) => id === event.id)) {
        fail("ID_COLLISION", "Principal outbox ID already exists.");
      }
      draft.outbox.push(clone(event));
    },
  });
}

export function createMemoryPrincipalStore() {
  let state = {
    principals: new Map(),
    principalByFixture: new Map(),
    links: new Map(),
    currentLinkByAccount: new Map(),
    delegations: new Map(),
    events: [],
    outbox: [],
    receipts: new Map(),
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
    runCommand(
      { tenantId, idempotencyKey, commandHash },
      reducer,
      preflight = async () => undefined,
    ) {
      return serial(async () => {
        const key = receiptKey(tenantId, idempotencyKey);
        const receipt = state.receipts.get(key);
        if (receipt) {
          if (receipt.commandHash !== commandHash) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "The idempotency key was used for another C05 command.",
            );
          }
          return { duplicate: true, value: clone(receipt.value) };
        }
        const prepared = await preflight();
        const draft = structuredClone(state);
        const value = await reducer(
          createMemoryTransaction(draft),
          prepared,
        );
        draft.receipts.set(key, {
          commandHash,
          value: clone(value),
        });
        state = draft;
        return { duplicate: false, value: clone(value) };
      });
    },
    async readTenantSnapshot(tenantId) {
      await queue;
      return clone({
        principals: Array.from(state.principals.values()).filter(
          (principal) => principal.tenantId === tenantId,
        ),
        links: Array.from(state.links.values()).filter(
          (link) => link.tenantId === tenantId,
        ),
        delegations: Array.from(state.delegations.values()).filter(
          (delegation) => delegation.tenantId === tenantId,
        ),
        events: state.events.filter(
          (event) => event.data?.tenant_id === tenantId,
        ),
        outbox: state.outbox.filter(
          (event) => event.data?.tenant_id === tenantId,
        ),
      });
    },
    async readActionSnapshot({
      tenantId,
      identityAccountId,
      workloadActorPrincipalId,
      delegationId,
    }) {
      await queue;
      const identityLinkId = state.currentLinkByAccount.get(
        accountKey(tenantId, identityAccountId),
      );
      const link = state.links.get(identityLinkId);
      const delegations = [];
      const principalIds = new Set([
        link?.principalId,
        workloadActorPrincipalId,
      ]);
      const seen = new Set();
      let currentId = delegationId;
      while (currentId && delegations.length < MAX_DELEGATION_DEPTH) {
        if (seen.has(currentId)) break;
        seen.add(currentId);
        const delegation = state.delegations.get(currentId);
        if (!delegation || delegation.tenantId !== tenantId) break;
        delegations.push(delegation);
        principalIds.add(delegation.humanSubjectPrincipalId);
        principalIds.add(delegation.delegatorPrincipalId);
        principalIds.add(delegation.delegatePrincipalId);
        currentId = delegation.parentDelegationId;
      }
      return clone({
        link: link ?? null,
        humanSubject: link
          ? state.principals.get(link.principalId) ?? null
          : null,
        workloadActor:
          state.principals.get(workloadActorPrincipalId) ?? null,
        principals: Array.from(state.principals.values()).filter(
          (principal) =>
            principal.tenantId === tenantId &&
            principalIds.has(principal.principalId),
        ),
        delegations,
      });
    },
  });
}

function eventFor({
  idFactory,
  clock,
  type,
  subject,
  tenantId,
  correlationId,
  commandActorId,
  data,
}) {
  return {
    specversion: "1.0",
    id: `evt_${idFactory()}`,
    source: "/product-core/stable-principal",
    type,
    subject,
    time: clock(),
    datacontenttype: "application/json",
    dataschema: "https://contracts.example/c05/stable-principal-event.v1.json",
    tenantkind: "SYNTHETIC",
    correlationid: correlationId,
    synthetic: true,
    data: {
      tenant_id: tenantId,
      command_actor_id: commandActorId,
      ...data,
    },
  };
}

function safePrincipal(principal) {
  return {
    principalId: principal.principalId,
    tenantId: principal.tenantId,
    principalType: principal.principalType,
    fixturePrincipalRef: principal.fixturePrincipalRef,
    state: principal.state,
    lifecycleVersion: principal.lifecycleVersion,
    securityEpoch: principal.securityEpoch,
    createdAt: principal.createdAt,
    updatedAt: principal.updatedAt,
  };
}

function safeLink(link) {
  return {
    identityLinkId: link.identityLinkId,
    tenantId: link.tenantId,
    identityAccountId: link.identityAccountId,
    providerConnectionId: link.providerConnectionId,
    principalId: link.principalId,
    state: link.state,
    lifecycleVersion: link.lifecycleVersion,
    accountLifecycleVersion: link.accountLifecycleVersion,
    accountRevocationEpoch: link.accountRevocationEpoch,
    linkEvidenceRef: link.linkEvidenceRef,
    createdAt: link.createdAt,
    updatedAt: link.updatedAt,
    retiredAt: link.retiredAt,
  };
}

function safeDelegation(delegation) {
  return {
    delegationId: delegation.delegationId,
    tenantId: delegation.tenantId,
    humanSubjectPrincipalId: delegation.humanSubjectPrincipalId,
    delegatorPrincipalId: delegation.delegatorPrincipalId,
    delegatePrincipalId: delegation.delegatePrincipalId,
    parentDelegationId: delegation.parentDelegationId,
    depth: delegation.depth,
    purposeRef: delegation.purposeRef,
    state: delegation.state,
    lifecycleVersion: delegation.lifecycleVersion,
    issuedAt: delegation.issuedAt,
    expiresAt: delegation.expiresAt,
    revokedAt: delegation.revokedAt,
    revocationReasonRef: delegation.revocationReasonRef,
  };
}

function transitionAllowed(current, desired) {
  return (
    (current === "ACTIVE" &&
      ["SUSPENDED", "DEACTIVATED"].includes(desired)) ||
    (current === "SUSPENDED" &&
      ["ACTIVE", "DEACTIVATED"].includes(desired))
  );
}

export function createStablePrincipalRegistry({
  store,
  tenantRegistry,
  tenantRegistryContext,
  identityFederation,
  identityFederationReadContext,
  identityFederationServerContext,
  principalCatalog,
  authorize,
  clock = () => new Date().toISOString(),
  idFactory = uuidV7,
}) {
  if (
    !store?.runCommand ||
    !store?.readTenantSnapshot ||
    !store?.readActionSnapshot ||
    !tenantRegistry?.snapshot ||
    !identityFederation?.snapshot ||
    !identityFederation?.resolveSession ||
    !principalCatalog?.resolvePrincipal ||
    !principalCatalog?.resolveIdentityCorrection ||
    typeof authorize !== "function" ||
    typeof clock !== "function" ||
    typeof idFactory !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C05 dependencies are incomplete.");
  }

  async function isAuthorized(context, capability) {
    try {
      return (
        context?.synthetic === true &&
        Boolean(await authorize(context, capability))
      );
    } catch {
      return false;
    }
  }

  function now() {
    const value = clock();
    isoMillis(value, "clock");
    return value;
  }

  async function tenantSnapshot(tenantId, requireActive) {
    let tenant;
    try {
      tenant = await tenantRegistry.snapshot(
        tenantRegistryContext,
        tenantId,
      );
    } catch {
      fail("DEPENDENCY_UNAVAILABLE", "Tenant verification failed.");
    }
    if (
      tenant?.tenantId !== tenantId ||
      tenant.tenantKind !== "SYNTHETIC" ||
      tenant.synthetic !== true ||
      !tenant.fixtureRef
    ) {
      fail(
        "SYNTHETIC_BOUNDARY_VIOLATION",
        "Tenant is not a verified Synthetic Tenant.",
      );
    }
    if (requireActive && tenant.state !== "ACTIVE") {
      fail("TENANT_NOT_ACTIVE", "Tenant is not active.");
    }
    return tenant;
  }

  async function identitySnapshot(tenantId) {
    let value;
    try {
      value = await identityFederation.snapshot(
        identityFederationReadContext,
        { tenantId },
      );
    } catch {
      fail("DEPENDENCY_UNAVAILABLE", "C04 identity verification failed.");
    }
    if (
      value?.tenantId !== tenantId ||
      value.tenantKind !== "SYNTHETIC" ||
      value.authorizationStatus !== "NOT_EVALUATED" ||
      !Array.isArray(value.accounts)
    ) {
      fail("DEPENDENCY_UNAVAILABLE", "C04 returned an invalid safe snapshot.");
    }
    return value;
  }

  function validateC04Account(account, tenantId) {
    if (
      !account ||
      !IDENTITY_ACCOUNT_ID.test(account.accountId ?? "") ||
      account.tenantId !== tenantId ||
      typeof account.providerConnectionId !== "string" ||
      account.providerConnectionId.length === 0 ||
      account.providerConnectionId.length > 80 ||
      !["ACTIVE", "SUSPENDED", "TERMINATED"].includes(account.state) ||
      !Number.isSafeInteger(account.lifecycleVersion) ||
      account.lifecycleVersion < 1 ||
      !Number.isSafeInteger(account.revocationEpoch) ||
      account.revocationEpoch < 1 ||
      !REFERENCE.test(account.profileRef ?? "")
    ) {
      fail("DEPENDENCY_UNAVAILABLE", "C04 returned an invalid account.");
    }
    return account;
  }

  async function activeIdentityAccount(tenantId, identityAccountId) {
    const identity = await identitySnapshot(tenantId);
    const account = identity.accounts
      .map((candidate) => validateC04Account(candidate, tenantId))
      .find(({ accountId }) => accountId === identityAccountId);
    if (!account) {
      fail("IDENTITY_ACCOUNT_NOT_FOUND", "Identity Account was not found.");
    }
    if (account.state !== "ACTIVE") {
      fail(
        "IDENTITY_ACCOUNT_NOT_ACTIVE",
        "Identity Account is not active.",
      );
    }
    return account;
  }

  async function currentIdentityAccount(tenantId, identityAccountId) {
    const identity = await identitySnapshot(tenantId);
    const account = identity.accounts
      .map((candidate) => validateC04Account(candidate, tenantId))
      .find(({ accountId }) => accountId === identityAccountId);
    if (!account) {
      fail("IDENTITY_ACCOUNT_NOT_FOUND", "Identity Account was not found.");
    }
    if (!["ACTIVE", "SUSPENDED", "TERMINATED"].includes(account.state)) {
      fail("DEPENDENCY_UNAVAILABLE", "C04 returned an invalid account state.");
    }
    return account;
  }

  async function emit(tx, context, command, type, subject, data) {
    const event = eventFor({
      idFactory,
      clock: now,
      type,
      subject,
      tenantId: command.tenantId,
      correlationId: command.correlationId,
      commandActorId: context.actorId,
      data,
    });
    await tx.appendEvent(event);
    await tx.appendOutbox(event);
    return event.id;
  }

  async function revokeDelegations(tx, tenantId, principalIds, reasonRef) {
    const delegations = await tx.listDelegations(tenantId);
    const revokedIds = new Set();
    for (const delegation of delegations) {
      if (
        delegation.state === "ACTIVE" &&
        [
          delegation.humanSubjectPrincipalId,
          delegation.delegatorPrincipalId,
          delegation.delegatePrincipalId,
        ].some((principalId) => principalIds.has(principalId))
      ) {
        revokedIds.add(delegation.delegationId);
      }
    }
    let changed = true;
    while (changed) {
      changed = false;
      for (const delegation of delegations) {
        if (
          delegation.state === "ACTIVE" &&
          delegation.parentDelegationId &&
          revokedIds.has(delegation.parentDelegationId) &&
          !revokedIds.has(delegation.delegationId)
        ) {
          revokedIds.add(delegation.delegationId);
          changed = true;
        }
      }
    }
    const timestamp = now();
    const toRevoke = delegations
      .filter(({ delegationId }) => revokedIds.has(delegationId))
      .sort((left, right) => right.depth - left.depth);
    for (const delegation of toRevoke) {
      await tx.putDelegation({
        ...delegation,
        state: "REVOKED",
        lifecycleVersion: delegation.lifecycleVersion + 1,
        revokedAt: timestamp,
        revocationReasonRef: reasonRef,
      });
    }
    return revokedIds.size;
  }

  async function bumpPrincipalSecurity(tx, principal, timestamp) {
    const updated = {
      ...principal,
      securityEpoch: principal.securityEpoch + 1,
      updatedAt: timestamp,
    };
    await tx.putPrincipal(updated);
    return updated;
  }

  async function registerPrincipal(tx, context, command, tenant) {
    const catalogEntry = principalCatalog.resolvePrincipal(
      tenant.fixtureRef,
      command.fixturePrincipalRef,
    );
    const existing = await tx.findPrincipalByFixture(
      command.tenantId,
      command.fixturePrincipalRef,
    );
    if (existing) {
      if (existing.principalType !== catalogEntry.principalType) {
        fail("PRINCIPAL_IMMUTABLE", "Principal type cannot change.");
      }
      return {
        principal: safePrincipal(existing),
        applied: false,
      };
    }
    const timestamp = now();
    const principal = {
      principalId: generatedIdentifier(
        "prn_",
        PRINCIPAL_ID,
        "generated principalId",
        idFactory,
      ),
      tenantId: command.tenantId,
      tenantKind: "SYNTHETIC",
      principalType: catalogEntry.principalType,
      fixturePrincipalRef: catalogEntry.fixturePrincipalRef,
      state: "ACTIVE",
      lifecycleVersion: 1,
      securityEpoch: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    await tx.insertPrincipal(principal);
    const eventId = await emit(
      tx,
      context,
      command,
      "product.principal.registered.v1",
      principal.principalId,
      {
        principal_id: principal.principalId,
        principal_type: principal.principalType,
        lifecycle_version: principal.lifecycleVersion,
        security_epoch: principal.securityEpoch,
      },
    );
    return {
      principal: safePrincipal(principal),
      eventId,
      applied: true,
    };
  }

  async function linkIdentityAccount(
    tx,
    context,
    command,
    tenant,
    account,
  ) {
    const principal = await tx.loadPrincipalForUpdate(command.principalId);
    if (!principal || principal.tenantId !== command.tenantId) {
      fail("PRINCIPAL_NOT_FOUND", "Principal was not found.");
    }
    if (principal.principalType !== "HUMAN") {
      fail(
        "PRINCIPAL_TYPE_MISMATCH",
        "Only a HUMAN Stable Principal can own an Identity Account.",
      );
    }
    if (principal.state !== "ACTIVE") {
      fail("PRINCIPAL_NOT_ACTIVE", "Principal is not active.");
    }
    const catalogEntry = principalCatalog.resolvePrincipal(
      tenant.fixtureRef,
      principal.fixturePrincipalRef,
    );
    if (!catalogEntry.identityProfileRefs.includes(account.profileRef)) {
      fail(
        "IDENTITY_LINK_CONFLICT",
        "Frozen synthetic identity mapping does not match this Principal.",
      );
    }
    const current = await tx.loadCurrentIdentityLinkForAccount(
      command.tenantId,
      command.identityAccountId,
    );
    if (current) {
      if (current.principalId !== principal.principalId) {
        fail(
          "IDENTITY_LINK_CONFLICT",
          "Identity Account is linked to another Stable Principal.",
        );
      }
      return {
        identityLink: safeLink(current),
        principal: safePrincipal(principal),
        applied: false,
      };
    }
    const timestamp = now();
    const link = {
      identityLinkId: generatedIdentifier(
        "lnk_",
        IDENTITY_LINK_ID,
        "generated identityLinkId",
        idFactory,
      ),
      tenantId: command.tenantId,
      tenantKind: "SYNTHETIC",
      identityAccountId: account.accountId,
      providerConnectionId: account.providerConnectionId,
      principalId: principal.principalId,
      principalType: "HUMAN",
      state: "ACTIVE",
      lifecycleVersion: 1,
      accountLifecycleVersion: account.lifecycleVersion,
      accountRevocationEpoch: account.revocationEpoch,
      linkEvidenceRef: command.linkEvidenceRef,
      createdAt: timestamp,
      updatedAt: timestamp,
      retiredAt: null,
    };
    await tx.insertIdentityLink(link);
    const updatedPrincipal = await bumpPrincipalSecurity(
      tx,
      principal,
      timestamp,
    );
    await revokeDelegations(
      tx,
      command.tenantId,
      new Set([principal.principalId]),
      "synthetic://c05/identity-link-changed",
    );
    const eventId = await emit(
      tx,
      context,
      command,
      "product.principal.identity-linked.v1",
      principal.principalId,
      {
        principal_id: principal.principalId,
        identity_link_id: link.identityLinkId,
        identity_account_id: link.identityAccountId,
        security_epoch: updatedPrincipal.securityEpoch,
      },
    );
    return {
      identityLink: safeLink(link),
      principal: safePrincipal(updatedPrincipal),
      eventId,
      applied: true,
    };
  }

  async function retireIdentityLink(tx, context, command) {
    const link = await tx.loadIdentityLinkForUpdate(command.identityLinkId);
    if (!link || link.tenantId !== command.tenantId) {
      fail("IDENTITY_LINK_NOT_FOUND", "Identity Link was not found.");
    }
    if (link.lifecycleVersion !== command.expectedVersion) {
      fail("VERSION_CONFLICT", "Identity Link version changed.");
    }
    if (link.state === "RETIRED") {
      fail("IDENTITY_LINK_RETIRED", "Identity Link is already retired.");
    }
    const principal = await tx.loadPrincipalForUpdate(link.principalId);
    const timestamp = now();
    const retired = {
      ...link,
      state: "RETIRED",
      lifecycleVersion: link.lifecycleVersion + 1,
      updatedAt: timestamp,
      retiredAt: timestamp,
    };
    await tx.putIdentityLink(retired);
    const updatedPrincipal = await bumpPrincipalSecurity(
      tx,
      principal,
      timestamp,
    );
    const revokedDelegations = await revokeDelegations(
      tx,
      command.tenantId,
      new Set([principal.principalId]),
      command.reasonRef,
    );
    const eventId = await emit(
      tx,
      context,
      command,
      "product.principal.identity-link-retired.v1",
      principal.principalId,
      {
        principal_id: principal.principalId,
        identity_link_id: retired.identityLinkId,
        security_epoch: updatedPrincipal.securityEpoch,
        revoked_delegations: revokedDelegations,
        reason_ref: command.reasonRef,
      },
    );
    return {
      identityLink: safeLink(retired),
      principal: safePrincipal(updatedPrincipal),
      eventId,
      applied: true,
    };
  }

  async function reassignIdentityAccount(
    tx,
    context,
    command,
    tenant,
    account,
    link,
  ) {
    if (!link || link.tenantId !== command.tenantId) {
      fail("IDENTITY_LINK_NOT_FOUND", "Identity Link was not found.");
    }
    if (link.lifecycleVersion !== command.expectedVersion) {
      fail("VERSION_CONFLICT", "Identity Link version changed.");
    }
    if (link.state === "RETIRED") {
      fail("IDENTITY_LINK_RETIRED", "Identity Link is already retired.");
    }
    if (
      account.state === "TERMINATED" ||
      account.accountId !== link.identityAccountId ||
      account.providerConnectionId !== link.providerConnectionId ||
      account.state !== link.state ||
      account.lifecycleVersion !== link.accountLifecycleVersion ||
      account.revocationEpoch !== link.accountRevocationEpoch
    ) {
      fail(
        "IDENTITY_LINK_CONFLICT",
        "Identity Link does not match the current C04 account.",
      );
    }
    if (link.principalId === command.targetPrincipalId) {
      fail("IDENTITY_LINK_CONFLICT", "Target Principal is unchanged.");
    }
    const principalIds = [link.principalId, command.targetPrincipalId].sort();
    const principals = new Map();
    for (const principalId of principalIds) {
      const principal = await tx.loadPrincipalForUpdate(principalId);
      if (!principal || principal.tenantId !== command.tenantId) {
        fail("PRINCIPAL_NOT_FOUND", "Principal was not found.");
      }
      principals.set(principalId, principal);
    }
    const sourcePrincipal = principals.get(link.principalId);
    const targetPrincipal = principals.get(command.targetPrincipalId);
    if (
      sourcePrincipal.principalType !== "HUMAN" ||
      targetPrincipal.principalType !== "HUMAN"
    ) {
      fail(
        "PRINCIPAL_TYPE_MISMATCH",
        "Identity correction requires HUMAN Principals.",
      );
    }
    if (targetPrincipal.state !== "ACTIVE") {
      fail("PRINCIPAL_NOT_ACTIVE", "Target Principal is not active.");
    }
    const correction = principalCatalog.resolveIdentityCorrection(
      tenant.fixtureRef,
      command.reasonRef,
    );
    const expectedMappingHash = await sha256({
      correctionRef: correction.correctionRef,
      identityProfileRef: correction.identityProfileRef,
      sourceFixturePrincipalRef:
        correction.sourceFixturePrincipalRef,
      targetFixturePrincipalRef:
        correction.targetFixturePrincipalRef,
    });
    if (correction.mappingHash !== expectedMappingHash) {
      fail(
        "INVALID_PRINCIPAL_CATALOG",
        "Identity correction mappingHash does not match its frozen mapping.",
      );
    }
    if (
      correction.identityProfileRef !== account.profileRef ||
      correction.sourceFixturePrincipalRef !==
        sourcePrincipal.fixturePrincipalRef ||
      correction.targetFixturePrincipalRef !==
        targetPrincipal.fixturePrincipalRef
    ) {
      fail(
        "IDENTITY_LINK_CONFLICT",
        "Frozen synthetic correction mapping does not match this Principal.",
      );
    }
    const timestamp = now();
    const retired = {
      ...link,
      state: "RETIRED",
      lifecycleVersion: link.lifecycleVersion + 1,
      updatedAt: timestamp,
      retiredAt: timestamp,
    };
    await tx.putIdentityLink(retired);
    const replacement = {
      ...link,
      identityLinkId: generatedIdentifier(
        "lnk_",
        IDENTITY_LINK_ID,
        "generated identityLinkId",
        idFactory,
      ),
      principalId: targetPrincipal.principalId,
      state: link.state,
      lifecycleVersion: 1,
      linkEvidenceRef: command.reasonRef,
      createdAt: timestamp,
      updatedAt: timestamp,
      retiredAt: null,
    };
    await tx.insertIdentityLink(replacement);
    const updatedSource = await bumpPrincipalSecurity(
      tx,
      sourcePrincipal,
      timestamp,
    );
    const updatedTarget = await bumpPrincipalSecurity(
      tx,
      targetPrincipal,
      timestamp,
    );
    const revokedDelegations = await revokeDelegations(
      tx,
      command.tenantId,
      new Set([sourcePrincipal.principalId, targetPrincipal.principalId]),
      command.reasonRef,
    );
    const eventId = await emit(
      tx,
      context,
      command,
      "product.principal.identity-link-reassigned.v1",
      replacement.principalId,
      {
        old_principal_id: sourcePrincipal.principalId,
        new_principal_id: targetPrincipal.principalId,
        retired_identity_link_id: retired.identityLinkId,
        new_identity_link_id: replacement.identityLinkId,
        revoked_delegations: revokedDelegations,
        correction_ref: correction.correctionRef,
        correction_mapping_hash: correction.mappingHash,
      },
    );
    return {
      retiredIdentityLink: safeLink(retired),
      identityLink: safeLink(replacement),
      sourcePrincipal: safePrincipal(updatedSource),
      targetPrincipal: safePrincipal(updatedTarget),
      eventId,
      applied: true,
    };
  }

  async function changePrincipalState(tx, context, command) {
    const principal = await tx.loadPrincipalForUpdate(command.principalId);
    if (!principal || principal.tenantId !== command.tenantId) {
      fail("PRINCIPAL_NOT_FOUND", "Principal was not found.");
    }
    if (principal.lifecycleVersion !== command.expectedVersion) {
      fail("VERSION_CONFLICT", "Principal version changed.");
    }
    if (!transitionAllowed(principal.state, command.desiredState)) {
      fail("INVALID_PRINCIPAL_STATE", "Principal state transition is invalid.");
    }
    const timestamp = now();
    let retiredLinks = 0;
    if (command.desiredState === "DEACTIVATED") {
      for (const link of await tx.listIdentityLinks(command.tenantId)) {
        if (
          link.principalId === principal.principalId &&
          link.state !== "RETIRED"
        ) {
          await tx.putIdentityLink({
            ...link,
            state: "RETIRED",
            lifecycleVersion: link.lifecycleVersion + 1,
            updatedAt: timestamp,
            retiredAt: timestamp,
          });
          retiredLinks += 1;
        }
      }
    }
    const revokedDelegations = await revokeDelegations(
      tx,
      command.tenantId,
      new Set([principal.principalId]),
      command.reasonRef,
    );
    const updated = {
      ...principal,
      state: command.desiredState,
      lifecycleVersion: principal.lifecycleVersion + 1,
      securityEpoch: principal.securityEpoch + 1,
      updatedAt: timestamp,
    };
    await tx.putPrincipal(updated);
    const eventId = await emit(
      tx,
      context,
      command,
      "product.principal.state-changed.v1",
      principal.principalId,
      {
        principal_id: principal.principalId,
        old_state: principal.state,
        new_state: updated.state,
        lifecycle_version: updated.lifecycleVersion,
        security_epoch: updated.securityEpoch,
        retired_identity_links: retiredLinks,
        revoked_delegations: revokedDelegations,
        reason_ref: command.reasonRef,
      },
    );
    return {
      principal: safePrincipal(updated),
      retiredIdentityLinks: retiredLinks,
      revokedDelegations,
      eventId,
      applied: true,
    };
  }

  async function syncIdentityAccount(tx, context, command, account) {
    const link = await tx.loadCurrentIdentityLinkForAccount(
      command.tenantId,
      account.accountId,
    );
    if (!link) {
      return {
        identityAccountId: account.accountId,
        linked: false,
        applied: false,
      };
    }
    if (link.providerConnectionId !== account.providerConnectionId) {
      fail(
        "IDENTITY_LINK_CONFLICT",
        "Identity Account provider binding changed unexpectedly.",
      );
    }
    if (
      account.lifecycleVersion < link.accountLifecycleVersion ||
      account.revocationEpoch < link.accountRevocationEpoch
    ) {
      return {
        identityLink: safeLink(link),
        stale: true,
        applied: false,
      };
    }
    const desiredState =
      account.state === "TERMINATED" ? "RETIRED" : account.state;
    if (!LINK_STATES.includes(desiredState)) {
      fail("DEPENDENCY_UNAVAILABLE", "C04 account state cannot be projected.");
    }
    if (
      desiredState === link.state &&
      account.lifecycleVersion === link.accountLifecycleVersion &&
      account.revocationEpoch === link.accountRevocationEpoch
    ) {
      return {
        identityLink: safeLink(link),
        applied: false,
      };
    }
    const principal = await tx.loadPrincipalForUpdate(link.principalId);
    const timestamp = now();
    const updatedLink = {
      ...link,
      state: desiredState,
      lifecycleVersion: link.lifecycleVersion + 1,
      accountLifecycleVersion: account.lifecycleVersion,
      accountRevocationEpoch: account.revocationEpoch,
      updatedAt: timestamp,
      retiredAt: desiredState === "RETIRED" ? timestamp : null,
    };
    await tx.putIdentityLink(updatedLink);
    const updatedPrincipal = await bumpPrincipalSecurity(
      tx,
      principal,
      timestamp,
    );
    const revokedDelegations = await revokeDelegations(
      tx,
      command.tenantId,
      new Set([principal.principalId]),
      "synthetic://c05/c04-account-lifecycle-changed",
    );
    const eventId = await emit(
      tx,
      context,
      command,
      "product.principal.identity-link-synchronized.v1",
      principal.principalId,
      {
        principal_id: principal.principalId,
        identity_link_id: updatedLink.identityLinkId,
        identity_account_id: updatedLink.identityAccountId,
        link_state: updatedLink.state,
        account_lifecycle_version: updatedLink.accountLifecycleVersion,
        account_revocation_epoch: updatedLink.accountRevocationEpoch,
        security_epoch: updatedPrincipal.securityEpoch,
        revoked_delegations: revokedDelegations,
      },
    );
    return {
      identityLink: safeLink(updatedLink),
      principal: safePrincipal(updatedPrincipal),
      eventId,
      applied: true,
    };
  }

  async function delegationChainForUpdate(
    tx,
    tenantId,
    parentDelegationId,
    nowMilliseconds,
  ) {
    const reversed = [];
    const seenDelegations = new Set();
    let currentId = parentDelegationId;
    while (currentId) {
      if (
        seenDelegations.has(currentId) ||
        reversed.length >= MAX_DELEGATION_DEPTH
      ) {
        fail("DELEGATION_INVALID", "Delegation parent chain is invalid.");
      }
      seenDelegations.add(currentId);
      const current = await tx.loadDelegationForUpdate(currentId);
      if (
        !current ||
        current.tenantId !== tenantId ||
        current.state !== "ACTIVE" ||
        isoMillis(current.expiresAt, "expiresAt") <= nowMilliseconds
      ) {
        fail("DELEGATION_INVALID", "Delegation parent is not active.");
      }
      reversed.push(current);
      currentId = current.parentDelegationId;
    }
    return reversed.reverse();
  }

  async function createDelegation(tx, context, command) {
    const timestamp = now();
    const nowMilliseconds = isoMillis(timestamp, "clock");
    const expiresAt = isoMillis(command.expiresAt, "expiresAt");
    if (expiresAt <= nowMilliseconds) {
      fail("DELEGATION_INVALID", "Delegation must have a future expiry.");
    }
    const principalIds = Array.from(
      new Set([
        command.humanSubjectPrincipalId,
        command.delegatorPrincipalId,
        command.delegatePrincipalId,
      ]),
    ).sort();
    const principals = new Map();
    for (const principalId of principalIds) {
      const principal = await tx.loadPrincipalForUpdate(principalId);
      if (
        !principal ||
        principal.tenantId !== command.tenantId ||
        principal.state !== "ACTIVE"
      ) {
        fail("PRINCIPAL_NOT_ACTIVE", "Delegation endpoint is not active.");
      }
      principals.set(principalId, principal);
    }
    const humanSubject = principals.get(command.humanSubjectPrincipalId);
    const delegator = principals.get(command.delegatorPrincipalId);
    const delegate = principals.get(command.delegatePrincipalId);
    if (humanSubject.principalType !== "HUMAN") {
      fail(
        "PRINCIPAL_TYPE_MISMATCH",
        "Delegation root must be a HUMAN Principal.",
      );
    }
    if (!["AGENT", "SERVICE"].includes(delegate.principalType)) {
      fail(
        "PRINCIPAL_TYPE_MISMATCH",
        "Delegation target must be an AGENT or SERVICE Principal.",
      );
    }
    if (delegator.principalId === delegate.principalId) {
      fail("DELEGATION_INVALID", "Self delegation is forbidden.");
    }

    let parentChain = [];
    if (command.parentDelegationId === undefined) {
      if (
        delegator.principalId !== humanSubject.principalId ||
        delegator.principalType !== "HUMAN"
      ) {
        fail(
          "DELEGATION_INVALID",
          "A root delegation must start at its HUMAN Subject.",
        );
      }
    } else {
      parentChain = await delegationChainForUpdate(
        tx,
        command.tenantId,
        command.parentDelegationId,
        nowMilliseconds,
      );
      const parent = parentChain.at(-1);
      if (
        parent.humanSubjectPrincipalId !== humanSubject.principalId ||
        parent.delegatePrincipalId !== delegator.principalId ||
        parent.purposeRef !== command.purposeRef ||
        expiresAt > isoMillis(parent.expiresAt, "parent.expiresAt")
      ) {
        fail("DELEGATION_INVALID", "Delegation chain is not continuous.");
      }
      if (!["AGENT", "SERVICE"].includes(delegator.principalType)) {
        fail(
          "PRINCIPAL_TYPE_MISMATCH",
          "A forwarded delegation must be made by a workload Principal.",
        );
      }
    }
    const chainPrincipalIds = new Set([humanSubject.principalId]);
    for (const parent of parentChain) {
      chainPrincipalIds.add(parent.delegatorPrincipalId);
      chainPrincipalIds.add(parent.delegatePrincipalId);
    }
    if (chainPrincipalIds.has(delegate.principalId)) {
      fail("DELEGATION_INVALID", "Delegation cycles are forbidden.");
    }
    const depth = parentChain.length + 1;
    if (depth > MAX_DELEGATION_DEPTH) {
      fail("DELEGATION_INVALID", "Delegation chain is too deep.");
    }
    const delegation = {
      delegationId: generatedIdentifier(
        "dlg_",
        DELEGATION_ID,
        "generated delegationId",
        idFactory,
      ),
      tenantId: command.tenantId,
      tenantKind: "SYNTHETIC",
      humanSubjectPrincipalId: humanSubject.principalId,
      humanSubjectKind: humanSubject.principalType,
      delegatorPrincipalId: delegator.principalId,
      delegatorKind: delegator.principalType,
      delegatePrincipalId: delegate.principalId,
      delegateKind: delegate.principalType,
      parentDelegationId: command.parentDelegationId ?? null,
      depth,
      purposeRef: command.purposeRef,
      humanSubjectSecurityEpoch: humanSubject.securityEpoch,
      delegatorSecurityEpoch: delegator.securityEpoch,
      delegateSecurityEpoch: delegate.securityEpoch,
      state: "ACTIVE",
      lifecycleVersion: 1,
      issuedAt: timestamp,
      expiresAt: command.expiresAt,
      revokedAt: null,
      revocationReasonRef: null,
    };
    await tx.insertDelegation(delegation);
    const eventId = await emit(
      tx,
      context,
      command,
      "product.principal.delegation-created.v1",
      delegation.delegationId,
      {
        delegation_id: delegation.delegationId,
        human_subject_principal_id:
          delegation.humanSubjectPrincipalId,
        delegator_principal_id: delegation.delegatorPrincipalId,
        delegate_principal_id: delegation.delegatePrincipalId,
        parent_delegation_id: delegation.parentDelegationId,
        depth: delegation.depth,
        expires_at: delegation.expiresAt,
      },
    );
    return {
      delegation: safeDelegation(delegation),
      eventId,
      applied: true,
    };
  }

  async function revokeDelegation(tx, context, command) {
    const delegation = await tx.loadDelegationForUpdate(command.delegationId);
    if (!delegation || delegation.tenantId !== command.tenantId) {
      fail("DELEGATION_NOT_FOUND", "Delegation was not found.");
    }
    if (delegation.lifecycleVersion !== command.expectedVersion) {
      fail("VERSION_CONFLICT", "Delegation version changed.");
    }
    if (delegation.state !== "ACTIVE") {
      fail("DELEGATION_INVALID", "Delegation is not active.");
    }
    const all = await tx.listDelegations(command.tenantId);
    const revokedIds = new Set([delegation.delegationId]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const candidate of all) {
        if (
          candidate.state === "ACTIVE" &&
          candidate.parentDelegationId &&
          revokedIds.has(candidate.parentDelegationId) &&
          !revokedIds.has(candidate.delegationId)
        ) {
          revokedIds.add(candidate.delegationId);
          changed = true;
        }
      }
    }
    const timestamp = now();
    const toRevoke = all
      .filter(({ delegationId }) => revokedIds.has(delegationId))
      .sort((left, right) => right.depth - left.depth);
    for (const current of toRevoke) {
      await tx.putDelegation({
        ...current,
        state: "REVOKED",
        lifecycleVersion: current.lifecycleVersion + 1,
        revokedAt: timestamp,
        revocationReasonRef: command.reasonRef,
      });
    }
    const eventId = await emit(
      tx,
      context,
      command,
      "product.principal.delegation-revoked.v1",
      delegation.delegationId,
      {
        delegation_id: delegation.delegationId,
        revoked_delegations: revokedIds.size,
        reason_ref: command.reasonRef,
      },
    );
    return {
      delegationId: delegation.delegationId,
      revokedDelegations: revokedIds.size,
      eventId,
      applied: true,
    };
  }

  async function execute(context, command) {
    validateCommand(command);
    const capability = CAPABILITIES[command.kind];
    if (!(await isAuthorized(context, capability))) {
      fail("UNAUTHORIZED", "Stable Principal command is not authorized.");
    }
    nonEmptyString(context.actorId, "context.actorId", 128);
    const requireActive = [
      "CREATE_SYNTHETIC_PRINCIPAL",
      "LINK_IDENTITY_ACCOUNT",
      "REASSIGN_IDENTITY_ACCOUNT",
      "CREATE_DELEGATION",
    ].includes(command.kind) ||
      (command.kind === "CHANGE_PRINCIPAL_STATE" &&
        command.desiredState === "ACTIVE");
    const commandHash = await sha256({
      actorId: context.actorId,
      command,
    });
    let reassignmentAccountId = null;
    if (command.kind === "REASSIGN_IDENTITY_ACCOUNT") {
      const value = await store.readTenantSnapshot(command.tenantId);
      const link = value.links.find(
        ({ identityLinkId }) =>
          identityLinkId === command.identityLinkId,
      );
      if (!link) {
        fail("IDENTITY_LINK_NOT_FOUND", "Identity Link was not found.");
      }
      reassignmentAccountId = link.identityAccountId;
    }
    const preflight = async () => {
      const tenant = await tenantSnapshot(
        command.tenantId,
        requireActive,
      );
      let account = null;
      if (command.kind === "LINK_IDENTITY_ACCOUNT") {
        account = await activeIdentityAccount(
          command.tenantId,
          command.identityAccountId,
        );
      }
      if (command.kind === "SYNC_IDENTITY_ACCOUNT") {
        account = await currentIdentityAccount(
          command.tenantId,
          command.identityAccountId,
        );
        if (tenant.state !== "ACTIVE" && account.state === "ACTIVE") {
          fail(
            "TENANT_NOT_ACTIVE",
            "An inactive Tenant cannot restore an Identity Link.",
          );
        }
      }
      if (command.kind === "REASSIGN_IDENTITY_ACCOUNT") {
        account = await currentIdentityAccount(
          command.tenantId,
          reassignmentAccountId,
        );
      }
      return { tenant, account };
    };
    const stored = await store.runCommand(
      {
        tenantId: command.tenantId,
        idempotencyKey: command.idempotencyKey,
        commandHash,
      },
      async (tx, { tenant, account }) => {
        let reassignmentLink = null;
        if (command.kind === "REASSIGN_IDENTITY_ACCOUNT") {
          reassignmentLink = await tx.loadIdentityLinkForUpdate(
            command.identityLinkId,
          );
          if (
            !reassignmentLink ||
            reassignmentLink.tenantId !== command.tenantId
          ) {
            fail("IDENTITY_LINK_NOT_FOUND", "Identity Link was not found.");
          }
        }
        if (command.kind === "CREATE_SYNTHETIC_PRINCIPAL") {
          return registerPrincipal(tx, context, command, tenant);
        }
        if (command.kind === "LINK_IDENTITY_ACCOUNT") {
          return linkIdentityAccount(
            tx,
            context,
            command,
            tenant,
            account,
          );
        }
        if (command.kind === "RETIRE_IDENTITY_LINK") {
          return retireIdentityLink(tx, context, command);
        }
        if (command.kind === "REASSIGN_IDENTITY_ACCOUNT") {
          return reassignIdentityAccount(
            tx,
            context,
            command,
            tenant,
            account,
            reassignmentLink,
          );
        }
        if (command.kind === "CHANGE_PRINCIPAL_STATE") {
          return changePrincipalState(tx, context, command);
        }
        if (command.kind === "SYNC_IDENTITY_ACCOUNT") {
          return syncIdentityAccount(tx, context, command, account);
        }
        if (command.kind === "CREATE_DELEGATION") {
          return createDelegation(tx, context, command);
        }
        return revokeDelegation(tx, context, command);
      },
      preflight,
    );
    return {
      commandKind: command.kind,
      tenantId: command.tenantId,
      ...stored.value,
      duplicate: stored.duplicate || stored.value.duplicate === true,
    };
  }

  function validateResolvedSession(value, expectedTenantId) {
    if (
      value?.tenantId !== expectedTenantId ||
      value.tenantKind !== "SYNTHETIC" ||
      typeof value.identityAccountId !== "string" ||
      typeof value.sessionId !== "string" ||
      value.trustSource !== "VERIFIED_SESSION" ||
      value.authorizationStatus !== "NOT_EVALUATED"
    ) {
      fail("ACTION_IDENTITY_INVALID", "C04 session context is invalid.");
    }
  }

  function buildDelegationChain(
    value,
    delegationId,
    expectedHumanSubjectId,
    expectedActorId,
    nowMilliseconds,
  ) {
    const principals = new Map(
      value.principals.map((principal) => [
        principal.principalId,
        principal,
      ]),
    );
    const delegations = new Map(
      value.delegations.map((delegation) => [
        delegation.delegationId,
        delegation,
      ]),
    );
    const reversed = [];
    const seenDelegations = new Set();
    const seenPrincipals = new Set([expectedActorId]);
    let currentId = delegationId;
    while (currentId) {
      if (
        seenDelegations.has(currentId) ||
        reversed.length >= MAX_DELEGATION_DEPTH
      ) {
        fail("ACTION_IDENTITY_INVALID", "Delegation chain is invalid.");
      }
      seenDelegations.add(currentId);
      const delegation = delegations.get(currentId);
      if (
        !delegation ||
        delegation.state !== "ACTIVE" ||
        delegation.humanSubjectPrincipalId !== expectedHumanSubjectId ||
        isoMillis(delegation.expiresAt, "expiresAt") <= nowMilliseconds
      ) {
        fail("ACTION_IDENTITY_INVALID", "Delegation chain is invalid.");
      }
      const human = principals.get(delegation.humanSubjectPrincipalId);
      const delegator = principals.get(delegation.delegatorPrincipalId);
      const delegate = principals.get(delegation.delegatePrincipalId);
      if (
        !human ||
        !delegator ||
        !delegate ||
        human.state !== "ACTIVE" ||
        delegator.state !== "ACTIVE" ||
        delegate.state !== "ACTIVE" ||
        human.securityEpoch !== delegation.humanSubjectSecurityEpoch ||
        delegator.securityEpoch !== delegation.delegatorSecurityEpoch ||
        delegate.securityEpoch !== delegation.delegateSecurityEpoch ||
        !["AGENT", "SERVICE"].includes(delegate.principalType)
      ) {
        fail("ACTION_IDENTITY_INVALID", "Delegation endpoint is invalid.");
      }
      if (seenPrincipals.has(delegation.delegatorPrincipalId)) {
        fail("ACTION_IDENTITY_INVALID", "Delegation chain contains a cycle.");
      }
      seenPrincipals.add(delegation.delegatorPrincipalId);
      reversed.push(delegation);
      currentId = delegation.parentDelegationId;
    }
    const chain = reversed.reverse();
    if (
      chain.length === 0 ||
      chain[0].delegatorPrincipalId !== expectedHumanSubjectId ||
      chain.at(-1).delegatePrincipalId !== expectedActorId
    ) {
      fail("ACTION_IDENTITY_INVALID", "Delegation endpoints do not match.");
    }
    for (let index = 1; index < chain.length; index += 1) {
      if (
        chain[index - 1].delegatePrincipalId !==
          chain[index].delegatorPrincipalId ||
        chain[index].depth !== chain[index - 1].depth + 1 ||
        chain[index].purposeRef !== chain[0].purposeRef ||
        isoMillis(chain[index].expiresAt, "expiresAt") >
          isoMillis(chain[index - 1].expiresAt, "expiresAt")
      ) {
        fail("ACTION_IDENTITY_INVALID", "Delegation chain is discontinuous.");
      }
    }
    return chain;
  }

  async function resolveC04Session(request) {
    try {
      const value = await identityFederation.resolveSession(
        identityFederationServerContext,
        {
          sessionToken: request.sessionToken,
          expectedTenantId: request.expectedTenantId,
        },
      );
      validateResolvedSession(value, request.expectedTenantId);
      return value;
    } catch (error) {
      if (error instanceof StablePrincipalError) throw error;
      fail("ACTION_IDENTITY_INVALID", "Session cannot be resolved.");
    }
  }

  function verifyActionSnapshot({
    value,
    session,
    workloadActorPrincipalId,
    delegationId,
    account,
  }) {
    if (
      !value?.link ||
      value.link.state !== "ACTIVE" ||
      value.link.identityAccountId !== session.identityAccountId ||
      !value.humanSubject ||
      value.link.principalId !== value.humanSubject.principalId ||
      value.humanSubject.principalType !== "HUMAN" ||
      value.humanSubject.state !== "ACTIVE" ||
      !value.workloadActor ||
      value.workloadActor.principalId !== workloadActorPrincipalId ||
      !["AGENT", "SERVICE"].includes(value.workloadActor.principalType) ||
      value.workloadActor.state !== "ACTIVE" ||
      !Array.isArray(value.principals) ||
      !Array.isArray(value.delegations) ||
      (account &&
        (account.accountId !== value.link.identityAccountId ||
          account.providerConnectionId !== value.link.providerConnectionId ||
          account.lifecycleVersion !== value.link.accountLifecycleVersion ||
          account.revocationEpoch !== value.link.accountRevocationEpoch))
    ) {
      fail("ACTION_IDENTITY_INVALID", "Action identity cannot be resolved.");
    }
    return buildDelegationChain(
      value,
      delegationId,
      value.humanSubject.principalId,
      value.workloadActor.principalId,
      isoMillis(now(), "clock"),
    );
  }

  async function resolveActionIdentity(serverContext, request) {
    exactKeys(
      request,
      ["sessionToken", "expectedTenantId", "delegationId"],
      "action identity request",
    );
    nonEmptyString(request.sessionToken, "sessionToken", 128);
    syntheticTenantId(request.expectedTenantId);
    identifier(request.delegationId, DELEGATION_ID, "delegationId");
    if (
      serverContext?.synthetic !== true ||
      serverContext.workloadTrustSource !== "VERIFIED_WORKLOAD_CONTEXT"
    ) {
      fail("ACTION_IDENTITY_INVALID", "Workload context is not verified.");
    }
    identifier(
      serverContext.workloadActorPrincipalId,
      PRINCIPAL_ID,
      "workloadActorPrincipalId",
    );
    const firstSession = await resolveC04Session(request);
    const firstValue = await store.readActionSnapshot({
      tenantId: request.expectedTenantId,
      identityAccountId: firstSession.identityAccountId,
      workloadActorPrincipalId: serverContext.workloadActorPrincipalId,
      delegationId: request.delegationId,
    });
    verifyActionSnapshot({
      value: firstValue,
      session: firstSession,
      workloadActorPrincipalId: serverContext.workloadActorPrincipalId,
      delegationId: request.delegationId,
    });
    const finalSession = await resolveC04Session(request);
    if (
      finalSession.identityAccountId !== firstSession.identityAccountId ||
      finalSession.sessionId !== firstSession.sessionId
    ) {
      fail("ACTION_IDENTITY_INVALID", "Session changed during resolution.");
    }
    const account = await activeIdentityAccount(
      request.expectedTenantId,
      finalSession.identityAccountId,
    );
    const value = await store.readActionSnapshot({
      tenantId: request.expectedTenantId,
      identityAccountId: finalSession.identityAccountId,
      workloadActorPrincipalId: serverContext.workloadActorPrincipalId,
      delegationId: request.delegationId,
    });
    const chain = verifyActionSnapshot({
      value,
      session: finalSession,
      workloadActorPrincipalId: serverContext.workloadActorPrincipalId,
      delegationId: request.delegationId,
      account,
    });
    return {
      tenantId: request.expectedTenantId,
      tenantKind: "SYNTHETIC",
      identityAccountId: firstSession.identityAccountId,
      identityLinkId: value.link.identityLinkId,
      sessionId: firstSession.sessionId,
      humanSubject: {
        principalId: value.humanSubject.principalId,
        principalType: value.humanSubject.principalType,
        lifecycleVersion: value.humanSubject.lifecycleVersion,
        securityEpoch: value.humanSubject.securityEpoch,
      },
      workloadActor: {
        principalId: value.workloadActor.principalId,
        principalType: value.workloadActor.principalType,
        lifecycleVersion: value.workloadActor.lifecycleVersion,
        securityEpoch: value.workloadActor.securityEpoch,
      },
      purposeRef: chain[0].purposeRef,
      delegationChain: chain.map((delegation) => ({
        delegationId: delegation.delegationId,
        delegatorPrincipalId: delegation.delegatorPrincipalId,
        delegatePrincipalId: delegation.delegatePrincipalId,
        purposeRef: delegation.purposeRef,
        lifecycleVersion: delegation.lifecycleVersion,
        expiresAt: delegation.expiresAt,
      })),
      trustSource:
        "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
      authorizationStatus: "NOT_EVALUATED",
    };
  }

  async function snapshot(context, query) {
    exactKeys(query, ["tenantId"], "snapshot query");
    syntheticTenantId(query.tenantId);
    if (!(await isAuthorized(context, "PRINCIPAL_READ"))) {
      fail("UNAUTHORIZED", "Stable Principal snapshot is not authorized.");
    }
    await tenantSnapshot(query.tenantId, false);
    const value = await store.readTenantSnapshot(query.tenantId);
    return {
      tenantId: query.tenantId,
      tenantKind: "SYNTHETIC",
      principals: value.principals.map(safePrincipal),
      identityLinks: value.links.map(safeLink),
      delegations: value.delegations.map(safeDelegation),
      events: clone(value.events),
      outbox: clone(value.outbox),
      authorizationStatus: "NOT_EVALUATED",
    };
  }

  return Object.freeze({
    execute,
    resolveActionIdentity,
    snapshot,
  });
}

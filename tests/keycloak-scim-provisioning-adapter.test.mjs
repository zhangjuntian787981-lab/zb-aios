import assert from "node:assert/strict";
import test from "node:test";
import {
  KeycloakScimProvisioningError,
  createKeycloakScimProvisioningAdapter,
} from "../lib/keycloak-scim-provisioning-adapter.mjs";

const ORIGIN = "https://scim.c04-synthetic.example";
const REALM = "synthetic";
const ISSUER = `${ORIGIN}/realms/${REALM}`;
const AUDIENCE = `${ISSUER}/scim/v2`;
const ACCESS_TOKEN = [
  "eyJhbGciOiJub25lIn0",
  Buffer.from(
    JSON.stringify({
      iss: ISSUER,
      aud: AUDIENCE,
      exp: 4102444800,
    }),
  ).toString("base64url"),
  "synthetic-signature",
].join(".");

function command(sourceRevision, familyName, desiredState = "ACTIVE") {
  return {
    externalId: "synthetic-directory-001",
    userName: "synthetic-user",
    sourceRevision,
    desiredState,
    profile: {
      givenName: "Synthetic",
      familyName,
      email: "synthetic-user@c04-synthetic.example",
    },
  };
}

function checkpointStore() {
  const records = new Map();
  const tails = new Map();
  let failNextConfirmation = false;
  return {
    failNextConfirmation() {
      failNextConfirmation = true;
    },
    snapshot(externalId) {
      return structuredClone(records.get(externalId) ?? null);
    },
    async transact(externalId, reducer) {
      const result = reducer(
        structuredClone(records.get(externalId) ?? null),
      );
      if (
        failNextConfirmation &&
        result.next?.status === "CONFIRMED"
      ) {
        failNextConfirmation = false;
        throw new Error("Synthetic confirmation failure.");
      }
      records.set(externalId, structuredClone(result.next));
      return structuredClone(result.value);
    },
    async runExclusive(externalId, operation) {
      const previous = tails.get(externalId) ?? Promise.resolve();
      let release;
      const gate = new Promise((resolve) => {
        release = resolve;
      });
      const tail = previous.then(() => gate);
      tails.set(externalId, tail);
      await previous;
      try {
        return await operation();
      } finally {
        release();
        if (tails.get(externalId) === tail) tails.delete(externalId);
      }
    },
  };
}

function jsonResponse(status, value) {
  return { status, body: JSON.stringify(value) };
}

function fakeScimTransport() {
  let remote = null;
  return {
    snapshot() {
      return structuredClone(remote);
    },
    async request({ url, method }) {
      const target = new URL(url);
      if (target.pathname.endsWith("/Users") && target.search) {
        return jsonResponse(200, {
          totalResults: remote ? 1 : 0,
          Resources: remote ? [remote] : [],
        });
      }
      const body = arguments[0].body
        ? JSON.parse(arguments[0].body)
        : null;
      if (target.pathname.endsWith("/Users") && method === "POST") {
        remote = { ...body, id: "synthetic-resource-001" };
        return jsonResponse(201, remote);
      }
      if (method === "PUT") {
        remote = { ...body, id: "synthetic-resource-001" };
        return jsonResponse(200, remote);
      }
      if (method === "GET" && target.pathname.endsWith(
        "/Users/synthetic-resource-001",
      )) {
        return jsonResponse(200, remote);
      }
      throw new Error("Unexpected synthetic SCIM request.");
    },
  };
}

function isAdapterError(code, forbidden = "") {
  return (error) => {
    assert.ok(error instanceof KeycloakScimProvisioningError);
    assert.equal(error.code, code);
    if (forbidden) assert.doesNotMatch(error.message, new RegExp(forbidden));
    return true;
  };
}

test("SCIM revisions run exclusively and finish in source order", async () => {
  const checkpoints = checkpointStore();
  const transport = fakeScimTransport();
  let releaseFirstToken;
  let firstTokenRequested;
  const firstTokenGate = new Promise((resolve) => {
    releaseFirstToken = resolve;
  });
  const firstTokenObserved = new Promise((resolve) => {
    firstTokenRequested = resolve;
  });
  let tokenCalls = 0;
  const adapter = createKeycloakScimProvisioningAdapter({
    origin: ORIGIN,
    realm: REALM,
    audience: AUDIENCE,
    checkpointStore: checkpoints,
    request: transport.request,
    getAccessToken: async () => {
      tokenCalls += 1;
      if (tokenCalls === 1) {
        firstTokenRequested();
        await firstTokenGate;
      }
      return { accessToken: ACCESS_TOKEN };
    },
  });

  const first = adapter.apply(command(1, "RevisionOne"));
  await firstTokenObserved;
  let secondSettled = false;
  const second = adapter.apply(command(2, "RevisionTwo")).finally(() => {
    secondSettled = true;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(secondSettled, false);
  releaseFirstToken();
  await Promise.all([first, second]);

  assert.equal(
    checkpoints.snapshot("synthetic-directory-001").sourceRevision,
    2,
  );
  assert.equal(transport.snapshot().name.familyName, "RevisionTwo");
});

test("a newer termination takes over a crashed pending revision", async () => {
  const checkpoints = checkpointStore();
  const transport = fakeScimTransport();
  const adapter = createKeycloakScimProvisioningAdapter({
    origin: ORIGIN,
    realm: REALM,
    audience: AUDIENCE,
    checkpointStore: checkpoints,
    request: transport.request,
    getAccessToken: async () => ({ accessToken: ACCESS_TOKEN }),
  });

  checkpoints.failNextConfirmation();
  await assert.rejects(
    adapter.apply(command(1, "BeforeCrash")),
    /Synthetic confirmation failure/,
  );
  assert.equal(
    checkpoints.snapshot("synthetic-directory-001").status,
    "PENDING",
  );
  const terminated = await adapter.apply(
    command(2, "Terminated", "TERMINATED"),
  );

  assert.equal(terminated.state, "TERMINATED");
  assert.equal(
    checkpoints.snapshot("synthetic-directory-001").status,
    "CONFIRMED",
  );
  assert.equal(transport.snapshot().active, false);
});

test("apply cannot override a constructor-owned checkpoint namespace", async () => {
  const checkpoints = checkpointStore();
  const adapter = createKeycloakScimProvisioningAdapter({
    origin: ORIGIN,
    realm: REALM,
    audience: AUDIENCE,
    checkpointStore: checkpoints,
    request: fakeScimTransport().request,
    getAccessToken: async () => ({ accessToken: ACCESS_TOKEN }),
  });

  await assert.rejects(
    adapter.apply({
      ...command(1, "NamespaceOverride"),
      tenantId: "stn_01984710-0000-7000-8000-000000000099",
      providerConnectionId:
        "idp_01984710-0000-7000-8000-000000000099",
    }),
    isAdapterError("INVALID_INPUT"),
  );
  assert.equal(
    checkpoints.snapshot("synthetic-directory-001"),
    null,
  );
});

test("SCIM credential-bearing Port failures are sanitized", async () => {
  const secret = "synthetic-secret-that-must-not-escape";
  const checkpoints = checkpointStore();
  const tokenFailure = createKeycloakScimProvisioningAdapter({
    origin: ORIGIN,
    realm: REALM,
    audience: AUDIENCE,
    checkpointStore: checkpoints,
    request: async () => jsonResponse(500, {}),
    getAccessToken: async () => {
      throw new Error(secret);
    },
  });
  await assert.rejects(
    tokenFailure.apply(command(1, "TokenFailure")),
    isAdapterError("TOKEN_REQUEST_FAILED", secret),
  );

  const transportFailure = createKeycloakScimProvisioningAdapter({
    origin: ORIGIN,
    realm: REALM,
    audience: AUDIENCE,
    checkpointStore: checkpointStore(),
    getAccessToken: async () => ({ accessToken: ACCESS_TOKEN }),
    request: async () => {
      throw new Error(`Authorization: Bearer ${ACCESS_TOKEN}`);
    },
  });
  await assert.rejects(
    transportFailure.apply(command(1, "TransportFailure")),
    isAdapterError("SCIM_TRANSPORT_FAILED", "Authorization"),
  );

  const responseFailure = createKeycloakScimProvisioningAdapter({
    origin: ORIGIN,
    realm: REALM,
    audience: AUDIENCE,
    checkpointStore: checkpointStore(),
    getAccessToken: async () => ({ accessToken: ACCESS_TOKEN }),
    request: async () =>
      jsonResponse(500, { scimType: `Authorization ${ACCESS_TOKEN}` }),
  });
  await assert.rejects(
    responseFailure.apply(command(1, "ResponseFailure")),
    isAdapterError("SCIM_REQUEST_FAILED", "Authorization"),
  );
});

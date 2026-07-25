import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import https from "node:https";
import test from "node:test";
import {
  KeycloakScimProvisioningError,
  createKeycloakScimProvisioningAdapter,
} from "../../lib/keycloak-scim-provisioning-adapter.mjs";

const REQUIRED_ENVIRONMENT = [
  "C04_KC_SCIM_ORIGIN",
  "C04_KC_SCIM_HOSTNAME",
  "C04_KC_SCIM_CA_FILE",
  "C04_KC_SCIM_ADMIN_USERNAME",
  "C04_KC_SCIM_ADMIN_PASSWORD",
  "C04_KC_SCIM_CLIENT_SECRET",
];
if (process.env.C04_KEYCLOAK_SCIM_EPHEMERAL !== "1") {
  throw new Error("C04_KEYCLOAK_SCIM_EPHEMERAL=1 is required.");
}
for (const name of REQUIRED_ENVIRONMENT) {
  if (!process.env[name]) throw new Error(`${name} is required.`);
}

const ORIGIN = process.env.C04_KC_SCIM_ORIGIN;
const HOSTNAME = process.env.C04_KC_SCIM_HOSTNAME;
const REALM = "c04-scim-synthetic";
const ISSUER = `${ORIGIN}/realms/${REALM}`;
const SCIM_BASE = `${ISSUER}/scim/v2`;
const CLIENT_ID = "c04-synthetic-scim-client";
const CORE_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const ca = await readFile(process.env.C04_KC_SCIM_CA_FILE);

function localLookup(hostname, options, callback) {
  if (hostname !== HOSTNAME) {
    callback(new Error("C04 SCIM test refused a non-synthetic hostname."));
    return;
  }
  if (options?.all) {
    callback(null, [{ address: "127.0.0.1", family: 4 }]);
    return;
  }
  callback(null, "127.0.0.1", 4);
}

function request({ url, method = "GET", headers = {}, body }) {
  const target = new URL(url);
  if (
    target.protocol !== "https:" ||
    target.hostname !== HOSTNAME ||
    target.origin !== ORIGIN
  ) {
    throw new Error("C04 SCIM test refused an unexpected network target.");
  }
  const payload = body === undefined ? null : Buffer.from(body);
  return new Promise((resolve, reject) => {
    const call = https.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method,
        headers: {
          ...headers,
          ...(payload ? { "content-length": payload.length } : {}),
        },
        ca,
        rejectUnauthorized: true,
        servername: HOSTNAME,
        lookup: localLookup,
      },
      (response) => {
        const chunks = [];
        let length = 0;
        response.on("data", (chunk) => {
          length += chunk.length;
          if (length > 2_000_000) {
            response.destroy(
              new Error("C04 SCIM response exceeded the safe test limit."),
            );
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => {
          resolve({
            status: response.statusCode,
            headers: response.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    call.on("error", reject);
    if (payload) call.write(payload);
    call.end();
  });
}

function expectStatus(response, allowed, operation) {
  if (!allowed.includes(response.status)) {
    throw new Error(`${operation} returned HTTP ${response.status}.`);
  }
}

async function jsonRequest(
  url,
  { method = "GET", headers = {}, body, allowed = [200] } = {},
) {
  const response = await request({
    url,
    method,
    headers: {
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  expectStatus(response, allowed, "C04 Keycloak JSON request");
  return {
    response,
    value: response.body ? JSON.parse(response.body) : null,
  };
}

async function formRequest(url, values) {
  return request({
    url,
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(values).toString(),
  });
}

function decodeJwtClaims(value) {
  const parts = value.split(".");
  assert.equal(parts.length, 3);
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

async function bootstrapScimRealm() {
  const adminAuthentication = await formRequest(
    `${ORIGIN}/realms/master/protocol/openid-connect/token`,
    {
      grant_type: "password",
      client_id: "admin-cli",
      username: process.env.C04_KC_SCIM_ADMIN_USERNAME,
      password: process.env.C04_KC_SCIM_ADMIN_PASSWORD,
    },
  );
  expectStatus(
    adminAuthentication,
    [200],
    "C04 Keycloak bootstrap authentication",
  );
  const adminToken = JSON.parse(adminAuthentication.body).access_token;
  assert.equal(typeof adminToken, "string");
  assert.ok(adminToken.length > 100);
  const adminHeaders = { authorization: `Bearer ${adminToken}` };

  await jsonRequest(`${ORIGIN}/admin/realms`, {
    method: "POST",
    headers: adminHeaders,
    allowed: [201],
    body: {
      realm: REALM,
      enabled: true,
      sslRequired: "all",
      registrationAllowed: false,
      resetPasswordAllowed: false,
      rememberMe: false,
      loginWithEmailAllowed: false,
      duplicateEmailsAllowed: false,
      bruteForceProtected: true,
      scimApiEnabled: true,
      accessTokenLifespan: 300,
      ssoSessionIdleTimeout: 600,
      ssoSessionMaxLifespan: 1200,
    },
  });

  const realm = await jsonRequest(
    `${ORIGIN}/admin/realms/${encodeURIComponent(REALM)}`,
    { headers: adminHeaders },
  );
  assert.equal(realm.value.scimApiEnabled, true);

  const userProfile = await jsonRequest(
    `${ORIGIN}/admin/realms/${encodeURIComponent(REALM)}/users/profile`,
    { headers: adminHeaders },
  );
  userProfile.value.attributes.push({
    name: "c04ExternalId",
    displayName: "C04 Synthetic External ID",
    validations: {
      length: {
        min: 1,
        max: 256,
      },
    },
    annotations: {
      "kc.scim.schema.attribute": "externalId",
    },
    permissions: {
      view: ["admin"],
      edit: ["admin"],
    },
    multivalued: false,
  });
  await jsonRequest(
    `${ORIGIN}/admin/realms/${encodeURIComponent(REALM)}/users/profile`,
    {
      method: "PUT",
      headers: adminHeaders,
      body: userProfile.value,
    },
  );

  const clientCreation = await jsonRequest(
    `${ORIGIN}/admin/realms/${encodeURIComponent(REALM)}/clients`,
    {
      method: "POST",
      headers: adminHeaders,
      allowed: [201],
      body: {
        clientId: CLIENT_ID,
        name: "C04 Synthetic SCIM Client",
        enabled: true,
        protocol: "openid-connect",
        clientAuthenticatorType: "client-secret",
        secret: process.env.C04_KC_SCIM_CLIENT_SECRET,
        publicClient: false,
        bearerOnly: false,
        standardFlowEnabled: false,
        implicitFlowEnabled: false,
        directAccessGrantsEnabled: false,
        serviceAccountsEnabled: true,
        fullScopeAllowed: false,
        protocolMappers: [
          {
            name: "c04-scim-exact-audience",
            protocol: "openid-connect",
            protocolMapper: "oidc-audience-mapper",
            consentRequired: false,
            config: {
              "included.custom.audience": SCIM_BASE,
              "access.token.claim": "true",
              "id.token.claim": "false",
            },
          },
        ],
      },
    },
  );
  const clientLocation = clientCreation.response.headers.location;
  assert.equal(typeof clientLocation, "string");
  const clientInternalId = new URL(clientLocation, ORIGIN).pathname
    .split("/")
    .at(-1);

  const serviceAccount = await jsonRequest(
    `${ORIGIN}/admin/realms/${encodeURIComponent(REALM)}/clients/${encodeURIComponent(clientInternalId)}/service-account-user`,
    { headers: adminHeaders },
  );
  const realmManagementClients = await jsonRequest(
    `${ORIGIN}/admin/realms/${encodeURIComponent(REALM)}/clients?clientId=realm-management`,
    { headers: adminHeaders },
  );
  assert.equal(realmManagementClients.value.length, 1);
  const realmManagementId = realmManagementClients.value[0].id;
  const manageUsersRole = await jsonRequest(
    `${ORIGIN}/admin/realms/${encodeURIComponent(REALM)}/clients/${encodeURIComponent(realmManagementId)}/roles/manage-users`,
    { headers: adminHeaders },
  );
  await jsonRequest(
    `${ORIGIN}/admin/realms/${encodeURIComponent(REALM)}/users/${encodeURIComponent(serviceAccount.value.id)}/role-mappings/clients/${encodeURIComponent(realmManagementId)}`,
    {
      method: "POST",
      headers: adminHeaders,
      allowed: [204],
      body: [manageUsersRole.value],
    },
  );
  await jsonRequest(
    `${ORIGIN}/admin/realms/${encodeURIComponent(REALM)}/clients/${encodeURIComponent(clientInternalId)}/scope-mappings/clients/${encodeURIComponent(realmManagementId)}`,
    {
      method: "POST",
      headers: adminHeaders,
      allowed: [204],
      body: [manageUsersRole.value],
    },
  );

  const serviceAuthentication = await formRequest(
    `${ISSUER}/protocol/openid-connect/token`,
    {
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: process.env.C04_KC_SCIM_CLIENT_SECRET,
    },
  );
  expectStatus(
    serviceAuthentication,
    [200],
    "C04 Keycloak SCIM client authentication",
  );
  const accessToken = JSON.parse(serviceAuthentication.body).access_token;
  const claims = decodeJwtClaims(accessToken);
  assert.equal(claims.iss, ISSUER);
  assert.ok(
    (Array.isArray(claims.aud) ? claims.aud : [claims.aud]).includes(
      SCIM_BASE,
    ),
  );
  return accessToken;
}

function scimHeaders(accessToken, extra = {}) {
  return {
    accept: "application/scim+json",
    authorization: `Bearer ${accessToken}`,
    ...extra,
  };
}

async function scimRequest(
  accessToken,
  path,
  { method = "GET", body, headers = {}, allowed = [200] } = {},
) {
  const response = await request({
    url: `${SCIM_BASE}/${path}`,
    method,
    headers: scimHeaders(accessToken, {
      ...(body === undefined
        ? {}
        : { "content-type": "application/scim+json" }),
      ...headers,
    }),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  expectStatus(response, allowed, `C04 SCIM ${method} ${path}`);
  return {
    response,
    value: response.body ? JSON.parse(response.body) : null,
  };
}

function rawUser({
  userName,
  externalId,
  givenName,
  familyName,
  email,
  active,
  id,
}) {
  return {
    schemas: [CORE_USER_SCHEMA],
    ...(id ? { id } : {}),
    userName,
    externalId,
    name: { givenName, familyName },
    emails: [{ value: email, type: "work", primary: true }],
    active,
  };
}

function createCheckpointStore() {
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
      const current = structuredClone(records.get(externalId) ?? null);
      const result = reducer(current);
      assert.deepEqual(Object.keys(result).sort(), ["next", "value"]);
      if (failNextConfirmation && result.next?.status === "CONFIRMED") {
        failNextConfirmation = false;
        throw new Error("Synthetic checkpoint confirmation failure.");
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

function isAdapterError(code) {
  return (error) => {
    assert.ok(error instanceof KeycloakScimProvisioningError);
    assert.equal(error.code, code);
    assert.doesNotMatch(
      error.message,
      new RegExp(process.env.C04_KC_SCIM_CLIENT_SECRET),
    );
    return true;
  };
}

test("C04 verifies Keycloak 26.7.0 SCIM preview and adapter safeguards", async (t) => {
  const accessToken = await bootstrapScimRealm();

  await t.test("ServiceProviderConfig declares ETag unsupported", async () => {
    const config = await scimRequest(
      accessToken,
      "ServiceProviderConfig",
    );
    assert.equal(config.value.patch.supported, true);
    assert.equal(config.value.filter.supported, true);
    assert.equal(config.value.etag.supported, false);
    assert.equal(config.value.bulk.supported, false);
  });

  await t.test(
    "real SCIM create, read, update, uniqueness, and deactivate work",
    async () => {
      const created = await scimRequest(accessToken, "Users", {
        method: "POST",
        allowed: [201],
        body: rawUser({
          userName: "synthetic-scim-raw-user",
          externalId: "syn-directory-raw-001",
          givenName: "Synthetic",
          familyName: "Original",
          email: "raw-original@c04-synthetic.example",
          active: true,
        }),
      });
      assert.match(created.value.id, /^[0-9a-f-]{36}$/i);
      assert.equal(created.value.externalId, "syn-directory-raw-001");

      const read = await scimRequest(
        accessToken,
        `Users/${encodeURIComponent(created.value.id)}`,
      );
      assert.equal(read.value.userName, "synthetic-scim-raw-user");
      assert.equal(read.value.active, true);

      const updated = await scimRequest(
        accessToken,
        `Users/${encodeURIComponent(created.value.id)}`,
        {
          method: "PUT",
          body: rawUser({
            id: created.value.id,
            userName: "synthetic-scim-raw-user",
            externalId: "syn-directory-raw-001",
            givenName: "Synthetic",
            familyName: "Updated",
            email: "raw-updated@c04-synthetic.example",
            active: true,
          }),
        },
      );
      assert.equal(updated.value.name.familyName, "Updated");
      assert.equal(
        updated.value.emails[0].value,
        "raw-updated@c04-synthetic.example",
      );

      const duplicate = await request({
        url: `${SCIM_BASE}/Users`,
        method: "POST",
        headers: scimHeaders(accessToken, {
          "content-type": "application/scim+json",
        }),
        body: JSON.stringify(
          rawUser({
            userName: "synthetic-scim-raw-user",
            externalId: "syn-directory-raw-duplicate",
            givenName: "Synthetic",
            familyName: "Duplicate",
            email: "raw-duplicate@c04-synthetic.example",
            active: true,
          }),
        ),
      });
      assert.equal(duplicate.status, 409);
      assert.equal(JSON.parse(duplicate.body).scimType, "uniqueness");

      const deactivated = await scimRequest(
        accessToken,
        `Users/${encodeURIComponent(created.value.id)}`,
        {
          method: "PATCH",
          headers: { "if-match": '"fabricated-stale-etag"' },
          body: {
            schemas: [PATCH_SCHEMA],
            Operations: [
              {
                op: "replace",
                path: "active",
                value: false,
              },
            ],
          },
        },
      );
      assert.equal(deactivated.value.active, false);
      assert.equal(deactivated.response.headers.etag, undefined);
      const readDeactivated = await scimRequest(
        accessToken,
        `Users/${encodeURIComponent(created.value.id)}`,
      );
      assert.equal(readDeactivated.value.active, false);
    },
  );

  await t.test(
    "adapter takes over by externalId and makes termination absorbing",
    async () => {
      const checkpointStore = createCheckpointStore();
      const adapter = createKeycloakScimProvisioningAdapter({
        origin: ORIGIN,
        realm: REALM,
        audience: SCIM_BASE,
        getAccessToken: async ({ tokenEndpoint, audience }) => {
          assert.equal(
            tokenEndpoint,
            `${ISSUER}/protocol/openid-connect/token`,
          );
          assert.equal(audience, SCIM_BASE);
          return { accessToken };
        },
        request,
        checkpointStore,
      });
      const active = {
        externalId: "syn-directory-adapter-001",
        userName: "synthetic-scim-adapter-user",
        sourceRevision: 1,
        desiredState: "ACTIVE",
        profile: {
          givenName: "Adapter",
          familyName: "Synthetic",
          email: "adapter@c04-synthetic.example",
        },
      };

      checkpointStore.failNextConfirmation();
      await assert.rejects(
        adapter.apply(active),
        /Synthetic checkpoint confirmation failure/,
      );
      assert.equal(
        checkpointStore.snapshot(active.externalId).status,
        "PENDING",
      );
      const afterRemoteSuccess = await scimRequest(
        accessToken,
        `Users?${new URLSearchParams({
          filter: `externalId eq "${active.externalId}"`,
        })}`,
      );
      assert.equal(afterRemoteSuccess.value.totalResults, 1);
      const createdId = afterRemoteSuccess.value.Resources[0].id;

      const retried = await adapter.apply(active);
      assert.equal(retried.resourceId, createdId);
      assert.equal(retried.applied, true);
      assert.equal(
        checkpointStore.snapshot(active.externalId).status,
        "CONFIRMED",
      );
      const afterRetry = await scimRequest(
        accessToken,
        `Users?${new URLSearchParams({
          filter: `externalId eq "${active.externalId}"`,
        })}`,
      );
      assert.equal(afterRetry.value.totalResults, 1);

      const suspended = await adapter.apply({
        ...active,
        sourceRevision: 2,
        desiredState: "SUSPENDED",
      });
      assert.equal(suspended.state, "SUSPENDED");
      const terminated = await adapter.apply({
        ...active,
        sourceRevision: 3,
        desiredState: "TERMINATED",
      });
      assert.equal(terminated.state, "TERMINATED");

      const stale = await adapter.apply({
        ...active,
        sourceRevision: 2,
        desiredState: "ACTIVE",
      });
      assert.equal(stale.applied, false);
      assert.equal(stale.stale, true);
      assert.equal(stale.state, "TERMINATED");

      await assert.rejects(
        adapter.apply({
          ...active,
          sourceRevision: 4,
          desiredState: "ACTIVE",
        }),
        isAdapterError("TERMINATED_ACCOUNT"),
      );
      const finalRead = await scimRequest(
        accessToken,
        `Users/${encodeURIComponent(createdId)}`,
      );
      assert.equal(finalRead.value.active, false);
      assert.equal(
        checkpointStore.snapshot(active.externalId).desiredState,
        "TERMINATED",
      );
    },
  );

  await t.test("adapter rejects inexact origin and audience", () => {
    const checkpointStore = createCheckpointStore();
    const ports = {
      realm: REALM,
      getAccessToken: async () => ({ accessToken }),
      request,
      checkpointStore,
    };
    assert.throws(
      () =>
        createKeycloakScimProvisioningAdapter({
          ...ports,
          origin: `${ORIGIN}/`,
          audience: SCIM_BASE,
        }),
      isAdapterError("INVALID_CONFIGURATION"),
    );
    assert.throws(
      () =>
        createKeycloakScimProvisioningAdapter({
          ...ports,
          origin: ORIGIN,
          audience: `${SCIM_BASE}/`,
        }),
      isAdapterError("INVALID_CONFIGURATION"),
    );
  });
});

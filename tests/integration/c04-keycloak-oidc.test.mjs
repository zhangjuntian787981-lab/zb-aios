import assert from "node:assert/strict";
import {
  createHash,
  createHmac,
  createPublicKey,
  randomBytes,
  verify as verifySignature,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import https from "node:https";
import test from "node:test";
import {
  createIdentityFederation,
  createMemoryIdentityStore,
  createSyntheticIdentityCatalog,
} from "../../lib/identity-federation.mjs";

const REQUIRED_ENVIRONMENT = [
  "C04_KC_ORIGIN",
  "C04_KC_HOSTNAME",
  "C04_KC_CA_FILE",
  "C04_KC_ADMIN_USERNAME",
  "C04_KC_ADMIN_PASSWORD",
  "C04_KC_CLIENT_SECRET",
  "C04_KC_TEST_USERNAME",
  "C04_KC_USER_PASSWORD",
];
if (process.env.C04_KEYCLOAK_EPHEMERAL !== "1") {
  throw new Error("C04_KEYCLOAK_EPHEMERAL=1 is required.");
}
for (const name of REQUIRED_ENVIRONMENT) {
  if (!process.env[name]) throw new Error(`${name} is required.`);
}

const ORIGIN = process.env.C04_KC_ORIGIN;
const HOSTNAME = process.env.C04_KC_HOSTNAME;
const REALM = "c04-synthetic";
const ISSUER = `${ORIGIN}/realms/${REALM}`;
const CLIENT_ID = "synthetic-aios-portal";
const REDIRECT_URI =
  "https://portal.c04-synthetic.example/auth/callback";
const TENANT_ID = "stn_01984700-0000-7000-8000-000000000041";
const FIXTURE_REF = Object.freeze({
  fixtureId: "synthetic-tenant-c04-keycloak",
  sha256:
    "sha256:2ab310f4042f91e43b0b927f5b0ff79104fd90a7ddf2ebc388af8ffea14f4868",
});
const ca = await readFile(process.env.C04_KC_CA_FILE);

function localLookup(hostname, options, callback) {
  if (hostname !== HOSTNAME) {
    callback(new Error("C04 OIDC test refused a non-synthetic hostname."));
    return;
  }
  if (options?.all) {
    callback(null, [{ address: "127.0.0.1", family: 4 }]);
    return;
  }
  callback(null, "127.0.0.1", 4);
}

function request(url, { method = "GET", headers = {}, body } = {}) {
  const target = new URL(url);
  if (
    target.protocol !== "https:" ||
    target.hostname !== HOSTNAME ||
    target.origin !== ORIGIN
  ) {
    throw new Error("C04 OIDC test refused an unexpected network target.");
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
              new Error("C04 OIDC response exceeded the safe test limit."),
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
  const response = await request(url, {
    method,
    headers: {
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  expectStatus(response, allowed, "C04 Keycloak JSON request");
  if (!response.body) return { response, value: null };
  return { response, value: JSON.parse(response.body) };
}

function formRequest(url, values) {
  const body = new URLSearchParams(values).toString();
  return request(url, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  });
}

async function bootstrapSyntheticRealm() {
  const tokenResponse = await formRequest(
    `${ORIGIN}/realms/master/protocol/openid-connect/token`,
    {
      grant_type: "password",
      client_id: "admin-cli",
      username: process.env.C04_KC_ADMIN_USERNAME,
      password: process.env.C04_KC_ADMIN_PASSWORD,
    },
  );
  expectStatus(tokenResponse, [200], "C04 Keycloak bootstrap authentication");
  const adminToken = JSON.parse(tokenResponse.body).access_token;
  if (typeof adminToken !== "string" || adminToken.length < 100) {
    throw new Error("C04 Keycloak bootstrap authentication failed.");
  }
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
      accessTokenLifespan: 300,
      ssoSessionIdleTimeout: 600,
      ssoSessionMaxLifespan: 1200,
      otpPolicyType: "totp",
      otpPolicyAlgorithm: "HmacSHA1",
      otpPolicyDigits: 6,
      otpPolicyLookAheadWindow: 1,
      otpPolicyPeriod: 30,
    },
  });

  const browserExecutions = await jsonRequest(
    `${ORIGIN}/admin/realms/${REALM}/authentication/flows/browser/executions`,
    { headers: adminHeaders },
  );
  for (const reference of [
    {
      providerId: "auth-username-password-form",
      alias: "c04-password-amr-reference",
      value: "pwd",
    },
    {
      providerId: "auth-otp-form",
      alias: "c04-otp-amr-reference",
      value: "otp",
    },
  ]) {
    const execution = browserExecutions.value.find(
      (candidate) => candidate.providerId === reference.providerId,
    );
    if (typeof execution?.id !== "string") {
      throw new Error("C04 Keycloak browser MFA execution was not found.");
    }
    await jsonRequest(
      `${ORIGIN}/admin/realms/${REALM}/authentication/executions/${encodeURIComponent(execution.id)}/config`,
      {
        method: "POST",
        headers: adminHeaders,
        allowed: [201],
        body: {
          alias: reference.alias,
          config: {
            "default.reference.value": reference.value,
            "default.reference.maxAge": "3600",
          },
        },
      },
    );
  }

  const clientCreation = await jsonRequest(
    `${ORIGIN}/admin/realms/${REALM}/clients`,
    {
      method: "POST",
      headers: adminHeaders,
      allowed: [201],
      body: {
        clientId: CLIENT_ID,
        name: "C04 Synthetic AIOS Portal",
        enabled: true,
        protocol: "openid-connect",
        clientAuthenticatorType: "client-secret",
        secret: process.env.C04_KC_CLIENT_SECRET,
        publicClient: false,
        bearerOnly: false,
        standardFlowEnabled: true,
        implicitFlowEnabled: false,
        directAccessGrantsEnabled: false,
        serviceAccountsEnabled: false,
        frontchannelLogout: true,
        consentRequired: false,
        redirectUris: [REDIRECT_URI],
        webOrigins: [],
        fullScopeAllowed: false,
        attributes: {
          "pkce.code.challenge.method": "S256",
        },
        protocolMappers: [
          {
            name: "C04 Authentication Method Reference",
            protocol: "openid-connect",
            protocolMapper: "oidc-amr-mapper",
            consentRequired: false,
            config: {
              "id.token.claim": "true",
              "access.token.claim": "false",
            },
          },
        ],
      },
    },
  );
  const clientLocation = clientCreation.response.headers.location;
  if (typeof clientLocation !== "string") {
    throw new Error("C04 Keycloak did not return the client location.");
  }
  const clientInternalId = new URL(clientLocation, ORIGIN).pathname
    .split("/")
    .at(-1);
  const client = await jsonRequest(
    `${ORIGIN}/admin/realms/${REALM}/clients/${encodeURIComponent(clientInternalId)}`,
    { headers: adminHeaders },
  );
  assert.deepEqual(client.value.redirectUris, [REDIRECT_URI]);
  assert.equal(
    client.value.attributes["pkce.code.challenge.method"],
    "S256",
  );
  assert.equal(client.value.standardFlowEnabled, true);
  assert.equal(client.value.directAccessGrantsEnabled, false);
  assert.equal(
    client.value.protocolMappers.some(
      (mapper) =>
        mapper.protocolMapper === "oidc-amr-mapper" &&
        mapper.config["id.token.claim"] === "true",
    ),
    true,
  );

  const userCreation = await jsonRequest(
    `${ORIGIN}/admin/realms/${REALM}/users`,
    {
      method: "POST",
      headers: adminHeaders,
      allowed: [201],
      body: {
        username: process.env.C04_KC_TEST_USERNAME,
        enabled: true,
        emailVerified: true,
        email: "synthetic-operator@c04-synthetic.example",
        firstName: "Synthetic",
        lastName: "Operator",
        requiredActions: ["CONFIGURE_TOTP"],
        credentials: [
          {
            type: "password",
            value: process.env.C04_KC_USER_PASSWORD,
            temporary: false,
          },
        ],
      },
    },
  );
  const userLocation = userCreation.response.headers.location;
  if (typeof userLocation !== "string") {
    throw new Error("C04 Keycloak did not return the user location.");
  }
  const subject = new URL(userLocation, ORIGIN).pathname.split("/").at(-1);
  if (!/^[0-9a-f-]{36}$/i.test(subject)) {
    throw new Error("C04 Keycloak returned an invalid synthetic subject.");
  }

  const discovery = await jsonRequest(
    `${ISSUER}/.well-known/openid-configuration`,
  );
  assert.equal(discovery.value.issuer, ISSUER);
  assert.equal(
    discovery.value.authorization_endpoint,
    `${ISSUER}/protocol/openid-connect/auth`,
  );
  assert.equal(
    discovery.value.token_endpoint,
    `${ISSUER}/protocol/openid-connect/token`,
  );
  assert.equal(
    discovery.value.jwks_uri,
    `${ISSUER}/protocol/openid-connect/certs`,
  );
  const jwks = await jsonRequest(discovery.value.jwks_uri);
  const signingKeyIds = jwks.value.keys
    .filter(
      (key) =>
        key.kty === "RSA" &&
        key.use === "sig" &&
        (key.alg === undefined || key.alg === "RS256") &&
        typeof key.kid === "string",
    )
    .map((key) => key.kid);
  if (signingKeyIds.length === 0) {
    throw new Error("C04 Keycloak exposed no RS256 signing key.");
  }
  return { subject, signingKeyIds };
}

function decodeJwtPart(value) {
  return JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
}

function createKeycloakBroker() {
  let discovery;
  return {
    exchangeCount: 0,
    browserFormCount: 0,
    otpFormCount: 0,
    lastVerification: null,

    async metadata() {
      if (discovery) return discovery;
      const result = await jsonRequest(
        `${ISSUER}/.well-known/openid-configuration`,
      );
      if (
        result.value.issuer !== ISSUER ||
        result.value.authorization_endpoint !==
          `${ISSUER}/protocol/openid-connect/auth` ||
        result.value.token_endpoint !==
          `${ISSUER}/protocol/openid-connect/token` ||
        result.value.jwks_uri !==
          `${ISSUER}/protocol/openid-connect/certs`
      ) {
        throw new Error("C04 Keycloak discovery metadata is not exact.");
      }
      discovery = result.value;
      return discovery;
    },

    validatePortRequest(value) {
      if (
        value.protocol !== "OIDC" ||
        value.issuer !== ISSUER ||
        value.clientId !== CLIENT_ID ||
        value.redirectUri !== REDIRECT_URI ||
        value.configurationVersion !== 1
      ) {
        throw new Error("C04 OIDC Broker rejected an inexact Port request.");
      }
    },

    async startAuthorization(value) {
      this.validatePortRequest(value);
      const metadata = await this.metadata();
      const authorizationUrl = new URL(metadata.authorization_endpoint);
      authorizationUrl.search = new URLSearchParams({
        response_type: "code",
        scope: "openid",
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        state: value.state,
        nonce: value.nonce,
        code_challenge: value.codeChallenge,
        code_challenge_method: "S256",
        max_age: "3600",
      });
      return { authorizationUrl: authorizationUrl.href };
    },

    async exchangeAndVerify(value) {
      this.validatePortRequest(value);
      this.exchangeCount += 1;
      const metadata = await this.metadata();
      const tokenResponse = await formRequest(metadata.token_endpoint, {
        grant_type: "authorization_code",
        client_id: CLIENT_ID,
        client_secret: process.env.C04_KC_CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        code: value.authorizationCode,
        code_verifier: value.codeVerifier,
      });
      if (tokenResponse.status !== 200) {
        throw new Error("C04 Keycloak rejected the authorization code.");
      }
      const idToken = JSON.parse(tokenResponse.body).id_token;
      if (typeof idToken !== "string") {
        throw new Error("C04 Keycloak returned no ID token.");
      }
      const parts = idToken.split(".");
      if (parts.length !== 3) {
        throw new Error("C04 Keycloak returned a malformed ID token.");
      }
      const header = decodeJwtPart(parts[0]);
      const payload = decodeJwtPart(parts[1]);
      if (
        header.alg !== "RS256" ||
        typeof header.kid !== "string" ||
        payload.iss !== ISSUER ||
        payload.aud !== CLIENT_ID ||
        payload.azp !== CLIENT_ID ||
        typeof payload.sub !== "string" ||
        typeof payload.nonce !== "string" ||
        !Number.isInteger(payload.iat) ||
        !Number.isInteger(payload.exp) ||
        !Number.isInteger(payload.auth_time) ||
        typeof payload.acr !== "string" ||
        !Array.isArray(payload.amr) ||
        !payload.amr.every((method) => typeof method === "string") ||
        !payload.amr.includes("pwd") ||
        !payload.amr.includes("otp")
      ) {
        throw new Error("C04 Keycloak ID token claims are not exact.");
      }
      const keys = await jsonRequest(metadata.jwks_uri);
      const jwk = keys.value.keys.find(
        (candidate) =>
          candidate.kid === header.kid &&
          candidate.kty === "RSA" &&
          candidate.use === "sig",
      );
      if (!jwk) throw new Error("C04 Keycloak signing key was not found.");
      const verified = verifySignature(
        "RSA-SHA256",
        Buffer.from(`${parts[0]}.${parts[1]}`),
        createPublicKey({ key: jwk, format: "jwk" }),
        Buffer.from(parts[2], "base64url"),
      );
      if (!verified) {
        throw new Error("C04 Keycloak ID token signature verification failed.");
      }
      const authenticationMethods = [
        ...new Set(payload.amr.map((method) => `amr:${method}`)),
      ].sort();
      this.lastVerification = {
        issuer: payload.iss,
        audience: payload.aud,
        authorizedParty: payload.azp,
        subject: payload.sub,
        algorithm: header.alg,
        keyId: header.kid,
        signatureVerified: true,
        authenticationMethods,
      };
      return {
        protocol: "OIDC",
        signatureVerified: true,
        synthetic: true,
        issuer: payload.iss,
        audience: [payload.aud],
        authorizedParty: payload.azp,
        subject: payload.sub,
        nonce: payload.nonce,
        issuedAt: new Date(payload.iat * 1000).toISOString(),
        notBefore: new Date((payload.nbf ?? payload.iat) * 1000).toISOString(),
        expiresAt: new Date(payload.exp * 1000).toISOString(),
        authenticationTime: new Date(
          payload.auth_time * 1000,
        ).toISOString(),
        authenticationMethods,
        algorithm: header.alg,
        keyId: header.kid,
        configurationVersion: 1,
      };
    },
  };
}

function decodeHtml(value) {
  return value
    .replaceAll("&amp;", "&")
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'")
    .replaceAll("&#x3D;", "=");
}

function generateTotp(secret, counterOffset = 0) {
  // Keycloak's hidden totpSecret is raw; its separate display value is Base32.
  const key = Buffer.from(secret, "utf8");
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(
    BigInt(Math.floor(Date.now() / 30_000) + counterOffset),
  );
  const digest = createHmac("sha1", key).update(counter).digest();
  key.fill(0);
  const offset = digest.at(-1) & 0x0f;
  const value =
    (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(value).padStart(6, "0");
}

async function waitForSafeTotpEnrollmentWindow() {
  const periodMilliseconds = 30_000;
  const elapsed = Date.now() % periodMilliseconds;
  if (elapsed > 20_000) {
    await new Promise((resolve) => {
      setTimeout(resolve, periodMilliseconds - elapsed + 1_000);
    });
  }
}

function findForm(html, id) {
  const formTag = html.match(
    new RegExp(`<form\\b[^>]*\\bid=["']${id}["'][^>]*>`, "i"),
  )?.[0];
  const actionValue = formTag?.match(/\baction=["']([^"']+)["']/i)?.[1];
  if (!actionValue) {
    throw new Error("C04 Keycloak browser form was not found.");
  }
  return decodeHtml(actionValue);
}

function findInputValue(html, id) {
  const inputTag = html.match(
    new RegExp(`<input\\b[^>]*\\bid=["']${id}["'][^>]*>`, "i"),
  )?.[0];
  const value = inputTag?.match(/\bvalue=["']([^"']*)["']/i)?.[1];
  if (!value) {
    throw new Error("C04 Keycloak browser input was not found.");
  }
  return decodeHtml(value);
}

class CookieJar {
  constructor() {
    this.values = new Map();
  }

  capture(headers) {
    const cookies = headers["set-cookie"] ?? [];
    for (const item of Array.isArray(cookies) ? cookies : [cookies]) {
      const pair = item.split(";", 1)[0];
      const separator = pair.indexOf("=");
      if (separator > 0) {
        this.values.set(
          pair.slice(0, separator),
          pair.slice(separator + 1),
        );
      }
    }
  }

  header() {
    return [...this.values]
      .map(([name, value]) => `${name}=${value}`)
      .join("; ");
  }
}

async function settleBrowserResponse(response, currentUrl, cookies) {
  let page = response;
  let pageUrl = currentUrl;
  for (let redirects = 0; redirects <= 8; redirects += 1) {
    cookies.capture(page.headers);
    if (![301, 302, 303, 307, 308].includes(page.status)) {
      return { external: false, page, pageUrl };
    }
    const location = page.headers.location;
    if (typeof location !== "string") {
      throw new Error("C04 Keycloak browser redirect had no location.");
    }
    const next = new URL(location, pageUrl);
    if (next.origin !== ORIGIN) {
      return { external: true, page, pageUrl: next.href };
    }
    pageUrl = next.href;
    page = await request(pageUrl, {
      headers: {
        accept: "text/html,application/xhtml+xml",
        ...(cookies.header() ? { cookie: cookies.header() } : {}),
      },
    });
  }
  throw new Error("C04 Keycloak browser exceeded the redirect limit.");
}

async function openBrowserPage(url, cookies) {
  const response = await request(url, {
    headers: {
      accept: "text/html,application/xhtml+xml",
      ...(cookies.header() ? { cookie: cookies.header() } : {}),
    },
  });
  return settleBrowserResponse(response, url, cookies);
}

async function submitBrowserForm(pageResult, cookies, formId, values) {
  if (pageResult.external) {
    throw new Error("C04 Keycloak browser form escaped the synthetic IdP.");
  }
  expectStatus(pageResult.page, [200], "C04 Keycloak browser form");
  assert.match(pageResult.page.headers["content-type"], /^text\/html\b/);
  const action = new URL(
    findForm(pageResult.page.body, formId),
    pageResult.pageUrl,
  );
  if (action.origin !== ORIGIN) {
    throw new Error("C04 Keycloak browser form action was not local.");
  }
  const response = await request(action.href, {
    method: "POST",
    headers: {
      accept: "text/html,application/xhtml+xml",
      "content-type": "application/x-www-form-urlencoded",
      ...(cookies.header() ? { cookie: cookies.header() } : {}),
    },
    body: new URLSearchParams(values).toString(),
  });
  return settleBrowserResponse(response, action.href, cookies);
}

function parseCallback(pageResult, expectedState) {
  if (!pageResult.external) {
    throw new Error("C04 Keycloak callback was not returned.");
  }
  const callback = new URL(pageResult.pageUrl);
  assert.equal(`${callback.origin}${callback.pathname}`, REDIRECT_URI);
  assert.equal(callback.searchParams.get("error"), null);
  const code = callback.searchParams.get("code");
  const state = callback.searchParams.get("state");
  if (!code || !state) {
    throw new Error("C04 Keycloak callback omitted code or state.");
  }
  assert.equal(state, expectedState);
  return { code, state };
}

function standaloneAuthorization() {
  const state = randomBytes(32).toString("base64url");
  const nonce = randomBytes(32).toString("base64url");
  const codeVerifier = randomBytes(48).toString("base64url");
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  const authorizationUrl = new URL(
    `${ISSUER}/protocol/openid-connect/auth`,
  );
  authorizationUrl.search = new URLSearchParams({
    response_type: "code",
    scope: "openid",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    max_age: "3600",
  });
  return { authorizationUrl: authorizationUrl.href, codeVerifier, state };
}

async function enrollSyntheticTotp() {
  const enrollment = standaloneAuthorization();
  const cookies = new CookieJar();
  const loginPage = await openBrowserPage(
    enrollment.authorizationUrl,
    cookies,
  );
  const configurationPage = await submitBrowserForm(
    loginPage,
    cookies,
    "kc-form-login",
    {
      username: process.env.C04_KC_TEST_USERNAME,
      password: process.env.C04_KC_USER_PASSWORD,
      credentialId: "",
      login: "Sign In",
    },
  );
  const secret = findInputValue(
    configurationPage.page.body,
    "totpSecret",
  );
  await waitForSafeTotpEnrollmentWindow();
  const callbackPage = await submitBrowserForm(
    configurationPage,
    cookies,
    "kc-totp-settings-form",
    {
      totp: generateTotp(secret, -1),
      totpSecret: secret,
      userLabel: "C04 synthetic ephemeral TOTP",
    },
  );
  const callback = parseCallback(callbackPage, enrollment.state);
  return {
    authorizationCode: callback.code,
    codeVerifier: enrollment.codeVerifier,
    secret,
  };
}

async function browserMfaLogin(
  broker,
  authorizationUrl,
  secret,
  otpMode = "correct",
) {
  const expectedState = new URL(authorizationUrl).searchParams.get("state");
  if (!expectedState) {
    throw new Error("C04 Keycloak authorization state was not found.");
  }
  const cookies = new CookieJar();
  const loginPage = await openBrowserPage(authorizationUrl, cookies);
  broker.browserFormCount += 1;
  const otpPage = await submitBrowserForm(
    loginPage,
    cookies,
    "kc-form-login",
    {
      username: process.env.C04_KC_TEST_USERNAME,
      password: process.env.C04_KC_USER_PASSWORD,
      credentialId: "",
      login: "Sign In",
    },
  );
  const correctOtp = generateTotp(secret);
  const otp =
    otpMode === "missing"
      ? ""
      : otpMode === "wrong"
        ? `${correctOtp[0] === "0" ? "1" : "0"}${correctOtp.slice(1)}`
        : correctOtp;
  broker.otpFormCount += 1;
  const callbackPage = await submitBrowserForm(
    otpPage,
    cookies,
    "kc-otp-login-form",
    { otp, login: "Sign In" },
  );
  if (otpMode === "correct") {
    return parseCallback(callbackPage, expectedState);
  }
  assert.equal(callbackPage.external, false);
  expectStatus(
    callbackPage.page,
    [200],
    "C04 Keycloak rejected OTP submission",
  );
  assert.match(callbackPage.page.body, /\bid=["']kc-otp-login-form["']/i);
  assert.equal(callbackPage.page.headers.location, undefined);
  return { code: null, state: null };
}

function createC04Runtime({ subject, signingKeyIds, broker }) {
  const tenant = {
    tenantId: TENANT_ID,
    tenantKind: "SYNTHETIC",
    synthetic: true,
    state: "PROVISIONING",
    lifecycleVersion: 1,
    generation: 1,
    operationId: "op_01984700-0000-7000-8000-000000000042",
    fixtureRef: FIXTURE_REF,
    trustSource: "VERIFIED_SERVER_CONTEXT",
  };
  const tenantRegistryContext = {
    actorId: "syn_svc_c04_keycloak_tenant_reader",
    capabilities: ["TENANT_LIFECYCLE_READ"],
    synthetic: true,
  };
  const tenantRegistry = {
    async snapshot(context, tenantId) {
      assert.deepEqual(context, tenantRegistryContext);
      assert.equal(tenantId, TENANT_ID);
      return structuredClone(tenant);
    },
    async admitNewRequest({ tenantId, expectedTenantKind }) {
      if (
        tenantId !== TENANT_ID ||
        expectedTenantKind !== "SYNTHETIC" ||
        tenant.state !== "ACTIVE"
      ) {
        throw new Error("Synthetic Tenant is not active.");
      }
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: tenant.lifecycleVersion,
        trustSource: "VERIFIED_SERVER_CONTEXT",
      };
    },
  };
  const identity = createIdentityFederation({
    store: createMemoryIdentityStore(),
    tenantRegistry,
    tenantRegistryContext,
    identityCatalog: createSyntheticIdentityCatalog([
      {
        ...FIXTURE_REF,
        provider: {
          issuer: ISSUER,
          clientId: CLIENT_ID,
          redirectRoutes: { PORTAL_HOME: REDIRECT_URI },
          configurationVersion: 1,
          allowedAlgorithms: ["RS256"],
          allowedKeyIds: signingKeyIds,
          requiredAuthenticationMethods: ["amr:otp"],
          maxAuthenticationAgeSeconds: 3600,
          upstreamProtocols: ["OIDC"],
        },
        users: [
          {
            fixtureUserId: "c04-keycloak-synthetic-operator",
            directoryObjectId: `keycloak-directory-${subject}`,
            loginSubject: subject,
            profileRef:
              "profile://c04-keycloak/synthetic-operator",
          },
        ],
      },
    ]),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    federationBroker: broker,
  });
  return { identity, tenant };
}

function isIdentityError(code) {
  return (error) => {
    assert.equal(error.code, code);
    return true;
  };
}

test("C04 completes a real Keycloak 26.7.0 OIDC code + PKCE flow", async (t) => {
  const syntheticRealm = await bootstrapSyntheticRealm();
  const totpEnrollment = await enrollSyntheticTotp();
  const broker = createKeycloakBroker();
  const { identity, tenant } = createC04Runtime({
    subject: syntheticRealm.subject,
    signingKeyIds: syntheticRealm.signingKeyIds,
    broker,
  });
  const projectionWorker = {
    actorId: "syn_svc_c04_keycloak_projection",
    capabilities: ["IDENTITY_TENANT_PROJECT", "IDENTITY_READ"],
    synthetic: true,
  };
  const provisioningWorker = {
    actorId: "syn_svc_c04_keycloak_provisioning",
    capabilities: ["IDENTITY_PROVISIONING_APPLY"],
    synthetic: true,
  };
  const portalContext = {
    actorId: "syn_svc_c04_keycloak_portal",
    synthetic: true,
  };

  await identity.execute(projectionWorker, {
    kind: "APPLY_TENANT_LIFECYCLE_EVENT",
    idempotencyKey: "c04-keycloak-project",
    tenantId: TENANT_ID,
    sourceEventId: "c04-keycloak-tenant-event",
    sourceLifecycleVersion: tenant.lifecycleVersion,
    sourceGeneration: tenant.generation,
    sourceOperationId: tenant.operationId,
    sourceState: tenant.state,
    correlationId: "c04-keycloak-runtime",
  });
  tenant.state = "ACTIVE";
  tenant.lifecycleVersion += 1;
  const projection = await identity.snapshot(projectionWorker, {
    tenantId: TENANT_ID,
  });
  await identity.execute(provisioningWorker, {
    kind: "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT",
    idempotencyKey: "c04-keycloak-provision-user",
    tenantId: TENANT_ID,
    providerConnectionId: projection.provider.providerConnectionId,
    fixtureUserId: "c04-keycloak-synthetic-operator",
    sourceEventId: "c04-keycloak-user-event",
    sourceRevision: 1,
    desiredState: "ACTIVE",
    correlationId: "c04-keycloak-runtime",
  });

  const started = await identity.startLogin(portalContext, {
    tenantId: TENANT_ID,
    providerConnectionId: projection.provider.providerConnectionId,
    returnRoute: "PORTAL_HOME",
  });
  const authorizationRequest = new URL(started.authorizationUrl);
  assert.equal(authorizationRequest.searchParams.get("client_id"), CLIENT_ID);
  assert.equal(
    authorizationRequest.searchParams.get("redirect_uri"),
    REDIRECT_URI,
  );
  assert.equal(
    authorizationRequest.searchParams.get("code_challenge_method"),
    "S256",
  );
  const callback = await browserMfaLogin(
    broker,
    started.authorizationUrl,
    totpEnrollment.secret,
  );
  assert.equal(callback.state, started.state);

  await assert.rejects(
    identity.completeLogin(portalContext, {
      transactionId: started.transactionId,
      state: `${started.state}x`,
      authorizationCode: callback.code,
      codeVerifier: started.codeVerifier,
    }),
    isIdentityError("AUTHENTICATION_FAILED"),
  );
  await assert.rejects(
    identity.completeLogin(portalContext, {
      transactionId: started.transactionId,
      state: started.state,
      authorizationCode: callback.code,
      codeVerifier: "0".repeat(64),
    }),
    isIdentityError("AUTHENTICATION_FAILED"),
  );
  assert.equal(broker.exchangeCount, 0);

  const completed = await identity.completeLogin(portalContext, {
    transactionId: started.transactionId,
    state: started.state,
    authorizationCode: callback.code,
    codeVerifier: started.codeVerifier,
  });
  assert.equal(completed.tenantId, TENANT_ID);
  assert.equal(completed.trustSource, "VERIFIED_SESSION");
  assert.equal(completed.authorizationStatus, "NOT_EVALUATED");
  assert.deepEqual(completed.authenticationMethods, [
    "amr:otp",
    "amr:pwd",
  ]);
  assert.equal(broker.browserFormCount, 1);
  assert.equal(broker.otpFormCount, 1);
  assert.equal(broker.exchangeCount, 1);
  assert.deepEqual(broker.lastVerification, {
    issuer: ISSUER,
    audience: CLIENT_ID,
    authorizedParty: CLIENT_ID,
    subject: syntheticRealm.subject,
    algorithm: "RS256",
    keyId: broker.lastVerification.keyId,
    signatureVerified: true,
    authenticationMethods: ["amr:otp", "amr:pwd"],
  });
  assert.ok(
    syntheticRealm.signingKeyIds.includes(broker.lastVerification.keyId),
  );

  const resolved = await identity.resolveSession(portalContext, {
    sessionToken: completed.sessionToken,
    expectedTenantId: TENANT_ID,
  });
  assert.equal(resolved.identityAccountId, completed.identityAccountId);
  assert.equal(resolved.authorizationStatus, "NOT_EVALUATED");

  await assert.rejects(
    identity.completeLogin(portalContext, {
      transactionId: started.transactionId,
      state: started.state,
      authorizationCode: callback.code,
      codeVerifier: started.codeVerifier,
    }),
    isIdentityError("LOGIN_REPLAY_DETECTED"),
  );
  assert.equal(broker.exchangeCount, 1);

  await assert.rejects(
    broker.exchangeAndVerify({
      protocol: "OIDC",
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      authorizationCode: callback.code,
      codeVerifier: started.codeVerifier,
      configurationVersion: 1,
    }),
    /rejected the authorization code/,
  );
  assert.equal(broker.exchangeCount, 2);

  await assert.rejects(
    broker.exchangeAndVerify({
      protocol: "OIDC",
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      authorizationCode: totpEnrollment.authorizationCode,
      codeVerifier: "f".repeat(64),
      configurationVersion: 1,
    }),
    /rejected the authorization code/,
  );
  assert.equal(broker.browserFormCount, 1);
  assert.equal(broker.otpFormCount, 1);
  assert.equal(broker.exchangeCount, 3);

  const missingOtpStarted = await identity.startLogin(portalContext, {
    tenantId: TENANT_ID,
    providerConnectionId: projection.provider.providerConnectionId,
    returnRoute: "PORTAL_HOME",
  });
  const missingOtp = await browserMfaLogin(
    broker,
    missingOtpStarted.authorizationUrl,
    totpEnrollment.secret,
    "missing",
  );
  assert.equal(missingOtp.code, null);

  const wrongOtpStarted = await identity.startLogin(portalContext, {
    tenantId: TENANT_ID,
    providerConnectionId: projection.provider.providerConnectionId,
    returnRoute: "PORTAL_HOME",
  });
  const wrongOtp = await browserMfaLogin(
    broker,
    wrongOtpStarted.authorizationUrl,
    totpEnrollment.secret,
    "wrong",
  );
  assert.equal(wrongOtp.code, null);
  assert.equal(broker.browserFormCount, 3);
  assert.equal(broker.otpFormCount, 3);
  assert.equal(broker.exchangeCount, 3);

  await assert.rejects(
    broker.startAuthorization({
      protocol: "OIDC",
      issuer: "https://idp.wrong.example/realms/c04-synthetic",
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      state: started.state,
      nonce: started.state,
      codeChallenge: started.state,
      codeChallengeMethod: "S256",
      configurationVersion: 1,
    }),
    /inexact Port request/,
  );
  await assert.rejects(
    broker.exchangeAndVerify({
      protocol: "OIDC",
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri:
        "https://portal.c04-synthetic.example/auth/other-callback",
      authorizationCode: "unused",
      codeVerifier: started.codeVerifier,
      configurationVersion: 1,
    }),
    /inexact Port request/,
  );
  await assert.rejects(
    broker.exchangeAndVerify({
      protocol: "OIDC",
      issuer: ISSUER,
      clientId: "wrong-audience-client",
      redirectUri: REDIRECT_URI,
      authorizationCode: "unused",
      codeVerifier: started.codeVerifier,
      configurationVersion: 1,
    }),
    /inexact Port request/,
  );
  assert.equal(broker.exchangeCount, 3);

  t.diagnostic("PASS: real Keycloak password form required a subsequent TOTP form");
  t.diagnostic("PASS: missing and wrong TOTP submissions returned no authorization code");
  t.diagnostic("PASS: ID token AMR proved pwd + otp and mapped both methods into C04 Core");
  t.diagnostic("PASS: real Keycloak HTML MFA login returned the exact state");
  t.diagnostic("PASS: wrong Core state was rejected before token exchange");
  t.diagnostic("PASS: wrong Core PKCE verifier was rejected before token exchange");
  t.diagnostic("PASS: exact issuer, audience, redirect and RS256 JWKS verification passed");
  t.diagnostic("PASS: verified assertion entered C04 Core and produced a resolvable session");
  t.diagnostic("PASS: C04 callback replay and Keycloak authorization-code replay were rejected");
  t.diagnostic("PASS: real Keycloak token exchange rejected a wrong PKCE verifier");
  t.diagnostic("PASS: inexact issuer, client/audience and redirect Port requests were rejected");
});

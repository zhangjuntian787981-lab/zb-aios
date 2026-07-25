import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import https from "node:https";
import test from "node:test";

const REQUIRED_ENVIRONMENT = [
  "C04_KC_ORIGIN",
  "C04_KC_HOSTNAME",
  "C04_KC_CA_FILE",
  "C04_KC_ADMIN_USERNAME",
  "C04_KC_ADMIN_PASSWORD",
  "C04_KC_TEST_USERNAME",
  "C04_KC_USER_PASSWORD",
];
if (process.env.C04_KEYCLOAK_SAML_EPHEMERAL !== "1") {
  throw new Error("C04_KEYCLOAK_SAML_EPHEMERAL=1 is required.");
}
for (const name of REQUIRED_ENVIRONMENT) {
  if (!process.env[name]) throw new Error(`${name} is required.`);
}

const ORIGIN = process.env.C04_KC_ORIGIN;
const HOSTNAME = process.env.C04_KC_HOSTNAME;
const UPSTREAM_REALM = "c04-saml-upstream";
const BROKER_REALM = "c04-saml-broker";
const IDP_ALIAS = "synthetic-saml";
const OIDC_CLIENT_ID = "c04-saml-portal";
const FIRST_BROKER_LOGIN_FLOW = "c04-deny-unlinked-first-broker-login";
const DENY_ACCESS_AUTHENTICATOR = "deny-access-authenticator";
const UNLINKED_USERNAME = "synthetic-saml-unlinked";
const REDIRECT_URI =
  "https://portal.c04-synthetic.example/auth/callback";
const UPSTREAM_ISSUER = `${ORIGIN}/realms/${UPSTREAM_REALM}`;
const BROKER_ISSUER = `${ORIGIN}/realms/${BROKER_REALM}`;
const UPSTREAM_SAML_ENDPOINT = `${UPSTREAM_ISSUER}/protocol/saml`;
const BROKER_SAML_ENTITY_ID = BROKER_ISSUER;
const BROKER_SAML_ACS =
  `${BROKER_ISSUER}/broker/${IDP_ALIAS}/endpoint`;
const ca = await readFile(process.env.C04_KC_CA_FILE);

function localLookup(hostname, options, callback) {
  if (hostname !== HOSTNAME) {
    callback(new Error("C04 SAML test refused a non-synthetic hostname."));
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
    throw new Error("C04 SAML test refused an unexpected network target.");
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
          if (length > 4_000_000) {
            response.destroy(
              new Error("C04 SAML response exceeded the safe test limit."),
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
  return {
    response,
    value: response.body ? JSON.parse(response.body) : null,
  };
}

async function formRequest(url, values) {
  return request(url, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(values).toString(),
  });
}

function decodeHtml(value) {
  const named = {
    amp: "&",
    apos: "'",
    gt: ">",
    lt: "<",
    quot: '"',
  };
  return value.replace(
    /&(?:#(\d+)|#x([0-9a-f]+)|([a-z]+));/gi,
    (entity, decimal, hexadecimal, name) => {
      if (decimal) return String.fromCodePoint(Number(decimal));
      if (hexadecimal) return String.fromCodePoint(parseInt(hexadecimal, 16));
      return named[name.toLowerCase()] ?? entity;
    },
  );
}

function parseAttributes(source) {
  const attributes = new Map();
  const pattern =
    /([:\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;
  for (const match of source.matchAll(pattern)) {
    attributes.set(
      match[1].toLowerCase(),
      decodeHtml(match[2] ?? match[3] ?? match[4] ?? ""),
    );
  }
  return attributes;
}

function parseForms(html, pageUrl) {
  const forms = [];
  const formPattern = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  for (const match of html.matchAll(formPattern)) {
    const attributes = parseAttributes(match[1]);
    const action = new URL(attributes.get("action") ?? pageUrl, pageUrl);
    if (action.origin !== ORIGIN) {
      throw new Error("C04 SAML form escaped the synthetic Keycloak origin.");
    }
    const fields = new Map();
    for (const input of match[2].matchAll(/<input\b([^>]*)>/gi)) {
      const inputAttributes = parseAttributes(input[1]);
      const name = inputAttributes.get("name");
      if (name) fields.set(name, inputAttributes.get("value") ?? "");
    }
    forms.push({
      id: attributes.get("id") ?? "",
      method: (attributes.get("method") ?? "GET").toUpperCase(),
      action: action.href,
      fields,
    });
  }
  return forms;
}

function defaultCookiePath(url) {
  const pathname = new URL(url).pathname;
  if (!pathname.startsWith("/") || pathname === "/") return "/";
  const finalSlash = pathname.lastIndexOf("/");
  return finalSlash === 0 ? "/" : pathname.slice(0, finalSlash);
}

class CookieJar {
  constructor() {
    this.cookies = new Map();
  }

  capture(url, headers) {
    const setCookies = headers["set-cookie"] ?? [];
    for (const raw of Array.isArray(setCookies) ? setCookies : [setCookies]) {
      const parts = raw.split(";").map((part) => part.trim());
      const separator = parts[0].indexOf("=");
      if (separator <= 0) continue;
      const name = parts[0].slice(0, separator);
      const value = parts[0].slice(separator + 1);
      let path = defaultCookiePath(url);
      let remove = value === "";
      for (const part of parts.slice(1)) {
        const attributeSeparator = part.indexOf("=");
        const attributeName = (
          attributeSeparator < 0
            ? part
            : part.slice(0, attributeSeparator)
        ).toLowerCase();
        const attributeValue =
          attributeSeparator < 0 ? "" : part.slice(attributeSeparator + 1);
        if (attributeName === "path" && attributeValue.startsWith("/")) {
          path = attributeValue;
        }
        if (attributeName === "max-age" && Number(attributeValue) <= 0) {
          remove = true;
        }
      }
      const key = `${name}\0${path}`;
      if (remove) this.cookies.delete(key);
      else this.cookies.set(key, { name, path, value });
    }
  }

  header(url) {
    const pathname = new URL(url).pathname;
    return [...this.cookies.values()]
      .filter(
        (cookie) =>
          pathname === cookie.path ||
          pathname.startsWith(
            cookie.path.endsWith("/") ? cookie.path : `${cookie.path}/`,
          ),
      )
      .sort((left, right) => right.path.length - left.path.length)
      .map((cookie) => `${cookie.name}=${cookie.value}`)
      .join("; ");
  }
}

async function browserRequest(
  jar,
  url,
  { method = "GET", headers = {}, body } = {},
) {
  const cookie = jar.header(url);
  const response = await request(url, {
    method,
    headers: {
      accept: "text/html,application/xhtml+xml",
      ...(cookie ? { cookie } : {}),
      ...headers,
    },
    body,
  });
  jar.capture(url, response.headers);
  return response;
}

async function followInternalRedirects(jar, response, responseUrl) {
  let currentResponse = response;
  let currentUrl = responseUrl;
  for (let count = 0; count < 12; count += 1) {
    if (![301, 302, 303, 307, 308].includes(currentResponse.status)) {
      return { response: currentResponse, url: currentUrl };
    }
    const location = currentResponse.headers.location;
    if (typeof location !== "string") {
      throw new Error("C04 SAML redirect had no location.");
    }
    const next = new URL(location, currentUrl);
    if (next.origin !== ORIGIN) {
      throw new Error("C04 SAML browser escaped before the callback boundary.");
    }
    currentUrl = next.href;
    currentResponse = await browserRequest(jar, currentUrl);
  }
  throw new Error("C04 SAML browser exceeded the redirect limit.");
}

async function submitForm(jar, form, overrides = {}) {
  const values = new URLSearchParams(form.fields);
  for (const [name, value] of Object.entries(overrides)) {
    values.set(name, value);
  }
  if (form.method === "GET") {
    const target = new URL(form.action);
    target.search = values.toString();
    return {
      response: await browserRequest(jar, target.href),
      url: target.href,
    };
  }
  return {
    response: await browserRequest(jar, form.action, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body: values.toString(),
    }),
    url: form.action,
  };
}

async function followToCallbackOrResponse(jar, response, responseUrl) {
  let currentResponse = response;
  let currentUrl = responseUrl;
  for (let count = 0; count < 12; count += 1) {
    if (![301, 302, 303, 307, 308].includes(currentResponse.status)) {
      return { kind: "response", response: currentResponse, url: currentUrl };
    }
    const location = currentResponse.headers.location;
    if (typeof location !== "string") {
      throw new Error("C04 SAML completion redirect had no location.");
    }
    const next = new URL(location, currentUrl);
    if (`${next.origin}${next.pathname}` === REDIRECT_URI) {
      return { kind: "callback", location: next };
    }
    if (next.origin !== ORIGIN) {
      throw new Error("C04 SAML completion escaped the allowed origins.");
    }
    currentUrl = next.href;
    currentResponse = await browserRequest(jar, currentUrl);
  }
  throw new Error("C04 SAML completion exceeded the redirect limit.");
}

function findForm(page, pageUrl, predicate, operation) {
  const form = parseForms(page.body, pageUrl).find(predicate);
  if (!form) throw new Error(`${operation} form was not found.`);
  return form;
}

function xmlOpeningTag(xml, localName) {
  const match = xml.match(
    new RegExp(`<(?:(?:[\\w-]+):)?${localName}\\b[^>]*>`, "i"),
  );
  if (!match) throw new Error(`SAML ${localName} element was not found.`);
  return match[0];
}

function xmlAttribute(tag, name) {
  const match = tag.match(
    new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`, "i"),
  );
  if (!match) throw new Error(`SAML ${name} attribute was not found.`);
  return decodeHtml(match[1] ?? match[2]);
}

function descriptorSection(xml, localName) {
  const match = xml.match(
    new RegExp(
      `<(?:(?:[\\w-]+):)?${localName}\\b[\\s\\S]*?` +
        `</(?:(?:[\\w-]+):)?${localName}>`,
      "i",
    ),
  );
  if (!match) throw new Error(`${localName} metadata was not found.`);
  return match[0];
}

function signingCertificate(metadata, descriptorName) {
  const section = descriptorSection(metadata, descriptorName);
  const match = section.match(
    /<(?:(?:[\w-]+):)?X509Certificate\b[^>]*>([\s\S]*?)<\/(?:(?:[\w-]+):)?X509Certificate>/i,
  );
  if (!match) throw new Error("SAML signing certificate was not found.");
  const certificate = match[1].replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/=]+$/.test(certificate) || certificate.length < 500) {
    throw new Error("SAML signing certificate was malformed.");
  }
  return certificate;
}

function xmlText(xml, localName) {
  const match = xml.match(
    new RegExp(
      `<(?:(?:[\\w-]+):)?${localName}\\b[^>]*>([^<]+)` +
        `</(?:(?:[\\w-]+):)?${localName}>`,
      "i",
    ),
  );
  if (!match) throw new Error(`SAML ${localName} text was not found.`);
  return decodeHtml(match[1].trim());
}

function validateSamlDocuments(authnRequestXml, samlResponseXml) {
  const requestTag = xmlOpeningTag(authnRequestXml, "AuthnRequest");
  const requestId = xmlAttribute(requestTag, "ID");
  assert.equal(
    xmlAttribute(requestTag, "AssertionConsumerServiceURL"),
    BROKER_SAML_ACS,
  );
  assert.equal(
    xmlAttribute(requestTag, "Destination"),
    UPSTREAM_SAML_ENDPOINT,
  );
  assert.ok(
    /<(?:(?:ds|dsig):)?Signature\b/i.test(authnRequestXml),
    "The broker AuthnRequest must carry an XML signature.",
  );
  assert.equal(xmlText(authnRequestXml, "Issuer"), BROKER_SAML_ENTITY_ID);

  const responseTag = xmlOpeningTag(samlResponseXml, "Response");
  assert.equal(xmlAttribute(responseTag, "Destination"), BROKER_SAML_ACS);
  assert.equal(xmlAttribute(responseTag, "InResponseTo"), requestId);
  const assertionStart = samlResponseXml.search(
    /<(?:(?:[\w-]+):)?Assertion\b/i,
  );
  assert.ok(assertionStart > 0, "The SAML Assertion must be present.");
  assert.ok(
    /<(?:(?:ds|dsig):)?Signature\b/i.test(
      samlResponseXml.slice(0, assertionStart),
    ),
    "The SAML Response must carry an XML signature.",
  );
  const assertion = samlResponseXml.slice(assertionStart);
  assert.ok(
    /<(?:(?:ds|dsig):)?Signature\b/i.test(assertion),
    "The SAML Assertion must carry an XML signature.",
  );
  assert.equal(xmlText(assertion, "Audience"), BROKER_SAML_ENTITY_ID);
  const confirmation = xmlOpeningTag(assertion, "SubjectConfirmationData");
  assert.equal(xmlAttribute(confirmation, "Recipient"), BROKER_SAML_ACS);
  assert.equal(xmlAttribute(confirmation, "InResponseTo"), requestId);
  assert.ok(
    /<(?:(?:[\w-]+):)?OneTimeUse\b/i.test(assertion),
    "The synthetic assertion must carry the requested OneTimeUse condition.",
  );
  return requestId;
}

async function adminSession() {
  const tokenResponse = await formRequest(
    `${ORIGIN}/realms/master/protocol/openid-connect/token`,
    {
      grant_type: "password",
      client_id: "admin-cli",
      username: process.env.C04_KC_ADMIN_USERNAME,
      password: process.env.C04_KC_ADMIN_PASSWORD,
    },
  );
  expectStatus(tokenResponse, [200], "C04 Keycloak admin authentication");
  const token = JSON.parse(tokenResponse.body).access_token;
  if (typeof token !== "string" || token.length < 100) {
    throw new Error("C04 Keycloak returned no usable admin token.");
  }
  return { authorization: `Bearer ${token}` };
}

async function createRealm(adminHeaders, realm) {
  await jsonRequest(`${ORIGIN}/admin/realms`, {
    method: "POST",
    headers: adminHeaders,
    allowed: [201],
    body: {
      realm,
      enabled: true,
      sslRequired: "all",
      registrationAllowed: false,
      resetPasswordAllowed: false,
      rememberMe: false,
      loginWithEmailAllowed: false,
      duplicateEmailsAllowed: false,
      bruteForceProtected: true,
      eventsEnabled: true,
      enabledEventTypes: [
        "IDENTITY_PROVIDER_RESPONSE_ERROR",
        "IDENTITY_PROVIDER_LOGIN_ERROR",
        "LOGIN",
        "CODE_TO_TOKEN",
      ],
      accessTokenLifespan: 300,
      ssoSessionIdleTimeout: 600,
      ssoSessionMaxLifespan: 1200,
    },
  });
}

async function createDenyUnlinkedFirstBrokerLoginFlow(adminHeaders) {
  const authenticationRoot =
    `${ORIGIN}/admin/realms/${BROKER_REALM}/authentication`;
  const flowUrl =
    `${authenticationRoot}/flows/${FIRST_BROKER_LOGIN_FLOW}`;
  await jsonRequest(`${authenticationRoot}/flows`, {
    method: "POST",
    headers: adminHeaders,
    allowed: [201],
    body: {
      alias: FIRST_BROKER_LOGIN_FLOW,
      description:
        "Reject every first-broker login unless the identity was pre-linked.",
      providerId: "basic-flow",
      topLevel: true,
      builtIn: false,
    },
  });
  await jsonRequest(`${flowUrl}/executions/execution`, {
    method: "POST",
    headers: adminHeaders,
    allowed: [201],
    body: {
      provider: DENY_ACCESS_AUTHENTICATOR,
    },
  });
  const executions = await jsonRequest(`${flowUrl}/executions`, {
    headers: adminHeaders,
  });
  const denyExecution = executions.value.find(
    (execution) => execution.providerId === DENY_ACCESS_AUTHENTICATOR,
  );
  assert.ok(
    denyExecution,
    "The deny-access execution must exist in the first-broker flow.",
  );
  await jsonRequest(`${flowUrl}/executions`, {
    method: "PUT",
    headers: adminHeaders,
    allowed: [204],
    body: {
      ...denyExecution,
      requirement: "REQUIRED",
    },
  });
  const configuredExecutions = await jsonRequest(
    `${flowUrl}/executions`,
    { headers: adminHeaders },
  );
  assert.ok(
    configuredExecutions.value.some(
      (execution) =>
        execution.providerId === DENY_ACCESS_AUTHENTICATOR &&
        execution.requirement === "REQUIRED",
    ),
    "The first-broker flow must require the deny-access authenticator.",
  );
}

async function createUser(
  adminHeaders,
  realm,
  withPassword,
  username = process.env.C04_KC_TEST_USERNAME,
) {
  const credentials = withPassword
    ? [
        {
          type: "password",
          value: process.env.C04_KC_USER_PASSWORD,
          temporary: false,
        },
      ]
    : [];
  const creation = await jsonRequest(
    `${ORIGIN}/admin/realms/${realm}/users`,
    {
      method: "POST",
      headers: adminHeaders,
      allowed: [201],
      body: {
        username,
        enabled: true,
        emailVerified: true,
        email: `${username}@${realm}.example`,
        firstName: "Synthetic",
        lastName: "Operator",
        requiredActions: [],
        credentials,
      },
    },
  );
  const location = creation.response.headers.location;
  if (typeof location !== "string") {
    throw new Error("C04 Keycloak returned no synthetic user location.");
  }
  return new URL(location, ORIGIN).pathname.split("/").at(-1);
}

async function realmUserCount(adminHeaders, realm) {
  const count = await jsonRequest(
    `${ORIGIN}/admin/realms/${realm}/users/count`,
    { headers: adminHeaders },
  );
  assert.ok(
    Number.isInteger(count.value) && count.value >= 0,
    "Keycloak must return a non-negative realm user count.",
  );
  return count.value;
}

async function exactUsers(adminHeaders, realm, username) {
  const query = new URLSearchParams({
    exact: "true",
    username,
  });
  const users = await jsonRequest(
    `${ORIGIN}/admin/realms/${realm}/users?${query}`,
    { headers: adminHeaders },
  );
  assert.ok(
    Array.isArray(users.value),
    "Keycloak must return a user search result list.",
  );
  return users.value;
}

async function configureRealms() {
  const adminHeaders = await adminSession();
  await createRealm(adminHeaders, UPSTREAM_REALM);
  await createRealm(adminHeaders, BROKER_REALM);
  await createDenyUnlinkedFirstBrokerLoginFlow(adminHeaders);

  await jsonRequest(`${ORIGIN}/admin/realms/${BROKER_REALM}/clients`, {
    method: "POST",
    headers: adminHeaders,
    allowed: [201],
    body: {
      clientId: OIDC_CLIENT_ID,
      name: "C04 Synthetic SAML Portal",
      enabled: true,
      protocol: "openid-connect",
      publicClient: true,
      bearerOnly: false,
      standardFlowEnabled: true,
      implicitFlowEnabled: false,
      directAccessGrantsEnabled: false,
      serviceAccountsEnabled: false,
      consentRequired: false,
      redirectUris: [REDIRECT_URI],
      webOrigins: [],
      fullScopeAllowed: false,
      attributes: {
        "pkce.code.challenge.method": "S256",
      },
    },
  });

  const upstreamMetadataResponse = await request(
    `${UPSTREAM_SAML_ENDPOINT}/descriptor`,
  );
  expectStatus(
    upstreamMetadataResponse,
    [200],
    "C04 upstream IdP metadata",
  );
  const upstreamMetadata = upstreamMetadataResponse.body;
  assert.equal(
    xmlAttribute(xmlOpeningTag(upstreamMetadata, "EntityDescriptor"), "entityID"),
    UPSTREAM_ISSUER,
  );
  const upstreamCertificate = signingCertificate(
    upstreamMetadata,
    "IDPSSODescriptor",
  );

  await jsonRequest(
    `${ORIGIN}/admin/realms/${BROKER_REALM}/identity-provider/instances`,
    {
      method: "POST",
      headers: adminHeaders,
      allowed: [201],
      body: {
        alias: IDP_ALIAS,
        displayName: "C04 Synthetic SAML",
        providerId: "saml",
        enabled: true,
        trustEmail: false,
        storeToken: false,
        addReadTokenRoleOnCreate: false,
        authenticateByDefault: false,
        linkOnly: false,
        firstBrokerLoginFlowAlias: FIRST_BROKER_LOGIN_FLOW,
        config: {
          validateSignature: "true",
          signingCertificate: upstreamCertificate,
          postBindingLogout: "true",
          singleLogoutServiceUrl: UPSTREAM_SAML_ENDPOINT,
          postBindingResponse: "true",
          nameIDPolicyFormat:
            "urn:oasis:names:tc:SAML:2.0:nameid-format:username",
          idpEntityId: UPSTREAM_ISSUER,
          loginHint: "false",
          allowCreate: "true",
          wantAssertionsSigned: "true",
          enabledFromMetadata: "false",
          syncMode: "IMPORT",
          postBindingAuthnRequest: "true",
          forceAuthn: "false",
          singleSignOnServiceUrl: UPSTREAM_SAML_ENDPOINT,
          wantAuthnRequestsSigned: "true",
          allowedClockSkew: "0",
          addExtensionsElementWithKeyInfo: "false",
          principalType: "SUBJECT",
          artifactBindingResponse: "false",
          signSpMetadata: "true",
        },
      },
    },
  );

  const brokerMetadataResponse = await request(
    `${BROKER_SAML_ACS}/descriptor`,
  );
  expectStatus(
    brokerMetadataResponse,
    [200],
    "C04 broker SP metadata",
  );
  const brokerMetadata = brokerMetadataResponse.body;
  const brokerDescriptor = descriptorSection(
    brokerMetadata,
    "SPSSODescriptor",
  );
  assert.equal(
    xmlAttribute(xmlOpeningTag(brokerMetadata, "EntityDescriptor"), "entityID"),
    BROKER_SAML_ENTITY_ID,
  );
  assert.equal(
    xmlAttribute(xmlOpeningTag(brokerDescriptor, "SPSSODescriptor"), "AuthnRequestsSigned"),
    "true",
  );
  assert.equal(
    xmlAttribute(xmlOpeningTag(brokerDescriptor, "SPSSODescriptor"), "WantAssertionsSigned"),
    "true",
  );
  assert.ok(
    /<(?:(?:ds|dsig):)?Signature\b/i.test(
      brokerMetadata.slice(0, brokerMetadata.indexOf(brokerDescriptor)),
    ),
    "The broker SP metadata must be signed.",
  );
  const brokerCertificate = signingCertificate(
    brokerMetadata,
    "SPSSODescriptor",
  );

  await jsonRequest(
    `${ORIGIN}/admin/realms/${UPSTREAM_REALM}/clients`,
    {
      method: "POST",
      headers: adminHeaders,
      allowed: [201],
      body: {
        clientId: BROKER_SAML_ENTITY_ID,
        name: "C04 Synthetic Broker SP",
        enabled: true,
        protocol: "saml",
        redirectUris: [BROKER_SAML_ACS],
        standardFlowEnabled: true,
        frontchannelLogout: true,
        fullScopeAllowed: true,
        attributes: {
          "saml_assertion_consumer_url_post": BROKER_SAML_ACS,
          "saml_single_logout_service_url_post": BROKER_SAML_ACS,
          "saml.force.post.binding": "true",
          "saml.client.signature": "true",
          "saml.server.signature": "true",
          "saml.assertion.signature": "true",
          "saml.signature.algorithm": "RSA_SHA256",
          "saml.signing.certificate": brokerCertificate,
          "saml.authnstatement": "true",
          "saml.onetimeuse.condition": "true",
          "saml_force_name_id_format": "true",
          "saml_name_id_format": "username",
          "saml.server.signature.keyinfo.ext": "false",
          "saml_signature_canonicalization_method":
            "http://www.w3.org/2001/10/xml-exc-c14n#",
        },
      },
    },
  );

  const upstreamUserId = await createUser(
    adminHeaders,
    UPSTREAM_REALM,
    true,
  );
  assert.ok(
    /^[0-9a-f-]{36}$/i.test(upstreamUserId),
    "The linked upstream user must have a UUID.",
  );
  const unlinkedUpstreamUserId = await createUser(
    adminHeaders,
    UPSTREAM_REALM,
    true,
    UNLINKED_USERNAME,
  );
  assert.ok(
    /^[0-9a-f-]{36}$/i.test(unlinkedUpstreamUserId),
    "The unlinked upstream user must have a UUID.",
  );
  const brokerUserId = await createUser(adminHeaders, BROKER_REALM, false);
  assert.ok(
    /^[0-9a-f-]{36}$/i.test(brokerUserId),
    "The linked broker user must have a UUID.",
  );
  await jsonRequest(
    `${ORIGIN}/admin/realms/${BROKER_REALM}/users/` +
      `${brokerUserId}/federated-identity/${IDP_ALIAS}`,
    {
      method: "POST",
      headers: adminHeaders,
      allowed: [204],
      body: {
        identityProvider: IDP_ALIAS,
        userId: process.env.C04_KC_TEST_USERNAME,
        userName: process.env.C04_KC_TEST_USERNAME,
      },
    },
  );

  const idp = await jsonRequest(
    `${ORIGIN}/admin/realms/${BROKER_REALM}/identity-provider/instances/` +
      IDP_ALIAS,
    { headers: adminHeaders },
  );
  assert.equal(idp.value.trustEmail, false);
  assert.equal(idp.value.storeToken, false);
  assert.equal(
    idp.value.firstBrokerLoginFlowAlias,
    FIRST_BROKER_LOGIN_FLOW,
  );
  assert.equal(idp.value.config.validateSignature, "true");
  assert.equal(idp.value.config.wantAssertionsSigned, "true");
  assert.equal(idp.value.config.wantAuthnRequestsSigned, "true");
  assert.equal(idp.value.config.signSpMetadata, "true");

  const clients = await jsonRequest(
    `${ORIGIN}/admin/realms/${UPSTREAM_REALM}/clients?` +
      new URLSearchParams({ clientId: BROKER_SAML_ENTITY_ID }),
    { headers: adminHeaders },
  );
  assert.equal(clients.value.length, 1);
  assert.equal(clients.value[0].attributes["saml.client.signature"], "true");
  assert.equal(clients.value[0].attributes["saml.server.signature"], "true");
  assert.equal(
    clients.value[0].attributes["saml.assertion.signature"],
    "true",
  );
  return adminHeaders;
}

function authorizationUrl(state, nonce, codeChallenge) {
  const url = new URL(
    `${BROKER_ISSUER}/protocol/openid-connect/auth`,
  );
  url.search = new URLSearchParams({
    response_type: "code",
    scope: "openid",
    client_id: OIDC_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    kc_idp_hint: IDP_ALIAS,
  });
  return url.href;
}

async function captureSamlExchange(
  username = process.env.C04_KC_TEST_USERNAME,
) {
  const jar = new CookieJar();
  const state = randomBytes(24).toString("base64url");
  const nonce = randomBytes(24).toString("base64url");
  const codeVerifier = randomBytes(48).toString("base64url");
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  const startUrl = authorizationUrl(state, nonce, codeChallenge);
  const start = await browserRequest(jar, startUrl);
  const brokerPage = await followInternalRedirects(jar, start, startUrl);
  expectStatus(brokerPage.response, [200], "C04 broker SAML request page");
  const requestForm = findForm(
    brokerPage.response,
    brokerPage.url,
    (form) => form.fields.has("SAMLRequest"),
    "C04 broker SAML request",
  );
  const authnRequestXml = Buffer.from(
    requestForm.fields.get("SAMLRequest"),
    "base64",
  ).toString("utf8");

  const requestSubmission = await submitForm(jar, requestForm);
  const loginPage = await followInternalRedirects(
    jar,
    requestSubmission.response,
    requestSubmission.url,
  );
  expectStatus(loginPage.response, [200], "C04 upstream login page");
  const loginForm = findForm(
    loginPage.response,
    loginPage.url,
    (form) => form.id === "kc-form-login",
    "C04 upstream login",
  );
  const loginSubmission = await submitForm(jar, loginForm, {
    username,
    password: process.env.C04_KC_USER_PASSWORD,
    credentialId: "",
    login: "Sign In",
  });
  const responsePage = await followInternalRedirects(
    jar,
    loginSubmission.response,
    loginSubmission.url,
  );
  expectStatus(responsePage.response, [200], "C04 upstream SAML response page");
  const responseForm = findForm(
    responsePage.response,
    responsePage.url,
    (form) => form.fields.has("SAMLResponse"),
    "C04 upstream SAML response",
  );
  const samlResponseXml = Buffer.from(
    responseForm.fields.get("SAMLResponse"),
    "base64",
  ).toString("utf8");
  validateSamlDocuments(authnRequestXml, samlResponseXml);
  return {
    jar,
    state,
    nonce,
    codeVerifier,
    authnRequestXml,
    responseForm,
    samlResponseXml,
  };
}

async function submitSamlResponse(exchange, responseForm = exchange.responseForm) {
  const submission = await submitForm(exchange.jar, responseForm);
  return followToCallbackOrResponse(
    exchange.jar,
    submission.response,
    submission.url,
  );
}

async function exchangeAuthorizationCode(code, codeVerifier) {
  const tokenResponse = await formRequest(
    `${BROKER_ISSUER}/protocol/openid-connect/token`,
    {
      grant_type: "authorization_code",
      client_id: OIDC_CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code,
      code_verifier: codeVerifier,
    },
  );
  expectStatus(tokenResponse, [200], "C04 broker OIDC PKCE token exchange");
  const token = JSON.parse(tokenResponse.body);
  if (
    typeof token.access_token !== "string" ||
    typeof token.id_token !== "string"
  ) {
    throw new Error("C04 broker returned no OIDC tokens.");
  }
  const payload = JSON.parse(
    Buffer.from(token.id_token.split(".")[1], "base64url").toString("utf8"),
  );
  assert.equal(payload.iss, BROKER_ISSUER);
  assert.equal(payload.aud, OIDC_CLIENT_ID);
  return token;
}

async function brokerEvents(adminHeaders) {
  const events = await jsonRequest(
    `${ORIGIN}/admin/realms/${BROKER_REALM}/events?max=100`,
    { headers: adminHeaders },
  );
  return events.value;
}

function tamperSignedNameId(exchange) {
  let changed = false;
  const xml = exchange.samlResponseXml.replace(
    /(<(?:(?:[\w-]+):)?NameID\b[^>]*>)([^<]+)(<\/(?:(?:[\w-]+):)?NameID>)/i,
    (full, opening, value, closing) => {
      changed = true;
      return `${opening}${value}x${closing}`;
    },
  );
  assert.equal(changed, true, "A signed NameID must be available to tamper.");
  assert.ok(
    xml !== exchange.samlResponseXml,
    "The tampered SAML document must differ from the original.",
  );
  const fields = new Map(exchange.responseForm.fields);
  fields.set("SAMLResponse", Buffer.from(xml, "utf8").toString("base64"));
  return { ...exchange.responseForm, fields };
}

test(
  "C04 completes and rejects the required real Keycloak 26.7.0 SAML flows",
  async () => {
    const adminHeaders = await configureRealms();

    const positive = await captureSamlExchange();
    const completed = await submitSamlResponse(positive);
    assert.equal(completed.kind, "callback");
    assert.equal(completed.location.searchParams.get("error"), null);
    assert.equal(completed.location.searchParams.get("state"), positive.state);
    const authorizationCode = completed.location.searchParams.get("code");
    assert.ok(authorizationCode, "The broker callback must include a code.");
    await exchangeAuthorizationCode(authorizationCode, positive.codeVerifier);

    const badSignature = await captureSamlExchange();
    const rejectedSignature = await submitSamlResponse(
      badSignature,
      tamperSignedNameId(badSignature),
    );
    assert.equal(rejectedSignature.kind, "response");
    assert.equal(rejectedSignature.response.status, 400);
    const signatureEvents = await brokerEvents(adminHeaders);
    assert.ok(
      signatureEvents.some((event) => event.error === "invalid_signature"),
      "Keycloak must record invalid_signature for the tampered response. " +
        JSON.stringify(
          signatureEvents.map((event) => ({
            error: event.error,
            type: event.type,
          })),
        ),
    );

    const replay = await captureSamlExchange();
    const firstSubmission = await submitSamlResponse(replay);
    assert.equal(firstSubmission.kind, "callback");
    assert.equal(firstSubmission.location.searchParams.get("error"), null);
    assert.equal(
      firstSubmission.location.searchParams.get("state"),
      replay.state,
    );
    const secondSubmission = await submitSamlResponse(replay);
    assert.equal(secondSubmission.kind, "response");
    assert.equal(secondSubmission.response.status, 400);
    assert.ok(
      (await brokerEvents(adminHeaders)).some(
        (event) => event.error === "already_logged_in",
      ),
      "The consumed SP login session must reject the exact response replay.",
    );

    const brokerUsersBefore = await realmUserCount(
      adminHeaders,
      BROKER_REALM,
    );
    assert.equal(
      (await exactUsers(adminHeaders, BROKER_REALM, UNLINKED_USERNAME))
        .length,
      0,
      "The upstream-only user must not exist in the broker realm.",
    );
    const unlinked = await captureSamlExchange(UNLINKED_USERNAME);
    const rejectedUnlinked = await submitSamlResponse(unlinked);
    assert.equal(
      rejectedUnlinked.kind,
      "response",
      "An unlinked upstream user must not reach the OIDC callback.",
    );
    assert.equal(
      rejectedUnlinked.response.status,
      401,
      "The deny-access first-broker flow must return HTTP 401.",
    );
    assert.equal(
      new URL(rejectedUnlinked.url).searchParams.has("code"),
      false,
      "The rejected first-broker login must not produce an OIDC code.",
    );
    assert.equal(
      await realmUserCount(adminHeaders, BROKER_REALM),
      brokerUsersBefore,
      "Rejecting an unlinked upstream user must not create a broker user.",
    );
    assert.equal(
      (await exactUsers(adminHeaders, BROKER_REALM, UNLINKED_USERNAME))
        .length,
      0,
      "The rejected upstream identity must remain absent from the broker realm.",
    );
  },
);

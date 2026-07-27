import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  C17ConnectorError,
  c17ConnectorSha256,
  createC17CredentialBroker,
  createC17ConnectorSdk,
  createC17ConnectorTemplates,
  validateConnectorEnvelope,
} from "../lib/c17-connector-sdk.mjs";
import {
  createC17MockLab,
} from "../lib/c17-mock-lab.mjs";

const templateDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c17/connector-templates.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const fixtureDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c17/synthetic-connector-fixtures.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const PRINCIPAL =
  "prn_018f0000-0000-7000-8000-000000000001";
const CALL = "tcl_018f0000-0000-7000-8000-000000000101";
const NOW = "2026-07-26T12:00:00.000Z";

function ids() {
  let value = 500;
  return () => {
    value += 1;
    return `018f0000-0000-7000-8000-${String(value).padStart(12, "0")}`;
  };
}

function serverContext(overrides = {}) {
  return {
    tenantId: TENANT,
    tenantKind: "SYNTHETIC",
    principalId: PRINCIPAL,
    callId: CALL,
    connectorStage: "C0_DISABLED",
    ...overrides,
  };
}

function createHarness({
  faultMode = "NONE",
  timeoutMs = 50,
} = {}) {
  const broker = createC17CredentialBroker(NOW);
  const lab = createC17MockLab({
    templateDocument,
    fixtureDocument,
    observedAt: NOW,
    faultMode,
  });
  const sdk = createC17ConnectorSdk({
    templateDocument,
    credentialBroker: broker,
    adapter: lab,
    timeoutMs,
  });
  return { sdk, broker, lab };
}

function requestEnvelope(overrides = {}) {
  return {
    document_status: "GENERIC_PRODUCT_TEMPLATE",
    contract_version: 1,
    message_type: "REQUEST",
    operation_id: "synthetic.approval.status.get",
    trace_id: "trace-c17-0001",
    principal_id:
      "prn_018f0000-0000-7000-8000-000000000001",
    purpose: "Read one fictitious approval status.",
    request: {
      parameters: { approvalRef: "SYN-APR-0001" },
      requested_as_of: null,
    },
    ...overrides,
  };
}

function countedProxy(value, counter) {
  return new Proxy(value, {
    get(target, property, receiver) {
      counter.count += 1;
      return Reflect.get(target, property, receiver);
    },
    getPrototypeOf(target) {
      counter.count += 1;
      return Reflect.getPrototypeOf(target);
    },
    ownKeys(target) {
      counter.count += 1;
      return Reflect.ownKeys(target);
    },
    getOwnPropertyDescriptor(target, property) {
      counter.count += 1;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  });
}

test("validator accepts and freezes one canonical request envelope", () => {
  const source = requestEnvelope();
  const validated = validateConnectorEnvelope(source);
  assert.deepEqual(validated, source);
  assert.notEqual(validated, source);
  assert.equal(Object.isFrozen(validated), true);
  assert.equal(Object.isFrozen(validated.request.parameters), true);
});

test("validator rejects extra fields and schema injection", () => {
  const attacks = [
    requestEnvelope({ endpoint: "synthetic.invalid" }),
    requestEnvelope({
      request: {
        parameters: JSON.parse(
          '{"approvalRef":"SYN-APR-0001","__proto__":{"admin":true}}',
        ),
        requested_as_of: null,
      },
    }),
    requestEnvelope({
      request: {
        parameters: { approvalRef: "SYN-APR-0001" },
        requested_as_of: null,
        credentials: "synthetic-placeholder",
      },
    }),
    requestEnvelope({
      request: {
        parameters: { approvalRef: "SYN-APR-0001" },
        requested_as_of: "2026-99-99T12:00:00.000Z",
      },
    }),
    requestEnvelope({
      operation_id: `synthetic.${"a".repeat(170)}.get`,
    }),
  ];
  for (const attack of attacks) {
    assert.throws(
      () => validateConnectorEnvelope(attack),
      (error) =>
        error instanceof C17ConnectorError &&
        error.code === "INVALID_ENVELOPE",
    );
  }
});

test("validator inertly rejects Envelope accessors and Proxies", () => {
  const accessorEnvelope = requestEnvelope();
  let getterCount = 0;
  Object.defineProperty(accessorEnvelope, "message_type", {
    enumerable: true,
    get() {
      getterCount += 1;
      return "REQUEST";
    },
  });
  assert.throws(
    () => validateConnectorEnvelope(accessorEnvelope),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_ENVELOPE",
  );
  assert.equal(getterCount, 0);

  const trapCounter = { count: 0 };
  const proxyEnvelope = countedProxy(
    requestEnvelope(),
    trapCounter,
  );
  assert.throws(
    () => validateConnectorEnvelope(proxyEnvelope),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_ENVELOPE",
  );
  assert.equal(trapCounter.count, 0);
});

test("validator rejects non-JSON result data", () => {
  assert.throws(
    () =>
      validateConnectorEnvelope({
        document_status: "GENERIC_PRODUCT_TEMPLATE",
        contract_version: 1,
        message_type: "RESULT",
        operation_id: "synthetic.approval.status.get",
        trace_id: "trace-c17-invalid-result",
        principal_id: PRINCIPAL,
        purpose: "Read one fictitious approval status.",
        result: {
          status: "OK",
          data: undefined,
          provenance: {
            source_mode: "SYNTHETIC",
            freshness_status: "CURRENT",
            as_of: null,
            observed_at: NOW,
            content_hash: null,
          },
          error: null,
        },
      }),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_ENVELOPE",
  );
});

test("validator rejects a 20000-level JSON request without reaching the Adapter", async () => {
  let nested = "leaf";
  for (let depth = 0; depth < 20_000; depth += 1) {
    nested = { nested };
  }
  const envelope = requestEnvelope({
    request: {
      parameters: {
        approvalRef: "SYN-APR-0001",
        nested,
      },
      requested_as_of: null,
    },
  });

  assert.throws(
    () => validateConnectorEnvelope(envelope),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_ENVELOPE",
  );

  const { sdk, lab } = createHarness();
  await assert.rejects(
    sdk.execute(serverContext(), envelope),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_ENVELOPE",
  );
  assert.equal(lab.snapshot().invocationCount, 0);
});

test("validator accepts F03 date-time variants and normalizes them to UTC milliseconds", () => {
  const request = validateConnectorEnvelope(
    requestEnvelope({
      request: {
        parameters: { approvalRef: "SYN-APR-0001" },
        requested_as_of: "2026-07-26T12:00:00+08:00",
      },
    }),
  );
  assert.equal(
    request.request.requested_as_of,
    "2026-07-26T04:00:00.000Z",
  );

  const data = {
    approvalRef: "SYN-APR-0001",
    status: "PENDING_SYNTHETIC_REVIEW",
  };
  const result = validateConnectorEnvelope({
    document_status: "GENERIC_PRODUCT_TEMPLATE",
    contract_version: 1,
    message_type: "RESULT",
    operation_id: "synthetic.approval.status.get",
    trace_id: "trace-c17-time-normalization",
    principal_id: PRINCIPAL,
    purpose: "Read one fictitious approval status.",
    result: {
      status: "OK",
      data,
      provenance: {
        source_mode: "SYNTHETIC",
        freshness_status: "CURRENT",
        as_of: "2026-07-26T11:55:00Z",
        observed_at: "2026-07-26T12:00:00+08:00",
        content_hash: c17ConnectorSha256(data),
      },
      error: null,
    },
  });
  assert.equal(result.result.provenance.as_of, "2026-07-26T11:55:00.000Z");
  assert.equal(
    result.result.provenance.observed_at,
    "2026-07-26T04:00:00.000Z",
  );
  assert.equal(
    result.result.provenance.content_hash,
    c17ConnectorSha256(data),
  );
});

test("template catalog exposes exactly three disabled read-only categories", () => {
  const catalog = createC17ConnectorTemplates(templateDocument);
  assert.deepEqual(
    catalog.list().map((template) => [
      template.category,
      template.operationId,
      template.mode,
    ]),
    [
      [
        "APPROVAL_COLLABORATION",
        "synthetic.approval.status.get",
        "READ_ONLY",
      ],
      ["ERP_BUSINESS", "synthetic.erp.order.get", "READ_ONLY"],
      ["BI_ANALYTICS", "synthetic.bi.metric.get", "READ_ONLY"],
    ],
  );
  assert.equal(catalog.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(catalog.connectorStage, "C0_DISABLED");
  assert.equal(catalog.networkAccess, "DISABLED");
  assert.equal(Object.isFrozen(catalog.list()[0]), true);
});

test("template catalog rejects compatible-looking local widening", () => {
  const mutations = [
    (document) => {
      document.templates[0].audience = "c16-c0-erp";
    },
    (document) => {
      document.templates[1].parameterSchema.properties.orderRef.pattern =
        "^.+$";
    },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(templateDocument);
    mutate(changed);
    assert.throws(
      () => createC17ConnectorTemplates(changed),
      (error) =>
        error instanceof C17ConnectorError &&
        error.code === "INVALID_CONFIGURATION",
    );
  }
});

test("template catalog inertly rejects accessors and Proxies", () => {
  const accessorDocument = structuredClone(templateDocument);
  let getterCount = 0;
  Object.defineProperty(accessorDocument, "schemaVersion", {
    enumerable: true,
    get() {
      getterCount += 1;
      return "1.0.0";
    },
  });
  assert.throws(
    () => createC17ConnectorTemplates(accessorDocument),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_CONFIGURATION",
  );
  assert.equal(getterCount, 0);

  const trapCounter = { count: 0 };
  const proxyDocument = countedProxy(
    structuredClone(templateDocument),
    trapCounter,
  );
  assert.throws(
    () => createC17ConnectorTemplates(proxyDocument),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_CONFIGURATION",
  );
  assert.equal(trapCounter.count, 0);
});

test("template catalog inertly rejects schema values with nested accessors and Proxies", () => {
  const catalog = createC17ConnectorTemplates(templateDocument);
  const accessorParameters = {};
  let getterCount = 0;
  Object.defineProperty(accessorParameters, "approvalRef", {
    enumerable: true,
    get() {
      getterCount += 1;
      return "SYN-APR-0001";
    },
  });
  assert.equal(
    catalog.validateParameters(
      "synthetic.approval.status.get",
      accessorParameters,
    ),
    false,
  );
  assert.equal(getterCount, 0);

  const trapCounter = { count: 0 };
  const proxyValue = countedProxy(
    { toString: () => "SYN-APR-0001" },
    trapCounter,
  );
  assert.equal(
    catalog.validateParameters(
      "synthetic.approval.status.get",
      { approvalRef: proxyValue },
    ),
    false,
  );
  assert.equal(trapCounter.count, 0);
});

test("SDK rejects an unregistered Adapter while C0 is disabled", () => {
  const { broker } = createHarness();
  let externalEffectCount = 0;
  const injectedAdapter = {
    async execute() {
      externalEffectCount += 1;
      return null;
    },
  };

  assert.throws(
    () =>
      createC17ConnectorSdk({
        templateDocument,
        credentialBroker: broker,
        adapter: injectedAdapter,
        timeoutMs: 50,
      }),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_CONFIGURATION",
  );
  assert.equal(externalEffectCount, 0);
});

test("SDK inertly rejects configuration accessors and Proxies", () => {
  const broker = createC17CredentialBroker(NOW);
  const lab = createC17MockLab({
    templateDocument,
    fixtureDocument,
    observedAt: NOW,
  });
  const accessorConfiguration = {
    templateDocument,
    credentialBroker: broker,
    timeoutMs: 50,
  };
  let getterCount = 0;
  Object.defineProperty(accessorConfiguration, "adapter", {
    enumerable: true,
    get() {
      getterCount += 1;
      return lab;
    },
  });
  assert.throws(
    () => createC17ConnectorSdk(accessorConfiguration),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_CONFIGURATION",
  );
  assert.equal(getterCount, 0);

  const trapCounter = { count: 0 };
  const proxyConfiguration = countedProxy(
    {
      templateDocument,
      credentialBroker: broker,
      adapter: lab,
      timeoutMs: 50,
    },
    trapCounter,
  );
  assert.throws(
    () => createC17ConnectorSdk(proxyConfiguration),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_CONFIGURATION",
  );
  assert.equal(trapCounter.count, 0);
});

test("SDK rejects an unregistered capability Broker while C0 is disabled", () => {
  const lab = createC17MockLab({
    templateDocument,
    fixtureDocument,
    observedAt: NOW,
  });
  const injectedBroker = {
    assertUsable() {},
    revoke() {},
  };

  assert.throws(
    () =>
      createC17ConnectorSdk({
        templateDocument,
        credentialBroker: injectedBroker,
        adapter: lab,
        timeoutMs: 50,
      }),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_CONFIGURATION",
  );
});

test("C17 capability Broker rejects executable configuration hooks", () => {
  let externalEffectCount = 0;
  assert.throws(
    () =>
      createC17CredentialBroker({
        clock: () => {
          externalEffectCount += 1;
          return NOW;
        },
        idFactory: ids(),
        ttlSeconds: 15,
      }),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_CONFIGURATION",
  );
  assert.equal(externalEffectCount, 0);
});

test("C17 capability Broker inertly rejects accessor and Proxy scopes", () => {
  const accessorScope = {
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  };
  let getterCount = 0;
  Object.defineProperty(accessorScope, "tenantId", {
    enumerable: true,
    get() {
      getterCount += 1;
      return TENANT;
    },
  });
  assert.throws(
    () => createC17CredentialBroker(NOW).issue(accessorScope),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_INPUT",
  );
  assert.equal(getterCount, 0);

  const trapCounter = { count: 0 };
  const proxyScope = countedProxy(
    {
      tenantId: TENANT,
      operationId: "synthetic.approval.status.get",
      callId: CALL,
      audience: "c16-c0-approval",
    },
    trapCounter,
  );
  assert.throws(
    () => createC17CredentialBroker(NOW).issue(proxyScope),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_INPUT",
  );
  assert.equal(trapCounter.count, 0);
});

test("C17 capability Broker inertly denies accessor and Proxy authorization values", () => {
  const scope = {
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  };
  const brokerForScope = createC17CredentialBroker(NOW);
  const capabilityForScope = brokerForScope.issue(scope);
  const accessorScope = {
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
  };
  let scopeGetterCount = 0;
  Object.defineProperty(accessorScope, "audience", {
    enumerable: true,
    get() {
      scopeGetterCount += 1;
      return "c16-c0-approval";
    },
  });
  assert.throws(
    () =>
      brokerForScope.assertUsable(
        capabilityForScope,
        accessorScope,
      ),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "DENIED",
  );
  assert.equal(scopeGetterCount, 0);

  const brokerForCapability = createC17CredentialBroker(NOW);
  const capability = brokerForCapability.issue(scope);
  const trapCounter = { count: 0 };
  const proxyCapability = countedProxy(
    { ...capability },
    trapCounter,
  );
  assert.throws(
    () =>
      brokerForCapability.assertUsable(proxyCapability, scope),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "DENIED",
  );
  assert.equal(trapCounter.count, 0);

  const brokerForRevoke = createC17CredentialBroker(NOW);
  const capabilityForRevoke = brokerForRevoke.issue(scope);
  const accessorCapability = { ...capabilityForRevoke };
  let capabilityGetterCount = 0;
  Object.defineProperty(accessorCapability, "capabilityId", {
    enumerable: true,
    get() {
      capabilityGetterCount += 1;
      return capabilityForRevoke.capabilityId;
    },
  });
  assert.throws(
    () => brokerForRevoke.revoke(accessorCapability),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "DENIED",
  );
  assert.equal(capabilityGetterCount, 0);
});

test("SDK consumes one C16 capability and returns a canonical result", async () => {
  const { sdk, broker, lab } = createHarness();
  const capability = broker.issue({
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  });
  const result = await sdk.execute(
    serverContext(),
    requestEnvelope(),
    capability,
  );
  assert.equal(result.message_type, "RESULT");
  assert.equal(result.result.status, "OK");
  assert.equal(result.result.data.approvalRef, "SYN-APR-0001");
  assert.equal(Object.hasOwn(result, "request"), false);
  assert.deepEqual(validateConnectorEnvelope(result), result);
  assert.equal(broker.snapshot().activeCapabilityCount, 0);
  assert.equal(broker.snapshot().revokedCapabilityCount, 1);
  assert.equal(lab.snapshot().invocationCount, 1);
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes(capability.opaque), false);
  assert.equal(serialized.includes(capability.capabilityId), false);
});

test("SDK rejects a CURRENT result observed before the requested as-of time", async () => {
  const { sdk, broker } = createHarness();
  const capability = broker.issue({
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  });

  await assert.rejects(
    sdk.execute(
      serverContext(),
      requestEnvelope({
        request: {
          parameters: { approvalRef: "SYN-APR-0001" },
          requested_as_of: "2026-07-26T12:30:00.000Z",
        },
      }),
      capability,
    ),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_ADAPTER_RESULT",
  );
});

test("SDK rejects an older observation after accepting a newer result for the same lookup", async () => {
  const { sdk, broker, lab } = createHarness({
    faultMode: "OUT_OF_ORDER_SEQUENCE",
  });
  const scope = {
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  };

  const first = await sdk.execute(
    serverContext(),
    requestEnvelope(),
    broker.issue(scope),
  );
  assert.equal(
    first.result.provenance.observed_at,
    "2026-07-26T12:00:00.000Z",
  );

  await assert.rejects(
    sdk.execute(
      serverContext(),
      requestEnvelope({ trace_id: "trace-c17-out-of-order" }),
      broker.issue(scope),
    ),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_ADAPTER_RESULT",
  );
  assert.equal(lab.snapshot().invocationCount, 2);
});

test("SDK inertly rejects nested context accessors and Proxies", async () => {
  const accessorTenant = {};
  let getterCount = 0;
  Object.defineProperty(accessorTenant, "toString", {
    enumerable: true,
    get() {
      getterCount += 1;
      return () => TENANT;
    },
  });
  const accessorHarness = createHarness();
  await assert.rejects(
    accessorHarness.sdk.execute(
      serverContext({ tenantId: accessorTenant }),
      requestEnvelope(),
    ),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "SYNTHETIC_BOUNDARY_VIOLATION",
  );
  assert.equal(getterCount, 0);
  assert.equal(accessorHarness.lab.snapshot().invocationCount, 0);

  const trapCounter = { count: 0 };
  const proxyTenant = countedProxy(
    { toString: () => TENANT },
    trapCounter,
  );
  const proxyHarness = createHarness();
  await assert.rejects(
    proxyHarness.sdk.execute(
      serverContext({ tenantId: proxyTenant }),
      requestEnvelope(),
    ),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "SYNTHETIC_BOUNDARY_VIOLATION",
  );
  assert.equal(trapCounter.count, 0);
  assert.equal(proxyHarness.lab.snapshot().invocationCount, 0);
});

test("SDK inertly denies capability accessors and Proxies", async () => {
  for (const makeCapability of [
    (capability, counter) => {
      const accessorCapability = { ...capability };
      Object.defineProperty(accessorCapability, "capabilityId", {
        enumerable: true,
        get() {
          counter.count += 1;
          return capability.capabilityId;
        },
      });
      return accessorCapability;
    },
    (capability, counter) =>
      countedProxy({ ...capability }, counter),
  ]) {
    const { sdk, broker, lab } = createHarness();
    const capability = broker.issue({
      tenantId: TENANT,
      operationId: "synthetic.approval.status.get",
      callId: CALL,
      audience: "c16-c0-approval",
    });
    const counter = { count: 0 };
    await assert.rejects(
      sdk.execute(
        serverContext(),
        requestEnvelope(),
        makeCapability(capability, counter),
      ),
      (error) =>
        error instanceof C17ConnectorError &&
        error.code === "DENIED",
    );
    assert.equal(counter.count, 0);
    assert.equal(lab.snapshot().invocationCount, 0);
  }
});

test("SDK rejects an expired C16 capability before Mock access", async () => {
  const { sdk, broker, lab } = createHarness();
  const capability = broker.issue({
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  });
  broker.setSyntheticObservedAt("2026-07-26T12:00:15.000Z");
  await assert.rejects(
    sdk.execute(serverContext(), requestEnvelope(), capability),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "DENIED",
  );
  assert.equal(lab.snapshot().invocationCount, 0);
});

test("SDK rejects a revoked C16 capability before Mock access", async () => {
  const { sdk, broker, lab } = createHarness();
  const capability = broker.issue({
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  });
  broker.revoke(capability);
  await assert.rejects(
    sdk.execute(serverContext(), requestEnvelope(), capability),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "DENIED",
  );
  assert.equal(lab.snapshot().invocationCount, 0);
});

test("SDK fails closed when authorization is missing or forged", async () => {
  for (const capability of [
    undefined,
    {
      capabilityId: "cap_forged",
      opaque: "synthetic-forged-value",
    },
  ]) {
    const { sdk, lab } = createHarness();
    await assert.rejects(
      sdk.execute(serverContext(), requestEnvelope(), capability),
      (error) =>
        error instanceof C17ConnectorError &&
        error.code === "DENIED",
    );
    assert.equal(lab.snapshot().invocationCount, 0);
  }
});

test("SDK rejects Tenant confusion before Mock access", async () => {
  const { sdk, broker, lab } = createHarness();
  const capability = broker.issue({
    tenantId:
      "stn_018f0000-0000-7000-8000-000000000011",
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  });
  await assert.rejects(
    sdk.execute(serverContext(), requestEnvelope(), capability),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "DENIED",
  );
  assert.equal(lab.snapshot().invocationCount, 0);
});

test("SDK rejects operation, call, and audience capability mismatches before Mock access", async () => {
  const mismatchScopes = [
    {
      tenantId: TENANT,
      operationId: "synthetic.erp.order.get",
      callId: CALL,
      audience: "c16-c0-approval",
    },
    {
      tenantId: TENANT,
      operationId: "synthetic.approval.status.get",
      callId: "tcl_018f0000-0000-7000-8000-000000000102",
      audience: "c16-c0-approval",
    },
    {
      tenantId: TENANT,
      operationId: "synthetic.approval.status.get",
      callId: CALL,
      audience: "c16-c0-erp",
    },
  ];

  for (const scope of mismatchScopes) {
    const { sdk, broker, lab } = createHarness();
    const capability = broker.issue(scope);
    await assert.rejects(
      sdk.execute(serverContext(), requestEnvelope(), capability),
      (error) =>
        error instanceof C17ConnectorError &&
        error.code === "DENIED",
    );
    assert.equal(lab.snapshot().invocationCount, 0);
  }
});

test("SDK rejects a non-stable principal before Mock access", async () => {
  const { sdk, broker, lab } = createHarness();
  const capability = broker.issue({
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  });
  await assert.rejects(
    sdk.execute(
      serverContext({ principalId: "person@synthetic.invalid" }),
      requestEnvelope({ principal_id: "person@synthetic.invalid" }),
      capability,
    ),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "SYNTHETIC_BOUNDARY_VIOLATION",
  );
  assert.equal(lab.snapshot().invocationCount, 0);
});

test("SDK rejects SSRF-shaped parameters before Mock access", async () => {
  const { sdk, broker, lab } = createHarness();
  const capability = broker.issue({
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  });
  await assert.rejects(
    sdk.execute(
      serverContext(),
      requestEnvelope({
        request: {
          parameters: {
            approvalRef: "SYN-APR-0001",
            targetUrl: "https://synthetic.invalid/resource",
          },
          requested_as_of: null,
        },
      }),
      capability,
    ),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_REQUEST",
  );
  assert.equal(lab.snapshot().invocationCount, 0);
  assert.equal(lab.snapshot().networkRequestCount, 0);
});

test("SDK rejects capability replay without a second Mock access", async () => {
  const { sdk, broker, lab } = createHarness();
  const capability = broker.issue({
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  });
  await sdk.execute(serverContext(), requestEnvelope(), capability);
  await assert.rejects(
    sdk.execute(
      serverContext(),
      requestEnvelope({ trace_id: "trace-c17-replayed" }),
      capability,
    ),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "REPLAY_REJECTED",
  );
  assert.equal(lab.snapshot().invocationCount, 1);
});

test("SDK fails closed when the Adapter exceeds its timeout", async () => {
  const { sdk, broker, lab } = createHarness({
    faultMode: "TIMEOUT",
    timeoutMs: 5,
  });
  const capability = broker.issue({
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  });
  await assert.rejects(
    sdk.execute(serverContext(), requestEnvelope(), capability),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "UNAVAILABLE" &&
      !error.message.includes(capability.opaque),
  );
  assert.equal(lab.snapshot().invocationCount, 1);
});

test("SDK never passes or exposes the C16 capability to an Adapter", async () => {
  const { sdk, broker, lab } = createHarness({
    faultMode: "THROW",
  });
  const capability = broker.issue({
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  });
  await assert.rejects(
    sdk.execute(serverContext(), requestEnvelope(), capability),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "UNAVAILABLE" &&
      !error.message.includes(capability.opaque),
  );
  assert.equal(lab.snapshot().invocationCount, 1);
});

test("SDK rejects an Adapter result with undeclared fields", async () => {
  const { sdk, broker } = createHarness({
    faultMode: "EXTRA_FIELD",
  });
  const capability = broker.issue({
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  });
  await assert.rejects(
    sdk.execute(serverContext(), requestEnvelope(), capability),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_ADAPTER_RESULT",
  );
});

test("SDK rejects a valid-shaped result for a different lookup", async () => {
  const { sdk, broker } = createHarness({
    faultMode: "LOOKUP_CONFUSION",
  });
  const capability = broker.issue({
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
  });
  await assert.rejects(
    sdk.execute(serverContext(), requestEnvelope(), capability),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_ADAPTER_RESULT",
  );
});

test("SDK and C16 cover all three Templates for all three Synthetic Tenants", async () => {
  const tenants = [
    "stn_018f0000-0000-7000-8000-000000000010",
    "stn_018f0000-0000-7000-8000-000000000011",
    "stn_018f0000-0000-7000-8000-000000000012",
  ];
  const operations = [
    {
      operationId: "synthetic.approval.status.get",
      audience: "c16-c0-approval",
      parameters: (index) => ({
        approvalRef: `SYN-APR-000${index + 1}`,
      }),
    },
    {
      operationId: "synthetic.erp.order.get",
      audience: "c16-c0-erp",
      parameters: (index) => ({
        orderRef: `SYN-ORD-000${index + 1}`,
      }),
    },
    {
      operationId: "synthetic.bi.metric.get",
      audience: "c16-c0-bi",
      parameters: (index) => ({
        metricCode:
          index === 1
            ? "open_order_count"
            : "on_time_delivery_rate",
        period: index === 2 ? "2026-Q2" : "2026-Q1",
      }),
    },
  ];
  const { sdk, broker, lab } = createHarness();
  let callIndex = 0;

  for (const [tenantIndex, tenantId] of tenants.entries()) {
    for (const operation of operations) {
      callIndex += 1;
      const callId = `tcl_018f0000-0000-7000-8000-${String(
        200 + callIndex,
      ).padStart(12, "0")}`;
      const parameters = operation.parameters(tenantIndex);
      const capability = broker.issue({
        tenantId,
        operationId: operation.operationId,
        callId,
        audience: operation.audience,
      });
      const result = await sdk.execute(
        serverContext({ tenantId, callId }),
        requestEnvelope({
          operation_id: operation.operationId,
          trace_id: `trace-c17-full-path-${callIndex}`,
          request: {
            parameters,
            requested_as_of: null,
          },
        }),
        capability,
      );
      assert.equal(result.result.status, "OK");
      for (const [field, value] of Object.entries(parameters)) {
        assert.equal(result.result.data[field], value);
      }
    }
  }
  assert.equal(lab.snapshot().invocationCount, 9);
  assert.equal(broker.snapshot().revokedCapabilityCount, 9);
  assert.equal(broker.snapshot().activeCapabilityCount, 0);
});

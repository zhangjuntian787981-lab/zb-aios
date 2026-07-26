import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  C16CredentialBrokerError,
  createC16EphemeralCredentialBroker,
} from "../lib/c16-ephemeral-credential-broker.mjs";
import {
  C16SyntheticToolAdapterError,
  createC16SyntheticToolAdapter,
} from "../lib/c16-synthetic-tool-adapter.mjs";
import { toolGatewaySha256 } from "../lib/tool-gateway.mjs";

const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const CALL = "tcl_018f0000-0000-7000-8000-000000000101";
const NOW = "2026-07-26T12:00:00.000Z";

function ids() {
  let value = 200;
  return () => {
    value += 1;
    return `018f0000-0000-7000-8000-${String(value).padStart(12, "0")}`;
  };
}

function scope(overrides = {}) {
  return {
    tenantId: TENANT,
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    audience: "c16-c0-approval",
    ...overrides,
  };
}

const fixtures = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c16/synthetic-tool-fixtures.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function call(overrides = {}) {
  const value = {
    tenantId: TENANT,
    tenantKind: "SYNTHETIC",
    operationId: "synthetic.approval.status.get",
    callId: CALL,
    effectKey:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    adapterVersion: "c0-approval-v1",
    audience: "c16-c0-approval",
    normalizedParams: { approvalRef: "SYN-APR-0001" },
    ...overrides,
  };
  return value;
}

test("opaque capability expires, revokes, and cannot cross any scope field", () => {
  const mutable = { now: NOW };
  const broker = createC16EphemeralCredentialBroker({
    clock: () => mutable.now,
    idFactory: ids(),
    ttlSeconds: 15,
  });
  const capability = broker.issue(scope());
  assert.equal(broker.assertUsable(capability, scope()), true);
  for (const changed of [
    scope({
      tenantId:
        "stn_018f0000-0000-7000-8000-000000000011",
    }),
    scope({ operationId: "synthetic.erp.order.get" }),
    scope({
      callId: "tcl_018f0000-0000-7000-8000-000000000199",
    }),
    scope({ audience: "c16-c0-erp" }),
  ]) {
    assert.throws(
      () => broker.assertUsable(capability, changed),
      (error) =>
        error instanceof C16CredentialBrokerError &&
        error.code === "CREDENTIAL_SCOPE_MISMATCH",
    );
  }
  broker.revoke(capability);
  assert.throws(
    () => broker.assertUsable(capability, scope()),
    (error) =>
      error instanceof C16CredentialBrokerError &&
      error.code === "CREDENTIAL_REVOKED",
  );

  const expiring = broker.issue(scope());
  mutable.now = "2026-07-26T12:00:15.000Z";
  assert.throws(
    () => broker.assertUsable(expiring, scope()),
    (error) =>
      error instanceof C16CredentialBrokerError &&
      error.code === "CREDENTIAL_EXPIRED",
  );
});

test("C0 Adapter deduplicates effect keys and returns no capability material", async () => {
  const broker = createC16EphemeralCredentialBroker({
    clock: () => NOW,
    idFactory: ids(),
  });
  const adapter = createC16SyntheticToolAdapter({
    credentialBroker: broker,
    fixtureDocument: fixtures,
  });
  const capability = broker.issue(scope());
  const first = await adapter.execute(call(), capability);
  const replay = await adapter.execute(call(), capability);
  assert.deepEqual(replay.result, first.result);
  assert.equal(replay.receipt.replayed, true);
  const replayReceiptBase = structuredClone(replay.receipt);
  delete replayReceiptBase.receiptSha256;
  assert.equal(
    replay.receipt.receiptSha256,
    toolGatewaySha256(replayReceiptBase),
  );
  assert.equal(adapter.snapshot().newExecutionCount, 1);
  assert.equal(adapter.snapshot().networkRequestCount, 0);
  const output = JSON.stringify({
    first,
    replay,
    snapshot: adapter.snapshot(),
  });
  assert.equal(output.includes(capability.opaque), false);
  assert.equal(output.includes(capability.capabilityId), false);

  await assert.rejects(
    adapter.execute(
      call({
        normalizedParams: { approvalRef: "SYN-APR-9999" },
      }),
      capability,
    ),
    (error) =>
      error instanceof C16SyntheticToolAdapterError &&
      error.code === "EFFECT_KEY_CONFLICT",
  );
});

test("C0 Adapter accepts only the exact fixed nine-row fixture", () => {
  const credentialBroker = { assertUsable() {} };
  const mutations = [
    (document) => {
      document.records[0].result.status = "SYNTHETIC_APPROVED";
    },
    (document) => {
      document.records.push({
        tenantId:
          "stn_018f0000-0000-7000-8000-000000000013",
        operationId: "synthetic.approval.status.get",
        lookup: { approvalRef: "SYN-APR-0004" },
        result: {
          approvalRef: "SYN-APR-0004",
          status: "PENDING_SYNTHETIC_REVIEW",
        },
      });
    },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(fixtures);
    mutate(changed);
    assert.throws(
      () =>
        createC16SyntheticToolAdapter({
          credentialBroker,
          fixtureDocument: changed,
        }),
      (error) =>
        error instanceof C16SyntheticToolAdapterError &&
        error.code === "INVALID_CONFIGURATION",
    );
  }
});

test("C0 Adapter fails closed on rate limit and injected failure", async () => {
  const broker = createC16EphemeralCredentialBroker({
    clock: () => NOW,
    idFactory: ids(),
  });
  const firstCall = call();
  const secondCall = call({
    callId: "tcl_018f0000-0000-7000-8000-000000000102",
    operationId: "synthetic.erp.order.get",
    effectKey:
      "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    adapterVersion: "c0-erp-v1",
    audience: "c16-c0-erp",
    normalizedParams: { orderRef: "SYN-ORD-0001" },
  });
  const limited = createC16SyntheticToolAdapter({
    credentialBroker: broker,
    fixtureDocument: fixtures,
    maxNewEffectsPerTenant: 1,
  });
  await limited.execute(firstCall, broker.issue(scope()));
  await assert.rejects(
    limited.execute(
      secondCall,
      broker.issue(
        scope({
          operationId: secondCall.operationId,
          callId: secondCall.callId,
          audience: secondCall.audience,
        }),
      ),
    ),
    (error) =>
      error instanceof C16SyntheticToolAdapterError &&
      error.code === "RATE_LIMITED",
  );

  const failedEffectKey = toolGatewaySha256("c16-failed-effect");
  const failed = createC16SyntheticToolAdapter({
    credentialBroker: broker,
    fixtureDocument: fixtures,
    failedEffectKeys: new Set([failedEffectKey]),
  });
  const failedCall = call({ effectKey: failedEffectKey });
  await assert.rejects(
    failed.execute(failedCall, broker.issue(scope())),
    (error) =>
      error instanceof C16SyntheticToolAdapterError &&
      error.code === "ADAPTER_UNAVAILABLE",
  );
  assert.equal(failed.snapshot().newExecutionCount, 0);
});

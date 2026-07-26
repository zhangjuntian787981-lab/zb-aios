import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createOpenFgaPdp,
  createOpenFgaRuntimePdp,
} from "../lib/openfga-pdp.mjs";

const STORE_ID = "01J00000000000000000000000";
const MODEL_ID = "01J00000000000000000000001";
const MODEL = {
  schema_version: "1.1",
  type_definitions: [{ type: "user" }],
};
const TUPLE = {
  user: "user:alice",
  relation: "viewer",
  object: "document:quote-1",
};

function response(body, { ok = true } = {}) {
  return {
    ok,
    async json() {
      return body;
    },
  };
}

test("the OpenFGA distribution lock fixes v1.18.1 Darwin arm64", async () => {
  const lock = JSON.parse(
    await readFile(
      new URL(
        "../implementation/p1/c06/openfga/openfga-distribution.lock.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );

  assert.deepEqual(
    {
      version: lock.version,
      platform: lock.platform,
      architecture: lock.architecture,
      asset: lock.asset,
      sha256: lock.sha256,
    },
    {
      version: "v1.18.1",
      platform: "darwin",
      architecture: "arm64",
      asset: "openfga_1.18.1_darwin_arm64.tar.gz",
      sha256:
        "d667620fcf54d5343fae374c60e1ac0af98defd5e44d93ca9af52866a2881f94",
    },
  );
});

test("the runtime port exposes read and check capabilities but no mutation", () => {
  const pdp = createOpenFgaRuntimePdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
  });
  assert.deepEqual(Object.keys(pdp).sort(), [
    "check",
    "readAllTuples",
    "readAuthorizationModel",
  ]);
  assert.equal("writeTuples" in pdp, false);
  assert.equal("publishModel" in pdp, false);
  assert.equal("provisionStore" in pdp, false);
});

test("provisionStore binds one store and publishModel uses that fixed path", async () => {
  const calls = [];
  const pdp = createOpenFgaPdp({
    baseUrl: "http://127.0.0.1:8080/",
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      if (url.endsWith("/stores")) return response({ id: STORE_ID });
      return response({ authorization_model_id: MODEL_ID });
    },
  });

  assert.deepEqual(await pdp.provisionStore({ name: "c06-synthetic" }), {
    storeId: STORE_ID,
  });
  assert.deepEqual(await pdp.publishModel(MODEL), {
    storeId: STORE_ID,
    authorizationModelId: MODEL_ID,
  });
  assert.equal(calls[0].url, "http://127.0.0.1:8080/stores");
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    name: "c06-synthetic",
  });
  assert.equal(
    calls[1].url,
    `http://127.0.0.1:8080/stores/${STORE_ID}/authorization-models`,
  );
  assert.deepEqual(JSON.parse(calls[1].init.body), MODEL);
  await assert.rejects(
    pdp.provisionStore({ name: "second-store" }),
    { code: "OPENFGA_STORE_ALREADY_BOUND" },
  );
});

test("check fixes store, model and higher consistency while preserving Deny", async () => {
  let captured;
  const pdp = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return response({ allowed: false });
    },
  });
  const contextualTuple = {
    user: "agent:worker",
    relation: "runner",
    object: "document:quote-1",
  };

  assert.deepEqual(
    await pdp.check({
      authorizationModelId: MODEL_ID,
      tupleKey: TUPLE,
      trustedContextualTuples: [contextualTuple],
    }),
    {
      allowed: false,
      storeId: STORE_ID,
      authorizationModelId: MODEL_ID,
      consistency: "HIGHER_CONSISTENCY",
    },
  );
  assert.equal(
    captured.url,
    `http://openfga.internal/stores/${STORE_ID}/check`,
  );
  assert.deepEqual(JSON.parse(captured.init.body), {
    authorization_model_id: MODEL_ID,
    tuple_key: TUPLE,
    contextual_tuples: {
      tuple_keys: [contextualTuple],
    },
    consistency: "HIGHER_CONSISTENCY",
  });
});

test("writeTuples fixes store and model and writes one bounded tuple set", async () => {
  let captured;
  const pdp = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return response({});
    },
  });

  assert.deepEqual(
    await pdp.writeTuples({
      authorizationModelId: MODEL_ID,
      tupleKeys: [TUPLE],
    }),
    {
      storeId: STORE_ID,
      authorizationModelId: MODEL_ID,
      writtenTupleCount: 1,
    },
  );
  assert.equal(
    captured.url,
    `http://openfga.internal/stores/${STORE_ID}/write`,
  );
  assert.deepEqual(JSON.parse(captured.init.body), {
    authorization_model_id: MODEL_ID,
    writes: {
      tuple_keys: [TUPLE],
    },
  });
});

test("read-back returns the fixed model and every stored tuple with higher consistency", async () => {
  const calls = [];
  const pdp = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      if (init.method === "GET") {
        return response({
          authorization_model: {
            id: MODEL_ID,
            schema_version: "1.1",
            type_definitions: [
              {
                type: "user",
                relations: {},
                metadata: null,
              },
            ],
            conditions: {},
          },
        });
      }
      const body = JSON.parse(init.body);
      if (!body.continuation_token) {
        return response({
          tuples: [{ key: TUPLE, timestamp: "2026-07-26T00:00:00Z" }],
          continuation_token: "next-page",
        });
      }
      return response({
        tuples: [
          {
            key: {
              user: "user:bob",
              relation: "viewer",
              object: "document:quote-2",
            },
            timestamp: "2026-07-26T00:00:01Z",
          },
        ],
        continuation_token: "",
      });
    },
  });

  assert.deepEqual(
    await pdp.readAuthorizationModel({ authorizationModelId: MODEL_ID }),
    {
      storeId: STORE_ID,
      authorizationModelId: MODEL_ID,
      model: MODEL,
    },
  );
  assert.deepEqual(
    await pdp.readAllTuples({ authorizationModelId: MODEL_ID }),
    {
      storeId: STORE_ID,
      authorizationModelId: MODEL_ID,
      consistency: "HIGHER_CONSISTENCY",
      tupleKeys: [
        TUPLE,
        {
          user: "user:bob",
          relation: "viewer",
          object: "document:quote-2",
        },
      ],
    },
  );
  assert.equal(calls[0].init.method, "GET");
  assert.equal("body" in calls[0].init, false);
  assert.deepEqual(JSON.parse(calls[1].init.body), {
    page_size: 100,
    consistency: "HIGHER_CONSISTENCY",
  });
  assert.deepEqual(JSON.parse(calls[2].init.body), {
    page_size: 100,
    consistency: "HIGHER_CONSISTENCY",
    continuation_token: "next-page",
  });
});

test("read-back rejects mismatched models and malformed pagination", async () => {
  const mismatched = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    fetchImpl: async () =>
      response({
        authorization_model: {
          id: "01J00000000000000000000009",
          ...MODEL,
        },
      }),
  });
  await assert.rejects(
    mismatched.readAuthorizationModel({ authorizationModelId: MODEL_ID }),
    { code: "OPENFGA_INVALID_RESPONSE" },
  );
  for (const conditions of [null, [], "invalid"]) {
    const malformedConditions = createOpenFgaPdp({
      baseUrl: "http://openfga.internal",
      storeId: STORE_ID,
      fetchImpl: async () =>
        response({
          authorization_model: {
            id: MODEL_ID,
            ...MODEL,
            conditions,
          },
        }),
    });
    await assert.rejects(
      malformedConditions.readAuthorizationModel({
        authorizationModelId: MODEL_ID,
      }),
      { code: "OPENFGA_INVALID_RESPONSE" },
    );
  }

  const repeatedPage = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    fetchImpl: async () =>
      response({
        tuples: [],
        continuation_token: "same-page",
      }),
  });
  await assert.rejects(
    repeatedPage.readAllTuples({ authorizationModelId: MODEL_ID }),
    { code: "OPENFGA_INVALID_RESPONSE" },
  );

  let page = 0;
  const excessivePagination = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    fetchImpl: async () => {
      page += 1;
      return response({
        tuples: [
          {
            key: {
              ...TUPLE,
              object: `document:quote-${page}`,
            },
          },
        ],
        continuation_token: `page-${page}`,
      });
    },
  });
  await assert.rejects(
    excessivePagination.readAllTuples({
      authorizationModelId: MODEL_ID,
    }),
    { code: "OPENFGA_INVALID_RESPONSE" },
  );
  assert.equal(page, 10);

  for (const tuples of [
    [
      {
        key: {
          ...TUPLE,
          condition: { name: "unapproved", context: {} },
        },
      },
    ],
    Array.from({ length: 101 }, () => ({ key: TUPLE })),
  ]) {
    const invalidTuples = createOpenFgaPdp({
      baseUrl: "http://openfga.internal",
      storeId: STORE_ID,
      fetchImpl: async () =>
        response({
          tuples,
          continuation_token: "",
        }),
    });
    await assert.rejects(
      invalidTuples.readAllTuples({ authorizationModelId: MODEL_ID }),
      { code: "OPENFGA_INVALID_RESPONSE" },
    );
  }
});

test("writeTuples rejects empty, oversized and caller-overridden writes", async () => {
  let calls = 0;
  const pdp = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    fetchImpl: async () => {
      calls += 1;
      return response({});
    },
  });

  for (const input of [
    {
      authorizationModelId: MODEL_ID,
      tupleKeys: [],
    },
    {
      authorizationModelId: MODEL_ID,
      tupleKeys: Array.from({ length: 101 }, () => TUPLE),
    },
    {
      authorizationModelId: MODEL_ID,
      tupleKeys: [TUPLE],
      storeId: "other-store",
    },
    {
      authorizationModelId: MODEL_ID,
      tupleKeys: [TUPLE],
      modelId: "other-model",
    },
    {
      authorizationModelId: MODEL_ID,
      writes: { tuple_keys: [TUPLE] },
    },
  ]) {
    await assert.rejects(pdp.writeTuples(input), {
      code: "OPENFGA_INVALID_INPUT",
    });
  }
  assert.equal(calls, 0);
});

test("a check without trusted contextual tuples omits them from the request", async () => {
  let body;
  const pdp = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    fetchImpl: async (url, init) => {
      body = JSON.parse(init.body);
      return response({ allowed: true });
    },
  });

  await pdp.check({
    authorizationModelId: MODEL_ID,
    tupleKey: TUPLE,
  });
  assert.equal("contextual_tuples" in body, false);
});

test("check rejects caller store overrides and untrusted contextual tuple fields", async () => {
  let calls = 0;
  const pdp = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    fetchImpl: async () => {
      calls += 1;
      return response({ allowed: true });
    },
  });

  await assert.rejects(
    pdp.check({
      authorizationModelId: MODEL_ID,
      tupleKey: TUPLE,
      storeId: "other-store",
    }),
    { code: "OPENFGA_INVALID_INPUT" },
  );
  await assert.rejects(
    pdp.check({
      authorizationModelId: MODEL_ID,
      tupleKey: TUPLE,
      contextualTuples: [],
    }),
    { code: "OPENFGA_INVALID_INPUT" },
  );
  assert.equal(calls, 0);
});

test("timeout and transport failures expose only stable non-secret errors", async () => {
  const timeoutPdp = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    timeoutMs: 5,
    fetchImpl: async () => new Promise(() => {}),
  });
  await assert.rejects(
    timeoutPdp.check({
      authorizationModelId: MODEL_ID,
      tupleKey: TUPLE,
    }),
    { code: "OPENFGA_TIMEOUT", message: "OPENFGA_TIMEOUT" },
  );

  const unavailablePdp = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    fetchImpl: async () => {
      throw new Error("secret-host-token");
    },
  });
  await assert.rejects(
    unavailablePdp.check({
      authorizationModelId: MODEL_ID,
      tupleKey: TUPLE,
    }),
    (error) => {
      assert.equal(error.code, "OPENFGA_UNAVAILABLE");
      assert.equal(error.message.includes("secret-host-token"), false);
      return true;
    },
  );
});

test("a response body that never completes is also bounded by the timeout", async () => {
  const pdp = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    timeoutMs: 5,
    fetchImpl: async () => ({
      ok: true,
      async json() {
        return new Promise(() => {});
      },
    }),
  });

  await assert.rejects(
    pdp.check({
      authorizationModelId: MODEL_ID,
      tupleKey: TUPLE,
    }),
    { code: "OPENFGA_TIMEOUT" },
  );
});

test("HTTP rejection and malformed response bodies are stable and non-secret", async () => {
  const rejectedPdp = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    fetchImpl: async () => response({ secret: "do-not-leak" }, { ok: false }),
  });
  await assert.rejects(
    rejectedPdp.check({
      authorizationModelId: MODEL_ID,
      tupleKey: TUPLE,
    }),
    (error) => {
      assert.equal(error.code, "OPENFGA_REQUEST_REJECTED");
      assert.equal(error.message.includes("do-not-leak"), false);
      return true;
    },
  );

  const malformedPdp = createOpenFgaPdp({
    baseUrl: "http://openfga.internal",
    storeId: STORE_ID,
    fetchImpl: async () => response({ allowed: "yes" }),
  });
  await assert.rejects(
    malformedPdp.check({
      authorizationModelId: MODEL_ID,
      tupleKey: TUPLE,
    }),
    { code: "OPENFGA_INVALID_RESPONSE" },
  );
});

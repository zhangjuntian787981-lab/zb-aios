const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_TIMEOUT_MS = 60_000;
const HIGHER_CONSISTENCY = "HIGHER_CONSISTENCY";
const SAFE_IDENTIFIER = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_READ_PAGES = 10;

function fail(code) {
  const error = new Error(code);
  error.name = "OpenFgaPdpError";
  error.code = code;
  throw error;
}

function exactObject(value, allowedKeys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("OPENFGA_INVALID_INPUT");
  }
  if (Object.keys(value).some((key) => !allowedKeys.includes(key))) {
    fail("OPENFGA_INVALID_INPUT");
  }
}

function safeIdentifier(value) {
  return typeof value === "string" && SAFE_IDENTIFIER.test(value);
}

function nonEmptyString(value, maxLength = 512) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maxLength
  );
}

function normalizeBaseUrl(value) {
  if (typeof value !== "string") fail("OPENFGA_CONFIGURATION_INVALID");

  let url;
  try {
    url = new URL(value);
  } catch {
    fail("OPENFGA_CONFIGURATION_INVALID");
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    fail("OPENFGA_CONFIGURATION_INVALID");
  }
  return url.toString().replace(/\/+$/, "");
}

function validateTupleKey(value) {
  exactObject(value, ["user", "relation", "object"]);
  if (
    !nonEmptyString(value.user) ||
    !nonEmptyString(value.relation, 128) ||
    !nonEmptyString(value.object)
  ) {
    fail("OPENFGA_INVALID_INPUT");
  }
  return {
    user: value.user,
    relation: value.relation,
    object: value.object,
  };
}

function validateStoredTupleKey(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("OPENFGA_INVALID_RESPONSE");
  }
  if (
    Object.keys(value).some(
      (key) => !["user", "relation", "object", "condition"].includes(key),
    ) ||
    (value.condition !== undefined && value.condition !== null) ||
    !nonEmptyString(value.user) ||
    !nonEmptyString(value.relation, 128) ||
    !nonEmptyString(value.object)
  ) {
    fail("OPENFGA_INVALID_RESPONSE");
  }
  return {
    user: value.user,
    relation: value.relation,
    object: value.object,
  };
}

function validateTrustedContextualTuples(value) {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 100) {
    fail("OPENFGA_INVALID_INPUT");
  }
  return value.map(validateTupleKey);
}

function validateWriteTuples(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) {
    fail("OPENFGA_INVALID_INPUT");
  }
  return value.map(validateTupleKey);
}

function validateModel(value) {
  exactObject(value, ["schema_version", "type_definitions", "conditions"]);
  if (
    value.schema_version !== "1.1" ||
    !Array.isArray(value.type_definitions) ||
    value.type_definitions.length === 0
  ) {
    fail("OPENFGA_INVALID_INPUT");
  }
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    fail("OPENFGA_INVALID_INPUT");
  }
}

function normalizeReadModelDefaults(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !Array.isArray(value.type_definitions)
  ) {
    fail("OPENFGA_INVALID_RESPONSE");
  }
  const result = JSON.parse(JSON.stringify(value));
  for (const definition of result.type_definitions) {
    if (
      !definition ||
      typeof definition !== "object" ||
      Array.isArray(definition)
    ) {
      fail("OPENFGA_INVALID_RESPONSE");
    }
    if (
      definition.relations &&
      typeof definition.relations === "object" &&
      !Array.isArray(definition.relations) &&
      Object.keys(definition.relations).length === 0
    ) {
      delete definition.relations;
    }
    if (definition.metadata === null) {
      delete definition.metadata;
      continue;
    }
    const metadata = definition.metadata;
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
      continue;
    }
    if (metadata.module === "") delete metadata.module;
    if (metadata.source_info === null) delete metadata.source_info;
    if (
      !metadata.relations ||
      typeof metadata.relations !== "object" ||
      Array.isArray(metadata.relations)
    ) {
      continue;
    }
    for (const relationMetadata of Object.values(metadata.relations)) {
      if (
        !relationMetadata ||
        typeof relationMetadata !== "object" ||
        Array.isArray(relationMetadata)
      ) {
        continue;
      }
      if (relationMetadata.module === "") delete relationMetadata.module;
      if (relationMetadata.source_info === null) {
        delete relationMetadata.source_info;
      }
      if (!Array.isArray(relationMetadata.directly_related_user_types)) {
        continue;
      }
      for (const reference of relationMetadata.directly_related_user_types) {
        if (
          reference &&
          typeof reference === "object" &&
          !Array.isArray(reference) &&
          reference.condition === ""
        ) {
          delete reference.condition;
        }
      }
    }
  }
  return result;
}

export function createOpenFgaPdp(options) {
  exactObject(options, ["baseUrl", "storeId", "fetchImpl", "timeoutMs"]);
  const baseUrl = normalizeBaseUrl(options.baseUrl);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (
    typeof fetchImpl !== "function" ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > MAX_TIMEOUT_MS ||
    (options.storeId !== undefined && !safeIdentifier(options.storeId))
  ) {
    fail("OPENFGA_CONFIGURATION_INVALID");
  }

  let boundStoreId = options.storeId;
  let provisioning = false;

  async function request(path, body, method = "POST") {
    const controller = new AbortController();
    let timedOut = false;
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
        const error = new Error("OPENFGA_TIMEOUT");
        error.name = "OpenFgaPdpError";
        error.code = "OPENFGA_TIMEOUT";
        reject(error);
      }, timeoutMs);
    });

    try {
      return await Promise.race([
        Promise.resolve().then(async () => {
          const init = {
            method,
            headers: {
              accept: "application/json",
              "content-type": "application/json",
            },
            signal: controller.signal,
          };
          if (body !== undefined) init.body = JSON.stringify(body);
          const response = await fetchImpl(`${baseUrl}${path}`, init);
          if (
            !response ||
            typeof response.ok !== "boolean" ||
            typeof response.json !== "function"
          ) {
            fail("OPENFGA_INVALID_RESPONSE");
          }
          if (!response.ok) fail("OPENFGA_REQUEST_REJECTED");

          try {
            return await response.json();
          } catch {
            fail("OPENFGA_INVALID_RESPONSE");
          }
        }),
        timeout,
      ]);
    } catch (error) {
      if (timedOut || error?.code === "OPENFGA_TIMEOUT") {
        fail("OPENFGA_TIMEOUT");
      }
      if (
        error?.name === "OpenFgaPdpError" &&
        typeof error.code === "string"
      ) {
        throw error;
      }
      fail("OPENFGA_UNAVAILABLE");
    } finally {
      clearTimeout(timer);
    }
  }

  function requireStore() {
    if (!boundStoreId) fail("OPENFGA_STORE_NOT_BOUND");
    return boundStoreId;
  }

  return Object.freeze({
    async provisionStore(input) {
      exactObject(input, ["name"]);
      if (boundStoreId || provisioning) {
        fail("OPENFGA_STORE_ALREADY_BOUND");
      }
      if (!nonEmptyString(input.name, 64)) fail("OPENFGA_INVALID_INPUT");

      provisioning = true;
      try {
        const response = await request("/stores", { name: input.name });
        if (!response || !safeIdentifier(response.id)) {
          fail("OPENFGA_INVALID_RESPONSE");
        }
        boundStoreId = response.id;
        return Object.freeze({ storeId: boundStoreId });
      } finally {
        provisioning = false;
      }
    },

    async publishModel(model) {
      const storeId = requireStore();
      const response = await request(
        `/stores/${encodeURIComponent(storeId)}/authorization-models`,
        validateModel(model),
      );
      if (
        !response ||
        !safeIdentifier(response.authorization_model_id)
      ) {
        fail("OPENFGA_INVALID_RESPONSE");
      }
      return Object.freeze({
        storeId,
        authorizationModelId: response.authorization_model_id,
      });
    },

    async writeTuples(input) {
      exactObject(input, ["authorizationModelId", "tupleKeys"]);
      const storeId = requireStore();
      if (!safeIdentifier(input.authorizationModelId)) {
        fail("OPENFGA_INVALID_INPUT");
      }
      const tupleKeys = validateWriteTuples(input.tupleKeys);
      await request(`/stores/${encodeURIComponent(storeId)}/write`, {
        authorization_model_id: input.authorizationModelId,
        writes: {
          tuple_keys: tupleKeys,
        },
      });
      return Object.freeze({
        storeId,
        authorizationModelId: input.authorizationModelId,
        writtenTupleCount: tupleKeys.length,
      });
    },

    async readAuthorizationModel(input) {
      exactObject(input, ["authorizationModelId"]);
      const storeId = requireStore();
      if (!safeIdentifier(input.authorizationModelId)) {
        fail("OPENFGA_INVALID_INPUT");
      }
      const response = await request(
        `/stores/${encodeURIComponent(storeId)}/authorization-models/${encodeURIComponent(input.authorizationModelId)}`,
        undefined,
        "GET",
      );
      const value = response?.authorization_model;
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        fail("OPENFGA_INVALID_RESPONSE");
      }
      exactObject(value, [
        "id",
        "schema_version",
        "type_definitions",
        "conditions",
      ]);
      if (value.id !== input.authorizationModelId) {
        fail("OPENFGA_INVALID_RESPONSE");
      }
      const model = {
        schema_version: value.schema_version,
        type_definitions: value.type_definitions,
      };
      if (value.conditions !== undefined) {
        if (
          !value.conditions ||
          typeof value.conditions !== "object" ||
          Array.isArray(value.conditions)
        ) {
          fail("OPENFGA_INVALID_RESPONSE");
        }
        if (Object.keys(value.conditions).length > 0) {
          model.conditions = value.conditions;
        }
      }
      return Object.freeze({
        storeId,
        authorizationModelId: input.authorizationModelId,
        model: validateModel(normalizeReadModelDefaults(model)),
      });
    },

    async readAllTuples(input) {
      exactObject(input, ["authorizationModelId"]);
      const storeId = requireStore();
      if (!safeIdentifier(input.authorizationModelId)) {
        fail("OPENFGA_INVALID_INPUT");
      }
      const tupleKeys = [];
      const seenTokens = new Set();
      let continuationToken = "";
      let pageCount = 0;
      do {
        pageCount += 1;
        if (pageCount > MAX_READ_PAGES) fail("OPENFGA_INVALID_RESPONSE");
        const body = {
          page_size: 100,
          consistency: HIGHER_CONSISTENCY,
        };
        if (continuationToken) {
          body.continuation_token = continuationToken;
        }
        const response = await request(
          `/stores/${encodeURIComponent(storeId)}/read`,
          body,
        );
        if (
          !Array.isArray(response?.tuples) ||
          typeof response.continuation_token !== "string" ||
          response.continuation_token.length > 4_096
        ) {
          fail("OPENFGA_INVALID_RESPONSE");
        }
        for (const tuple of response.tuples) {
          if (
            !tuple ||
            typeof tuple !== "object" ||
            Array.isArray(tuple) ||
            !tuple.key
          ) {
            fail("OPENFGA_INVALID_RESPONSE");
          }
          tupleKeys.push(validateStoredTupleKey(tuple.key));
          if (tupleKeys.length > 100) fail("OPENFGA_INVALID_RESPONSE");
        }
        continuationToken = response.continuation_token;
        if (continuationToken && response.tuples.length === 0) {
          fail("OPENFGA_INVALID_RESPONSE");
        }
        if (continuationToken) {
          if (seenTokens.has(continuationToken)) {
            fail("OPENFGA_INVALID_RESPONSE");
          }
          seenTokens.add(continuationToken);
        }
      } while (continuationToken);

      return Object.freeze({
        storeId,
        authorizationModelId: input.authorizationModelId,
        consistency: HIGHER_CONSISTENCY,
        tupleKeys: Object.freeze(tupleKeys),
      });
    },

    async check(input) {
      exactObject(input, [
        "authorizationModelId",
        "tupleKey",
        "trustedContextualTuples",
      ]);
      const storeId = requireStore();
      if (!safeIdentifier(input.authorizationModelId)) {
        fail("OPENFGA_INVALID_INPUT");
      }
      const tupleKey = validateTupleKey(input.tupleKey);
      const contextualTupleKeys = validateTrustedContextualTuples(
        input.trustedContextualTuples,
      );
      const requestBody = {
        authorization_model_id: input.authorizationModelId,
        tuple_key: tupleKey,
        consistency: HIGHER_CONSISTENCY,
      };
      if (contextualTupleKeys !== undefined) {
        requestBody.contextual_tuples = {
          tuple_keys: contextualTupleKeys,
        };
      }
      const response = await request(
        `/stores/${encodeURIComponent(storeId)}/check`,
        requestBody,
      );
      if (!response || typeof response.allowed !== "boolean") {
        fail("OPENFGA_INVALID_RESPONSE");
      }
      return Object.freeze({
        allowed: response.allowed,
        storeId,
        authorizationModelId: input.authorizationModelId,
        consistency: HIGHER_CONSISTENCY,
      });
    },
  });
}

export function createOpenFgaRuntimePdp(options) {
  const pdp = createOpenFgaPdp(options);
  return Object.freeze({
    readAuthorizationModel: pdp.readAuthorizationModel,
    readAllTuples: pdp.readAllTuples,
    check: pdp.check,
  });
}

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const contract =
  "implementation/p0/f03/contracts/core.openapi.v1.json";
const schema =
  "implementation/p0/f03/schemas/canonical-task-envelope.v1.schema.json";
const sample =
  "implementation/p0/f03/samples/task-envelope.valid.json";
const networkDenied =
  process.env.INDEPENDENT_REVIEW_NETWORK_MODE ===
  "DENY_ALL_OFFLINE_ALTERNATIVES";

async function validateFrozenContractOffline() {
  const [contractDocument, requestSchema, requestSample] = await Promise.all(
    [contract, schema, sample].map(async (path) =>
      JSON.parse(await readFile(new URL(`../${path}`, import.meta.url), "utf8")),
    ),
  );
  const operation = contractDocument.paths?.["/v1/tasks"]?.post;
  const responseSchema =
    contractDocument.components?.schemas?.MockContractResponse;
  const response = Object.fromEntries(
    Object.entries(responseSchema?.properties ?? {}).map(
      ([field, definition]) => [field, definition.const],
    ),
  );
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    validateFormats: true,
  });
  addFormats(ajv);
  assert.equal(operation?.operationId, "createTask");
  assert.equal(ajv.compile(requestSchema)(requestSample), true);
  assert.equal(ajv.compile(responseSchema)(response), true);
  assert.deepEqual(response, {
    authorization_status: "NOT_EVALUATED",
    connection_status: "MOCK_ONLY",
    synthetic: true,
  });
}

function firstLine(stream, child) {
  return new Promise((resolve, reject) => {
    let pending = "";
    const timer = setTimeout(
      () => reject(new Error("F03 Provider readiness timed out.")),
      2_000,
    );
    const finish = (callback, value) => {
      clearTimeout(timer);
      stream.off("data", onData);
      child.off("exit", onExit);
      callback(value);
    };
    const onData = (chunk) => {
      pending += chunk.toString("utf8");
      const newline = pending.indexOf("\n");
      if (newline === -1) return;
      finish(resolve, pending.slice(0, newline));
    };
    const onExit = (code) =>
      finish(
        reject,
        new Error(`F03 Provider exited before readiness: ${code}`),
      );
    stream.on("data", onData);
    child.on("exit", onExit);
    stream.once("error", reject);
  });
}

test("independent F03 Consumer and Provider interoperate only through frozen contracts", async () => {
  if (networkDenied) {
    await validateFrozenContractOffline();
    return;
  }
  const provider = spawn(
    process.execPath,
    [
      "scripts/f03-synthetic-contract-provider.mjs",
      contract,
      schema,
    ],
    {
      cwd: repositoryRoot,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let stderr = "";
  provider.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });

  try {
    const ready = JSON.parse(await firstLine(provider.stdout, provider));
    assert.equal(ready.status, "READY");
    assert.equal(ready.host, "127.0.0.1");
    assert.equal(Number.isSafeInteger(ready.port), true);

    const consumer = spawnSync(
      process.execPath,
      [
        "scripts/f03-synthetic-contract-consumer.mjs",
        `http://127.0.0.1:${ready.port}`,
        contract,
        schema,
        sample,
      ],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
        timeout: 5_000,
      },
    );
    assert.equal(consumer.status, 0, consumer.stderr);
    assert.deepEqual(JSON.parse(consumer.stdout), {
      status: "PASS",
      method: "POST",
      path: "/v1/tasks",
      responseStatus: 202,
      authorizationStatus: "NOT_EVALUATED",
      connectionStatus: "MOCK_ONLY",
      synthetic: true,
    });

    const exitCode = await new Promise((resolve, reject) => {
      provider.once("exit", resolve);
      provider.once("error", reject);
    });
    assert.equal(exitCode, 0, stderr);
  } finally {
    if (provider.exitCode === null) provider.kill("SIGTERM");
  }
});

test("F03 Consumer and Provider do not import Product Core implementations", async () => {
  for (const path of [
    "../scripts/f03-synthetic-contract-provider.mjs",
    "../scripts/f03-synthetic-contract-consumer.mjs",
  ]) {
    const source = await import("node:fs/promises").then(({ readFile }) =>
      readFile(new URL(path, import.meta.url), "utf8"),
    );
    assert.equal(source.includes("../lib/"), false, path);
    assert.equal(source.includes("f03-contract-lab"), false, path);
  }
});

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readFile } from "node:fs/promises";
import path from "node:path";

async function jsonFile(filePath) {
  return JSON.parse(await readFile(path.resolve(filePath), "utf8"));
}

function frozenOperation(contract) {
  for (const [route, pathItem] of Object.entries(contract.paths ?? {})) {
    for (const [method, operation] of Object.entries(pathItem ?? {})) {
      if (operation?.operationId === "createTask") {
        return { route, method: method.toUpperCase(), operation };
      }
    }
  }
  throw new Error("F03 Consumer contract operation is missing.");
}

async function main() {
  if (process.argv.length !== 6) {
    throw new Error(
      "F03 Consumer requires endpoint, contract, Schema, and sample paths.",
    );
  }
  const endpoint = new URL(process.argv[2]);
  if (
    endpoint.protocol !== "http:" ||
    endpoint.hostname !== "127.0.0.1" ||
    endpoint.username ||
    endpoint.password
  ) {
    throw new Error("F03 Consumer accepts only the local Synthetic Provider.");
  }
  const [contract, requestSchema, sample] = await Promise.all([
    jsonFile(process.argv[3]),
    jsonFile(process.argv[4]),
    jsonFile(process.argv[5]),
  ]);
  const { route, method, operation } = frozenOperation(contract);
  const expectedStatus = Number(
    Object.keys(operation.responses ?? {}).find((code) =>
      /^\d{3}$/.test(code),
    ),
  );
  const responseSchema =
    contract.components?.schemas?.MockContractResponse;
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    validateFormats: true,
  });
  addFormats(ajv);
  if (!ajv.compile(requestSchema)(sample)) {
    throw new Error("F03 Consumer sample does not match the request Schema.");
  }
  const validateResponse = ajv.compile(responseSchema);
  const response = await fetch(new URL(route, endpoint), {
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(sample),
    signal: AbortSignal.timeout(3_000),
  });
  const body = await response.json();
  if (response.status !== expectedStatus || !validateResponse(body)) {
    throw new Error("F03 Consumer response does not match the contract.");
  }
  process.stdout.write(
    `${JSON.stringify({
      status: "PASS",
      method,
      path: route,
      responseStatus: response.status,
      authorizationStatus: body.authorization_status,
      connectionStatus: body.connection_status,
      synthetic: body.synthetic,
    })}\n`,
  );
}

try {
  await main();
} catch {
  process.stderr.write("F03 synthetic Consumer failed.\n");
  process.exitCode = 1;
}

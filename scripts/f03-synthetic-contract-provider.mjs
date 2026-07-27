import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";

const MAX_REQUEST_BYTES = 1024 * 1024;

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
  throw new Error("F03 Provider contract operation is missing.");
}

function responseFromSchema(schema) {
  const response = {};
  for (const [field, definition] of Object.entries(
    schema?.properties ?? {},
  )) {
    if (!Object.hasOwn(definition, "const")) {
      throw new Error("F03 Provider response Schema is not fixed.");
    }
    response[field] = definition.const;
  }
  return response;
}

async function requestBody(request) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAX_REQUEST_BYTES) {
      throw new Error("F03 Provider request is too large.");
    }
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function main() {
  if (process.argv.length !== 4) {
    throw new Error("F03 Provider requires contract and Schema paths.");
  }
  const [contract, requestSchema] = await Promise.all([
    jsonFile(process.argv[2]),
    jsonFile(process.argv[3]),
  ]);
  const { route, method, operation } = frozenOperation(contract);
  const responseSchema =
    contract.components?.schemas?.MockContractResponse;
  const responseStatus = Number(
    Object.keys(operation.responses ?? {}).find((code) =>
      /^\d{3}$/.test(code),
    ),
  );
  if (
    contract["x-module"] !== "core" ||
    method !== "POST" ||
    !Number.isSafeInteger(responseStatus) ||
    !responseSchema
  ) {
    throw new Error("F03 Provider contract is invalid.");
  }

  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    validateFormats: true,
  });
  addFormats(ajv);
  const validateRequest = ajv.compile(requestSchema);
  const validateResponse = ajv.compile(responseSchema);
  const responseBody = responseFromSchema(responseSchema);
  if (!validateResponse(responseBody)) {
    throw new Error("F03 Provider response does not match the contract.");
  }

  const server = createServer(async (request, response) => {
    try {
      if (request.method !== method || request.url !== route) {
        response.writeHead(404).end();
        return;
      }
      const body = await requestBody(request);
      if (!validateRequest(body)) {
        response
          .writeHead(400, { "content-type": "application/json" })
          .end(JSON.stringify({ status: "INVALID_SYNTHETIC_REQUEST" }));
        return;
      }
      response
        .writeHead(responseStatus, {
          "content-type": "application/json",
        })
        .end(JSON.stringify(responseBody), () => server.close());
    } catch {
      response.writeHead(400).end();
      server.close();
    }
  });
  const timeout = setTimeout(() => {
    process.exitCode = 2;
    server.close();
  }, 5_000);
  server.once("close", () => clearTimeout(timeout));
  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    process.stdout.write(
      `${JSON.stringify({
        status: "READY",
        host: "127.0.0.1",
        port: address.port,
      })}\n`,
    );
  });
}

try {
  await main();
} catch {
  process.stderr.write("F03 synthetic Provider failed.\n");
  process.exitCode = 1;
}

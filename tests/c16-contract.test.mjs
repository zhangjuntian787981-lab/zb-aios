import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
  ToolGatewayError,
  createSyntheticToolCatalog,
} from "../lib/tool-gateway.mjs";

const ROOT = new URL(
  "../implementation/p1/c16/",
  import.meta.url,
);

async function json(name) {
  return JSON.parse(await readFile(new URL(name, ROOT), "utf8"));
}

test("C16 catalog, OpenAPI, and MCP projection share one closed operation set", async () => {
  const catalogDocument = await json("operation-catalog.v1.json");
  const openapi = await json("tool-gateway.openapi.v1.json");
  const mcp = await json("tool-gateway.mcp-projection.v1.json");
  const catalog = createSyntheticToolCatalog(catalogDocument);
  const expected = [
    "synthetic.approval.status.get",
    "synthetic.bi.metric.get",
    "synthetic.erp.order.get",
  ];
  assert.deepEqual(
    catalogDocument.operations
      .map(({ operationId }) => operationId)
      .sort(),
    expected,
  );
  assert.deepEqual(
    mcp.tools.map(({ operationId }) => operationId).sort(),
    expected,
  );
  assert.equal(mcp.authorizationSemantics, "ADVISORY_ONLY");
  assert.equal(mcp.runtimeAuthoritySource, "C05_C06_PER_STAGE");
  for (const operationId of expected) {
    const operation = catalog.operation(operationId);
    const projected = mcp.tools.find(
      (tool) => tool.operationId === operationId,
    );
    assert.deepEqual(projected.inputSchema, operation.parameterSchema);
    assert.equal(projected.inputSchema.additionalProperties, false);
  }
  assert.deepEqual(
    Object.values(openapi.paths)
      .flatMap((value) => Object.values(value))
      .map(({ operationId }) => operationId)
      .sort(),
    [
      "confirmToolParameters",
      "discoverTool",
      "executeConfirmedTool",
    ],
  );
  for (const schema of Object.values(openapi.components.schemas)) {
    if (schema.type === "object") {
      assert.equal(schema.additionalProperties, false);
    }
  }
  for (const name of ["Discovery", "Confirmation", "ToolResult"]) {
    const schema = openapi.components.schemas[name];
    assert.ok(schema.required.length > 0);
    assert.deepEqual(
      Object.keys(schema.properties).sort(),
      [...schema.required].sort(),
    );
  }
});

test("C16 fixtures cover three Synthetic Tenants and all three C0 tool classes", async () => {
  const fixtures = await json("synthetic-tool-fixtures.v1.json");
  const tenants = new Set(fixtures.records.map(({ tenantId }) => tenantId));
  const operations = new Set(
    fixtures.records.map(({ operationId }) => operationId),
  );
  assert.equal(fixtures.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(fixtures.networkAccess, "DISABLED");
  assert.equal(tenants.size, 3);
  assert.equal(operations.size, 3);
  for (const tenantId of tenants) {
    assert.equal(
      new Set(
        fixtures.records
          .filter((record) => record.tenantId === tenantId)
          .map(({ operationId }) => operationId),
      ).size,
      3,
    );
  }
});

test("C16 catalog rejects structurally valid local substitutions", async () => {
  const original = await json("operation-catalog.v1.json");
  const mutations = [
    (document) => {
      document.catalogVersion = "c16-substituted-tools-v1";
    },
    (document) => {
      const operation = document.operations.find(
        ({ operationId }) =>
          operationId === "synthetic.erp.order.get",
      );
      operation.adapterVersion = "c0-substituted-v1";
    },
    (document) => {
      const operation = document.operations.find(
        ({ operationId }) =>
          operationId === "synthetic.erp.order.get",
      );
      operation.audience = "c16-substituted";
    },
    (document) => {
      const operation = document.operations.find(
        ({ operationId }) =>
          operationId === "synthetic.erp.order.get",
      );
      operation.parameterSchema.properties.orderRef.pattern =
        "^ALT-ORD-[0-9]{4}$";
    },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(original);
    mutate(changed);
    assert.throws(
      () => createSyntheticToolCatalog(changed),
      (error) =>
        error instanceof ToolGatewayError &&
        error.code === "INVALID_CATALOG",
    );
  }
});

test("C16 verification matrix fixes required negative and recovery evidence", async () => {
  const matrix = await json("verification-matrix.v1.json");
  assert.equal(matrix.implementationStatus, "IMPLEMENTED");
  assert.equal(matrix.verificationStatus, "VERIFIED");
  assert.equal(matrix.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(matrix.enterpriseConnectors, "C0_DISABLED");
  const ids = new Set(matrix.assertions.map(({ id }) => id));
  for (const id of [
    "C16-IDENTITY-REAUTH",
    "C16-CATALOG-CLOSED",
    "C16-CONFIRMATION-BINDING",
    "C16-CREDENTIAL-ZERO-LEAK",
    "C16-C0-NO-NETWORK",
    "C16-C18-ACK-RECOVERY",
    "C16-PG-RLS-ROLES",
    "C16-PG-RESTORE",
  ]) {
    assert.equal(ids.has(id), true);
  }
});

test("C16 source contains no live endpoint, generic execution primitive, or embedded credential", async () => {
  const roots = [
    new URL("../lib/", import.meta.url),
    new URL("../tests/", import.meta.url),
    ROOT,
  ];
  const names = [
    "tool-gateway.mjs",
    "c16-c06-authorizer.mjs",
    "c16-ephemeral-credential-broker.mjs",
    "c16-synthetic-tool-adapter.mjs",
    "c16-outbox-worker.mjs",
    "postgres-tool-gateway-store.mjs",
  ];
  const contents = [];
  for (const name of names) {
    contents.push(await readFile(new URL(name, roots[0]), "utf8"));
  }
  const implementationFiles = await readdir(ROOT, {
    recursive: true,
    withFileTypes: true,
  });
  for (const entry of implementationFiles) {
    if (!entry.isFile()) continue;
    const absolute = path.join(entry.parentPath, entry.name);
    contents.push(await readFile(absolute, "utf8"));
  }
  const source = contents.join("\n");
  for (const forbidden of [
    /\bhttps?:\/\//i,
    /\bfetch\s*\(/,
    /node:child_process/,
    /\bexec(?:File|Sync)?\s*\(/,
    /\bSELECT\s+\*\s+FROM\s+\$\{/i,
    /BEGIN [A-Z ]*PRIVATE KEY/,
    /\b(?:api[_-]?key|client[_-]?secret|password)\s*[:=]\s*["'][^"']+["']/i,
  ]) {
    assert.doesNotMatch(source, forbidden);
  }
});

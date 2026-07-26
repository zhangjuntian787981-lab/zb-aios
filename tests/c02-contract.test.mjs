import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createTenantGovernanceShell,
} from "../lib/tenant-governance-shell.mjs";

const ROOT = new URL("../implementation/p1/c02/", import.meta.url);

async function json(name) {
  return JSON.parse(await readFile(new URL(name, ROOT), "utf8"));
}

test("C02 freezes one Core-authorized management API and shell contract", async () => {
  const [api, useCases, shell, matrix] = await Promise.all([
    json("management-api.openapi.v1.json"),
    json("management-use-cases.v1.json"),
    json("management-shell.contract.v1.json"),
    json("verification-matrix.v1.json"),
  ]);
  assert.equal(api.openapi, "3.1.2");
  assert.deepEqual(
    Object.values(api.paths).map(({ post }) => post.operationId),
    ["readGovernanceView", "commitGovernanceChange"],
  );
  assert.equal(api["x-c02-boundary"].authority_owner, "PRODUCT_CORE");
  assert.equal(
    api["x-c02-boundary"].browser_direct_core_access,
    false,
  );
  assert.equal(useCases.readOperations.length, 9);
  assert.equal(useCases.writeOperations.length, 7);
  assert.equal(
    useCases.confirmationPolicy.callerAssertedHashSufficient,
    false,
  );
  assert.equal(useCases.confirmationPolicy.singleUse, true);
  assert.equal(
    api["x-c02-boundary"].caller_asserted_confirmation_sufficient,
    false,
  );
  assert.equal(
    useCases.readOperations.some(({ operationId }) =>
      operationId.includes("PRIVATE")
    ),
    false,
  );
  assert.equal(
    useCases.writeOperations.every(
      ({ highRisk, requiresSecondConfirmation, requiresEvidence }) =>
        highRisk === true &&
        requiresSecondConfirmation === true &&
        requiresEvidence === true,
    ),
    true,
  );
  assert.equal(
    useCases.writeOperations.some(
      ({ operationId }) => operationId === "AUDIT_CHANGE",
    ),
    false,
  );
  assert.equal(shell.dataSource, "C02_BFF_ONLY");
  assert.equal(shell.permissionTruth, "PRODUCT_CORE");
  assert.equal(shell.pages.length, 9);
  assert.equal(
    shell.pages.find(({ readOperationId }) =>
      readOperationId === "AUDIT_VIEW"
    ).writeOperationId,
    null,
  );
  assert.equal(matrix.assertions.length, 8);
  assert.equal(matrix.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(matrix.enterpriseConnectors, "C0_DISABLED");
});

test("C02 OpenAPI, use cases, shell contract, and runtime catalog cannot drift", async () => {
  const [api, useCases, shell] = await Promise.all([
    json("management-api.openapi.v1.json"),
    json("management-use-cases.v1.json"),
    json("management-shell.contract.v1.json"),
  ]);
  assert.deepEqual(
    api.components.schemas.ReadOperationId.enum,
    useCases.readOperations.map(({ operationId }) => operationId),
  );
  assert.deepEqual(
    api.components.schemas.WriteOperationId.enum,
    useCases.writeOperations.map(({ operationId }) => operationId),
  );
  const runtimeShell = createTenantGovernanceShell({
    bffClient: {
      async read() {
        throw new Error("not used");
      },
      async mutate() {
        throw new Error("not used");
      },
    },
  });
  assert.deepEqual(runtimeShell.listPages(), shell.pages);

  function visit(value) {
    if (!value || typeof value !== "object") return;
    if (typeof value.$ref === "string") {
      assert.match(value.$ref, /^#\/components\/schemas\/[A-Za-z0-9]+$/);
      const schemaName = value.$ref.split("/").at(-1);
      assert.ok(api.components.schemas[schemaName]);
    }
    if (Array.isArray(value.required)) {
      assert.equal(new Set(value.required).size, value.required.length);
    }
    for (const nested of Object.values(value)) visit(nested);
  }
  visit(api);
});

test("C02 dependency bindings match the exact frozen P1 artifacts", async () => {
  const bindings = await json("dependency-bindings.v1.json");
  assert.deepEqual(
    bindings.dependencies.map(({ workPackage }) => workPackage),
    ["C03", "C04", "C05", "C06", "C07", "C13", "C18", "C19"],
  );
  for (const dependency of bindings.dependencies) {
    const bytes = await readFile(
      new URL(`../${dependency.path}`, import.meta.url),
    );
    assert.equal(
      `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
      dependency.sha256,
    );
  }
});

test("C02 runtime has no direct model, knowledge, Connector, or database path", async () => {
  const source = (
    await Promise.all(
      [
        "../lib/c02-c06-authorizer.mjs",
        "../lib/tenant-governance-bff.mjs",
        "../lib/tenant-governance-shell.mjs",
      ].map((path) =>
        readFile(new URL(path, import.meta.url), "utf8")
      ),
    )
  ).join("\n");
  for (const forbidden of [
    /\bfetch\s*\(/,
    /node:(?:http|https|net|tls|child_process)/,
    /\b(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET|DELETE\s+FROM)\b/i,
    /process\.env/,
    /\b(?:modelPort|ragPort|connectorPort|databasePort)\b/,
  ]) {
    assert.doesNotMatch(source, forbidden);
  }
});

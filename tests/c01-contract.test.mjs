import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createEmployeePortalShell,
} from "../lib/employee-portal-shell.mjs";

const ROOT = new URL("../implementation/p1/c01/", import.meta.url);

async function json(name) {
  return JSON.parse(await readFile(new URL(name, ROOT), "utf8"));
}

test("C01 freezes one replaceable Synthetic portal contract", async () => {
  const [api, useCases, shell, upstream, matrix] = await Promise.all([
    json("employee-portal.openapi.v1.json"),
    json("portal-use-cases.v1.json"),
    json("replacement-shell.contract.v1.json"),
    json("upstream-portal-baseline.v1.json"),
    json("verification-matrix.v1.json"),
  ]);
  assert.equal(api.openapi, "3.1.2");
  assert.deepEqual(
    Object.values(api.paths).map(({ post }) => post.operationId),
    ["readPortalView", "commitPortalCommand", "streamPortalRun"],
  );
  assert.equal(api["x-c01-boundary"].authority_owner, "PRODUCT_CORE");
  assert.equal(api["x-c01-boundary"].browser_direct_core_access, false);
  assert.equal(api["x-c01-boundary"].direct_model_access, false);
  assert.equal(api["x-c01-boundary"].direct_connector_access, false);
  assert.equal(useCases.readOperations.length, 9);
  assert.equal(useCases.writeOperations.length, 5);
  assert.deepEqual(useCases.streamOperations, ["RUN_STREAM_VIEW"]);
  assert.equal(
    useCases.writeOperations.find(
      ({ operationId }) =>
        operationId === "FILE_QUARANTINE_REQUEST",
    ).acceptsRawBytes,
    false,
  );
  assert.equal(shell.renderers.length, 2);
  const runtimeShell = createEmployeePortalShell({
    renderer: "MINIMAL_REPLACEMENT",
    bffClient: {
      async read() {
        throw new Error("not used");
      },
      async mutate() {
        throw new Error("not used");
      },
      async *stream() {
        throw new Error("not used");
      },
    },
  });
  assert.deepEqual(runtimeShell.listSurfaces(), shell.surfaces);
  assert.equal(upstream.project, "LibreChat");
  assert.equal(upstream.tag, "v0.8.7");
  assert.equal(
    upstream.gitCommitSha1,
    "9e74cc0e57b395926122bd4062c1fcedc48ed465",
  );
  assert.equal(upstream.integrationStatus, "NOT_EMBEDDED");
  assert.equal(upstream.deploymentStatus, "NOT_DEPLOYED");
  assert.equal(matrix.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(matrix.enterpriseConnectors, "C0_DISABLED");
  assert.deepEqual(matrix.openP1Items, []);
});

test("C01 OpenAPI and use-case operation catalogs cannot drift", async () => {
  const [api, useCases] = await Promise.all([
    json("employee-portal.openapi.v1.json"),
    json("portal-use-cases.v1.json"),
  ]);
  assert.deepEqual(
    api.components.schemas.ReadOperationId.enum,
    useCases.readOperations.map(({ operationId }) => operationId),
  );
  assert.deepEqual(
    api.components.schemas.WriteOperationId.enum,
    useCases.writeOperations.map(({ operationId }) => operationId),
  );

  function visit(value) {
    if (!value || typeof value !== "object") return;
    if (typeof value.$ref === "string") {
      assert.match(value.$ref, /^#\/components\/schemas\/[A-Za-z0-9]+$/);
      assert.ok(
        api.components.schemas[value.$ref.split("/").at(-1)],
        value.$ref,
      );
    }
    if (Array.isArray(value.required)) {
      assert.equal(new Set(value.required).size, value.required.length);
    }
    Object.values(value).forEach(visit);
  }
  visit(api);
});

test("C01 OpenAPI binds each operation to its exact result shape", async () => {
  const api = await json("employee-portal.openapi.v1.json");
  const viewBindings = Object.fromEntries(
    api.components.schemas.PortalView.allOf.map((branch) => [
      branch.if.properties.operationId.const,
      branch.then.properties.items.items.$ref,
    ]),
  );
  assert.deepEqual(viewBindings, {
    PORTAL_HOME_VIEW: "#/components/schemas/HomeItem",
    THREAD_VIEW: "#/components/schemas/ThreadItem",
    RUN_VIEW: "#/components/schemas/RunItem",
    FILE_STATUS_VIEW: "#/components/schemas/FileItem",
    RESOURCE_DIRECTORY_VIEW:
      "#/components/schemas/ResourceDirectoryItem",
    AGENT_SKILL_DIRECTORY_VIEW:
      "#/components/schemas/AgentSkillItem",
    MEMORY_VIEW: "#/components/schemas/MemoryItem",
    APPROVAL_VIEW: "#/components/schemas/ApprovalItem",
    CITATION_VIEW: "#/components/schemas/CitationItem",
  });
  assert.notEqual(
    viewBindings.FILE_STATUS_VIEW,
    viewBindings.THREAD_VIEW,
  );

  const receiptBindings = Object.fromEntries(
    api.components.schemas.MutationReceipt.allOf.map((branch) => [
      branch.if.properties.operationId.const,
      branch.then.properties.status.const,
    ]),
  );
  assert.deepEqual(receiptBindings, {
    THREAD_CREATE: "CREATED",
    CHAT_SUBMIT: "ACCEPTED",
    FILE_QUARANTINE_REQUEST: "QUARANTINED",
    MEMORY_CONFIRM: "RECORDED",
    APPROVAL_DECIDE: "RECORDED",
  });
  assert.notEqual(
    receiptBindings.FILE_QUARANTINE_REQUEST,
    receiptBindings.THREAD_CREATE,
  );
});

test("C01 dependency bindings match exact verified P1 evidence", async () => {
  const bindings = await json("dependency-bindings.v1.json");
  assert.deepEqual(
    bindings.dependencies.map(({ workPackage }) => workPackage),
    ["C03", "C04", "C05", "C06", "C08", "C14", "C15", "C16"],
  );
  for (const dependency of bindings.dependencies) {
    assert.equal(dependency.verificationStatus, "VERIFIED");
    const bytes = await readFile(
      new URL(`../${dependency.path}`, import.meta.url),
    );
    assert.equal(
      `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
      dependency.sha256,
      dependency.path,
    );
  }
});

test("C01 runtime has no direct model, RAG, Connector, database, or network path", async () => {
  const source = (
    await Promise.all(
      [
        "../lib/c01-c06-authorizer.mjs",
        "../lib/employee-portal-bff.mjs",
        "../lib/employee-portal-shell.mjs",
      ].map((path) => readFile(new URL(path, import.meta.url), "utf8")),
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

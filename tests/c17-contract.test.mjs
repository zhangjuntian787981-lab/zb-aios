import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function readJson(path) {
  return JSON.parse(
    await readFile(new URL(path, import.meta.url), "utf8"),
  );
}

const envelopeSchema = await readJson(
  "../implementation/p0/connector-envelope.v1.json",
);
const f03Connector = await readJson(
  "../implementation/p0/f03/contracts/connector.openapi.v1.json",
);
const f04Cases = await readJson(
  "../implementation/p0/f04/frozen-evaluation-cases.v1.json",
);
const c16Catalog = await readJson(
  "../implementation/p1/c16/operation-catalog.v1.json",
);
const c17Templates = await readJson(
  "../implementation/p1/c17/connector-templates.v1.json",
);
const compatibilityMatrix = await readJson(
  "../implementation/p1/c17/compatibility-matrix.v1.json",
);

test("C17 remains compatible with the frozen F03, F04, and C16 seams", () => {
  assert.equal(
    envelopeSchema.$id,
    "urn:multi-enterprise-ai-platform:connector-envelope:v1",
  );
  assert.equal(
    f03Connector.paths["/v1/connector-templates:validate"].post
      .operationId,
    "validateConnectorTemplate",
  );
  assert.equal(
    f03Connector["x-f03-boundary"]
      .mock_does_not_imply_enterprise_connected,
    true,
  );
  assert.equal(
    f04Cases.cases.some(
      (entry) =>
        entry.id === "F04-E010" &&
        entry.zero_tolerance_rule_id === "ZT-05",
    ),
    true,
  );

  for (const template of c17Templates.templates) {
    const operation = c16Catalog.operations.find(
      (entry) => entry.operationId === template.operationId,
    );
    assert.ok(operation);
    assert.equal(operation.mode, template.mode);
    assert.equal(operation.audience, template.audience);
    assert.deepEqual(
      operation.parameterSchema,
      template.parameterSchema,
    );
  }
});

test("C17 dependency closure pins both F03 evidence and the exact Envelope bytes", async () => {
  const f03 = compatibilityMatrix.dependencies.find(
    (entry) => entry.workPackage === "F03",
  );
  assert.deepEqual(f03, {
    workPackage: "F03",
    evidencePath: "implementation/p0/evidence/f03-evidence.v1.json",
    evidenceSha256:
      "sha256:64aac8860a9b397860015542338ca90b2a8bd2e9381e56e53fa2ffb1dc01bcda",
    contractPath: "implementation/p0/connector-envelope.v1.json",
    contractSha256:
      "sha256:3cf839e3ec5782e17c3bed8f7e6cfd30bd025044f8e69a43977e04476679a3a1",
    seam: "Canonical Connector Envelope v1 and validateConnectorTemplate",
  });
  const envelopeBytes = await readFile(
    new URL(
      "../implementation/p0/connector-envelope.v1.json",
      import.meta.url,
    ),
  );
  assert.equal(
    `sha256:${createHash("sha256").update(envelopeBytes).digest("hex")}`,
    f03.contractSha256,
  );
});

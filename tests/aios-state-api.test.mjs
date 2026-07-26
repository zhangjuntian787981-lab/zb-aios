import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const rootUrl = new URL("../", import.meta.url);
const api = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c08/aios-state-core.openapi.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const startManifest = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c08/run-manifest.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const replayMatrix = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c08/replay-matrix.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

const COMMAND_FIELDS = Object.freeze({
  CREATE_CASE: ["kind", "goalRef"],
  OPEN_THREAD: ["kind", "caseId", "purposeRef"],
  RECORD_ARTIFACT_VERSION: [
    "kind",
    "artifactId",
    "caseId",
    "threadId",
    "expectedArtifactVersion",
    "artifactKind",
    "contentRef",
    "contentSha256",
  ],
  START_RUN: ["kind", "threadId", "manifest"],
  PREPARE_TOOL_CALL: [
    "kind",
    "runId",
    "expectedRunVersion",
    "operationRef",
    "operationVersion",
    "requestHash",
    "compensationRef",
  ],
  FINISH_RUN: [
    "kind",
    "runId",
    "expectedRunVersion",
    "outcome",
    "resultArtifact",
  ],
});

function localSchema(ref) {
  const name = ref.replace("#/components/schemas/", "");
  return api.components.schemas[name];
}

test("C08 OpenAPI exposes only the implemented closed Core surface", () => {
  assert.equal(
    api["x-c08-boundary"].implementation_status,
    "IMPLEMENTED",
  );
  assert.equal(
    api["x-c08-boundary"].verification_status,
    "VERIFIED",
  );
  assert.equal(
    api["x-c08-boundary"].production_verification_status,
    "NOT_VERIFIED",
  );
  const operations = Object.entries(api.paths).flatMap(([path, item]) =>
    Object.values(item).map((operation) => ({
      path,
      operationId: operation.operationId,
    })),
  );
  assert.deepEqual(operations, [
    {
      path: "/internal/v1/aios-state/commands:execute",
      operationId: "execute",
    },
    {
      path: "/internal/v1/aios-state/tool-results:record",
      operationId: "recordToolCallResult",
    },
    {
      path: "/internal/v1/aios-state/runs:inspect",
      operationId: "inspectRun",
    },
    {
      path: "/internal/v1/aios-state/runs:reconstruct",
      operationId: "reconstructRun",
    },
    {
      path: "/internal/v1/aios-state/snapshots:read",
      operationId: "snapshot",
    },
  ]);

  const envelope = api.components.schemas.StateCommandRequest;
  assert.equal(envelope.additionalProperties, false);
  assert.deepEqual(envelope.required, [
    "sessionToken",
    "delegationId",
    "idempotencyKey",
    "correlationId",
    "command",
  ]);
  assert.deepEqual(Object.keys(envelope.properties), envelope.required);

  const commandUnion = api.components.schemas.StateCommand;
  assert.deepEqual(
    Object.keys(commandUnion.discriminator.mapping),
    Object.keys(COMMAND_FIELDS),
  );
  assert.equal(commandUnion.oneOf.length, 6);
  for (const [kind, ref] of Object.entries(
    commandUnion.discriminator.mapping,
  )) {
    const schema = localSchema(ref);
    assert.equal(schema.type, "object", kind);
    assert.equal(schema.additionalProperties, false, kind);
    assert.deepEqual(schema.required, COMMAND_FIELDS[kind], kind);
    assert.deepEqual(Object.keys(schema.properties), COMMAND_FIELDS[kind], kind);
    assert.equal(schema.properties.kind.const, kind);
  }
  const artifactCommand =
    api.components.schemas.RecordArtifactVersionCommand;
  assert.equal(
    artifactCommand.allOf[0].then.properties.expectedArtifactVersion.const,
    0,
  );
  assert.equal(
    artifactCommand.allOf[0].else.properties.expectedArtifactVersion.minimum,
    1,
  );

  const workerEnvelope = api.components.schemas.ToolResultRequest;
  assert.equal(workerEnvelope.additionalProperties, false);
  assert.deepEqual(workerEnvelope.required, [
    "idempotencyKey",
    "correlationId",
    "command",
  ]);
  assert.deepEqual(
    Object.keys(workerEnvelope.properties),
    workerEnvelope.required,
  );
  const workerCommand = api.components.schemas.RecordToolCallResultCommand;
  assert.equal(workerCommand.additionalProperties, false);
  assert.deepEqual(workerCommand.required, [
    "kind",
    "runId",
    "expectedRunVersion",
    "toolCallId",
    "expectedToolCallVersion",
    "receiptId",
  ]);
  assert.deepEqual(Object.keys(workerCommand.properties), workerCommand.required);
  assert.equal(
    Object.hasOwn(commandUnion.discriminator.mapping, "RECORD_TOOL_CALL_RESULT"),
    false,
  );

  const commandResult = api.components.schemas.StateCommandResult;
  assert.equal(commandResult.oneOf.length, 6);
  assert.equal(
    commandResult.oneOf.some(
      ({ $ref }) => $ref.endsWith("/RecordToolCallResult"),
    ),
    false,
  );

  const execute =
    api.paths["/internal/v1/aios-state/commands:execute"].post;
  const inspect =
    api.paths["/internal/v1/aios-state/runs:inspect"].post;
  const reconstruct =
    api.paths["/internal/v1/aios-state/runs:reconstruct"].post;
  assert.deepEqual(execute["x-runtime-order"], [
    "C05_RESOLVE_ACTION_IDENTITY",
    "C06_ENFORCE_OPERATION",
    "C06_BOUND_DECISION_IDENTITY_CHECK",
    "C05_FINAL_RESOLVE_ACTION_IDENTITY",
    "C03_FINAL_ACTIVE_ADMISSION",
    "C07_VERIFIED_SCOPE_AND_STORE",
  ]);
  assert.deepEqual(inspect["x-runtime-order"], execute["x-runtime-order"]);
  assert.deepEqual(reconstruct["x-runtime-order"], execute["x-runtime-order"]);

  const operational = api.components.schemas.OperationalRunSnapshot;
  assert.equal(operational.additionalProperties, false);
  assert.equal(
    operational.properties.case.$ref,
    "#/components/schemas/OperationalCase",
  );
  assert.equal(
    operational.properties.thread.$ref,
    "#/components/schemas/OperationalThread",
  );
  assert.deepEqual(
    operational.properties.tools.items,
    { $ref: "#/components/schemas/OperationalToolCall" },
  );
  assert.equal(
    operational.properties.result.oneOf.some(({ type }) => type === "null"),
    true,
  );
  const operationalTool =
    api.components.schemas.OperationalToolCall;
  assert.equal(operationalTool.required.includes("policy"), true);
  assert.deepEqual(operationalTool.properties.policy, {
    $ref: "#/components/schemas/AuthorizationEvidence",
  });
  const reconstructedTool =
    api.components.schemas.ReconstructedToolCall;
  assert.equal(reconstructedTool.required.includes("policy"), true);
  assert.deepEqual(reconstructedTool.properties.policy, {
    $ref: "#/components/schemas/AuthorizationEvidence",
  });

  const serialized = JSON.stringify({
    paths: api.paths,
    command: commandUnion,
  });
  for (const forbidden of [
    "claimOutbox",
    "completeOutbox",
    "failOutbox",
    "connectorInstance",
    "credential",
    "authorizationEffect",
  ]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }

  for (const [name, schema] of Object.entries(api.components.schemas)) {
    if (schema.type === "object") {
      assert.equal(schema.additionalProperties, false, name);
    }
  }
});

test("C08 START_RUN schema contains only start-time frozen references", () => {
  const fields = [
    "inputArtifact",
    "model",
    "prompt",
    "skill",
    "knowledge",
    "traceRef",
  ];
  assert.equal(startManifest.type, "object");
  assert.equal(startManifest.additionalProperties, false);
  assert.deepEqual(startManifest.required, fields);
  assert.deepEqual(Object.keys(startManifest.properties), fields);
  assert.equal(startManifest.properties.knowledge.minItems, 1);
  assert.equal(startManifest.properties.knowledge.maxItems, 32);
  assert.equal(startManifest.properties.knowledge.uniqueItems, true);
  for (const forbidden of ["tool", "tools", "policy", "result"]) {
    assert.equal(
      Object.hasOwn(startManifest.properties, forbidden),
      false,
      forbidden,
    );
  }
  for (const [name, schema] of Object.entries(startManifest.$defs)) {
    if (schema.type === "object") {
      assert.equal(schema.additionalProperties, false, name);
    }
  }

  const reconstructed =
    api.components.schemas.ReconstructedManifest;
  assert.deepEqual(reconstructed.required, [
    "runId",
    "caseId",
    "threadId",
    "input",
    "model",
    "prompt",
    "skill",
    "knowledge",
    "tools",
    "policy",
    "result",
    "tenantLifecycleVersion",
    "actor",
    "traceRef",
    "dependentPackageStatus",
  ]);
  assert.equal(reconstructed.properties.knowledge.minItems, 1);
  assert.equal(reconstructed.properties.tools.minItems, 0);
});

test("C08 replay matrix maps every case to a real exact test title", async () => {
  assert.equal(replayMatrix.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(replayMatrix.dataClassification, "SYNTHETIC_ONLY");
  assert.equal(replayMatrix.implementationStatus, "IMPLEMENTED");
  assert.equal(replayMatrix.verificationStatus, "VERIFIED");
  assert.equal(replayMatrix.enterpriseConnectors, "C0_DISABLED");
  assert.equal(replayMatrix.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(replayMatrix.cases.length, 47);
  assert.equal(
    new Set(replayMatrix.cases.map(({ caseId }) => caseId)).size,
    replayMatrix.cases.length,
  );
  assert.deepEqual(
    Object.keys(replayMatrix.verificationMap).sort(),
    replayMatrix.cases.map(({ caseId }) => caseId).sort(),
  );
  assert.equal(
    replayMatrix.cases.every(
      ({ evidenceStatus }) =>
        evidenceStatus === "VERIFIED_P1_SYNTHETIC",
    ),
    true,
  );

  for (const references of Object.values(replayMatrix.verificationMap)) {
    assert.equal(Array.isArray(references) && references.length > 0, true);
    for (const reference of references) {
      const separator = reference.indexOf("#");
      assert.equal(separator > 0, true, reference);
      const path = reference.slice(0, separator);
      const title = reference.slice(separator + 1);
      const source = await readFile(new URL(path, rootUrl), "utf8");
      assert.equal(
        source.includes(`"${title}"`) || source.includes(`'${title}'`),
        true,
        reference,
      );
    }
  }
});

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { c12Sha256 } from "../lib/agent-orchestrator.mjs";

const root = new URL(
  "../implementation/p1/c12/",
  import.meta.url,
);

async function json(name) {
  return JSON.parse(await readFile(new URL(name, root), "utf8"));
}

function assertObjectSchemasClosed(value, path = "#") {
  if (!value || typeof value !== "object") return;
  const types = Array.isArray(value.type) ? value.type : [value.type];
  if (types.includes("object")) {
    assert.equal(
      value.additionalProperties,
      false,
      `${path} must reject undeclared properties`,
    );
  }
  for (const [key, nested] of Object.entries(value)) {
    assertObjectSchemasClosed(nested, `${path}/${key}`);
  }
}

test("C12 contracts freeze one explicit Synthetic-only graph", async () => {
  const [api, graph, catalog, envelope, nodeSchemas, matrix] =
    await Promise.all([
    json("agent-orchestrator.openapi.v1.json"),
    json("orchestration-graph.v1.json"),
    json("synthetic-task-catalog.v1.json"),
    json("task-envelope.v1.schema.json"),
    json("node-io.v1.schema.json"),
    json("verification-matrix.v1.json"),
    ]);
  assert.equal(api.openapi, "3.1.2");
  assert.equal(
    api["x-c12-boundary"].verification_scope,
    "P1_SYNTHETIC_ONLY",
  );
  assert.equal(api["x-c12-boundary"].verification_status, "VERIFIED");
  assert.equal(api["x-c12-boundary"].dynamic_graph, false);
  assert.equal(api["x-c12-boundary"].free_form_multi_agent_chat, false);
  assert.equal(api["x-c12-boundary"].checkpoint_owner, "C12");
  assert.equal(api["x-c12-boundary"].run_ledger_owner, "C08");
  assert.equal(
    Object.hasOwn(api["x-c12-boundary"], "state_owner"),
    false,
  );
  assert.deepEqual(
    Object.values(api.paths).map(({ post }) => post.operationId),
    ["start", "advance", "resumeWithHumanDecision", "inspect"],
  );
  for (const { post } of Object.values(api.paths)) {
    assert.ok(post.requestBody?.content["application/json"].schema.$ref);
    assert.equal(
      post.responses["200"].content["application/json"].schema.$ref,
      post.operationId === "inspect"
        ? "./node-io.v1.schema.json#/$defs/TaskState"
        : "#/components/schemas/TaskView",
    );
    assert.equal(
      post.responses.default.content["application/json"].schema.$ref,
      "#/components/schemas/Error",
    );
  }
  assert.equal(graph.nodes.length, 9);
  assert.deepEqual(
    graph.nodes.map(({ nodeId }) => nodeId),
    [
      "CLASSIFY",
      "HARD_GATES",
      "RETRIEVE",
      "TOOL",
      "DRAFT",
      "VALIDATE",
      "INDEPENDENT_REVIEW",
      "HUMAN_GATE",
      "COMPLETE",
    ],
  );
  assert.equal(graph.nodes.every(({ externalEffect }) => !externalEffect), true);
  assert.equal(catalog.tasks.length, 3);
  assert.equal(
    new Set(catalog.tasks.map(({ tenantId }) => tenantId)).size,
    3,
  );
  assert.equal(
    catalog.tasks.every(
      ({ dataClass, humanDecisionRequired, budget }) =>
        dataClass === "SYNTHETIC" &&
        humanDecisionRequired === true &&
        budget.maxToolCalls === 1,
    ),
    true,
  );
  assert.equal(envelope.additionalProperties, false);
  for (const name of [
    "NodeRecord",
    "TaskState",
    "PolicyGateInput",
    "PolicyGateResult",
    "RagInput",
    "RagResult",
    "ToolInput",
    "ToolResult",
    "ModelInput",
    "ModelResult",
    "ArtifactCheckInput",
    "ValidationResult",
    "ReviewInput",
    "ReviewResult",
    "HumanDecisionInput",
    "HumanDecisionResult",
  ]) {
    assert.equal(nodeSchemas.$defs[name].additionalProperties, false);
  }
  assert.equal(
    nodeSchemas.$defs.NodeRecord.required.includes("binding"),
    true,
  );
  assert.equal(
    nodeSchemas.$defs.ModelInput.required.includes("evidenceContext"),
    true,
  );
  assert.equal(
    nodeSchemas.$defs.ToolInput.required.includes("sessionToken"),
    true,
  );
  assertObjectSchemasClosed(nodeSchemas);
  const nodeBindings = Object.fromEntries(
    nodeSchemas.$defs.NodeRecord.allOf.map((branch) => [
      branch.if.properties.nodeId.const,
      branch.then.properties.binding.$ref,
    ]),
  );
  assert.deepEqual(nodeBindings, {
    CLASSIFY: "#/$defs/ClassifyBinding",
    HARD_GATES: "#/$defs/PolicyGateResult",
    RETRIEVE: "#/$defs/RetrieveBinding",
    TOOL: "#/$defs/ToolBindingRecord",
    DRAFT: "#/$defs/DraftBinding",
    VALIDATE: "#/$defs/ValidationBinding",
    INDEPENDENT_REVIEW: "#/$defs/ReviewBinding",
    HUMAN_GATE: "#/$defs/HumanDecisionResult",
    COMPLETE: "#/$defs/CompleteBinding",
  });
  const taskIdPattern = api.components.schemas.TaskId.pattern;
  for (const name of [
    "AdvanceRequest",
    "ResumeHumanDecisionRequest",
    "InspectRequest",
  ]) {
    assert.equal(
      api.components.schemas[name].allOf[1].properties.taskId.$ref,
      "#/components/schemas/TaskId",
      name,
    );
  }
  assert.equal(nodeSchemas.$defs.TaskId.pattern, taskIdPattern);
  assert.deepEqual(api.components.schemas.TaskView.required, [
    "task",
    "replayed",
    "receipt",
  ]);
  assert.equal(
    api.components.schemas.TaskView.properties.receipt.$ref,
    "#/components/schemas/StatePortReceipt",
  );
  assert.deepEqual(
    api.components.schemas.StatePortReceipt.required,
    [
      "schemaVersion",
      "tenantId",
      "humanPrincipalId",
      "workloadActorPrincipalId",
      "taskId",
      "operation",
      "idempotencyKey",
      "requestSha256",
      "resultVersion",
      "resultStateSha256",
      "receiptSha256",
    ],
  );
  assert.equal(
    api.components.schemas.StatePortReceipt.additionalProperties,
    false,
  );
  assert.deepEqual(nodeSchemas.$defs.TaskState.properties.nextNodeId.enum, [
    "CLASSIFY",
    "HARD_GATES",
    "RETRIEVE",
    "TOOL",
    "DRAFT",
    "VALIDATE",
    "INDEPENDENT_REVIEW",
    "HUMAN_GATE",
    "COMPLETE",
    null,
  ]);
  assert.equal(
    catalog.tasks.every(({ bindings }) =>
      bindings.reviewModel.ref ===
        "synthetic://c14/models/local-canary" &&
      bindings.reviewModel.version === "2.0.0-rc.1" &&
      bindings.reviewModel.sha256 ===
        "sha256:152faf77163a3bf789d10e0fcb0db036456bd59780f9d06546c1d3eccc5e765a"
    ),
    true,
  );
  for (const name of ["ValidationResult", "ReviewResult"]) {
    for (const field of [
      "effectKey",
      "artifactRef",
      "artifactSha256",
    ]) {
      assert.equal(nodeSchemas.$defs[name].required.includes(field), true);
    }
  }
  assert.equal(
    nodeSchemas.$defs.ReviewInput.required.includes("budget"),
    true,
  );
  for (const field of [
    "inputTokens",
    "outputTokens",
    "totalTokens",
    "costMicrousd",
  ]) {
    assert.equal(
      nodeSchemas.$defs.ReviewResult.required.includes(field),
      true,
    );
    assert.equal(
      nodeSchemas.$defs.ReviewBinding.required.includes(field),
      true,
    );
  }
  for (const forbidden of [
    "tenantId",
    "dataClass",
    "riskClass",
    "budget",
    "model",
    "provider",
    "tool",
    "permission",
    "approval",
    "prompt",
  ]) {
    assert.equal(Object.hasOwn(envelope.properties, forbidden), false);
  }
  assert.equal(matrix.assertions.length, 12);
  assert.equal(matrix.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(matrix.enterpriseConnectors, "C0_DISABLED");
  assert.deepEqual(matrix.openP1Items, []);
});

test("C12 source contracts contain no arbitrary execution surface", async () => {
  const contractContent = await Promise.all([
    "agent-orchestrator.openapi.v1.json",
    "dependency-bindings.v1.json",
    "node-io.v1.schema.json",
    "orchestration-graph.v1.json",
    "synthetic-task-inputs.v1.json",
    "synthetic-task-catalog.v1.json",
    "task-envelope.v1.schema.json",
    "verification-matrix.v1.json",
    "README.md",
  ].map((name) => readFile(new URL(name, root), "utf8")));
  const runtimeContent = await readFile(
    new URL("../lib/agent-orchestrator.mjs", import.meta.url),
    "utf8",
  );
  const source = [...contractContent, runtimeContent].join("\n");
  for (const forbidden of [
    /node:child_process/,
    /\b(?:exec|spawn)\s*\(/,
    /\bSELECT\s+\*/,
    /BEGIN [A-Z ]*PRIVATE KEY/,
  ]) {
    assert.doesNotMatch(source, forbidden);
  }
});

test("C12 task inputs bind real three-Tenant Synthetic fixtures", async () => {
  const [catalog, fixture] = await Promise.all([
    json("synthetic-task-catalog.v1.json"),
    json("synthetic-task-inputs.v1.json"),
  ]);
  assert.equal(fixture.schemaVersion, "c12-synthetic-task-inputs.v1");
  assert.equal(fixture.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(fixture.inputs.length, 3);
  for (const task of catalog.tasks) {
    const input = fixture.inputs.find(
      (candidate) =>
        candidate.tenantId === task.tenantId &&
        candidate.inputRef === task.inputRef,
    );
    assert.ok(input);
    assert.equal(input.dataClass, "SYNTHETIC");
    assert.equal(input.payload.orderRef, task.toolInvocation.parameters.orderRef);
    assert.equal(c12Sha256(input.payload), input.payloadSha256);
    assert.equal(input.payloadSha256, task.inputSha256);
  }
});

test("C12 catalog bindings match the frozen upstream artifacts", async () => {
  const [catalog, bindings] = await Promise.all([
    json("synthetic-task-catalog.v1.json"),
    json("dependency-bindings.v1.json"),
  ]);
  assert.deepEqual(
    bindings.dependencies.map(({ workPackage }) => workPackage),
    ["C06", "C08", "C11", "C13", "C14", "C16"],
  );
  for (const dependency of bindings.dependencies) {
    const bytes = await readFile(
      new URL(`../${dependency.path}`, import.meta.url),
    );
    assert.equal(
      `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
      dependency.fileSha256,
    );
    assert.equal(
      dependency.bindingMode,
      dependency.workPackage === "C08"
        ? "CONTRACT_ONLY"
        : "TASK_CATALOG",
    );
    if (dependency.bindingMode === "CONTRACT_ONLY") continue;
    for (const task of catalog.tasks) {
      if (dependency.bindingName === "tool") {
        assert.equal(
          task.bindings.tool.operationId,
          dependency.ref,
        );
        assert.equal(
          task.bindings.tool.catalogVersion,
          dependency.version,
        );
        assert.equal(
          task.bindings.tool.sha256,
          dependency.bindingSha256,
        );
      } else {
        assert.deepEqual(task.bindings[dependency.bindingName], {
          ref: dependency.ref,
          version: dependency.version,
          sha256: dependency.bindingSha256,
        });
      }
    }
  }

  const policy = JSON.parse(
    await readFile(
      new URL(
        "../implementation/p1/c06/synthetic-policy-catalog.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.equal(
    policy.release_templates.some(
      (entry) =>
        entry.template_ref ===
          bindings.dependencies.find(
            ({ workPackage }) => workPackage === "C06",
          ).ref &&
        entry.bundle_sha256 ===
          bindings.dependencies.find(
            ({ workPackage }) => workPackage === "C06",
          ).bindingSha256,
    ),
    true,
  );
  const skill = JSON.parse(
    await readFile(
      new URL(
        "../implementation/p1/c13/synthetic-skill-catalog.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.equal(
    skill.tenants.every(({ releases }) =>
      releases.some(
        (entry) =>
          entry.manifest.name === "analyze-synthetic-order" &&
          entry.manifest.version ===
            bindings.dependencies.find(
              ({ workPackage }) => workPackage === "C13",
            ).version &&
          entry.contentSha256 ===
            bindings.dependencies.find(
              ({ workPackage }) => workPackage === "C13",
            ).bindingSha256,
      ),
    ),
    true,
  );
  const modelCatalog = JSON.parse(
    await readFile(
      new URL(
        "../implementation/p1/c14/synthetic-model-catalog.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  for (const task of catalog.tasks) {
    assert.equal(
      modelCatalog.models.some(
        (model) =>
          model.modelRef === task.bindings.reviewModel.ref &&
          model.version === task.bindings.reviewModel.version &&
          model.contentSha256 === task.bindings.reviewModel.sha256,
      ),
      true,
    );
  }

  const c08 = bindings.dependencies.find(
    ({ workPackage }) => workPackage === "C08",
  );
  const c08Evidence = JSON.parse(
    await readFile(new URL(`../${c08.path}`, import.meta.url), "utf8"),
  );
  assert.equal(c08Evidence.verification_status, "VERIFIED");
  assert.equal(c08Evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(
    c08Evidence.production_verification_status,
    "NOT_VERIFIED",
  );
  const c08Artifacts = new Map(
    c08Evidence.artifacts.map(({ path, sha256 }) => [path, sha256]),
  );
  assert.equal(c08Artifacts.get(c08.ref), c08.bindingSha256);
  assert.equal(
    c08Artifacts.get(c08.runManifestRef),
    c08.runManifestSha256,
  );
  const c08Api = JSON.parse(
    await readFile(new URL(`../${c08.ref}`, import.meta.url), "utf8"),
  );
  assert.equal(c08Api.info.version, c08.version);
  assert.equal(c08Api["x-c08-boundary"].orchestration_owner, "C12");
  assert.equal(
    c08Api["x-c08-boundary"].owned_state.includes("Checkpoint"),
    false,
  );
});

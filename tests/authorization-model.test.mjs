import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function load(path) {
  return JSON.parse(
    await readFile(new URL(`../${path}`, import.meta.url), "utf8"),
  );
}

function typeMap(model) {
  return new Map(
    model.type_definitions.map((definition) => [
      definition.type,
      definition,
    ]),
  );
}

test("the C06 OpenFGA model contains only the frozen subject and resource types", async () => {
  const model = await load(
    "implementation/p1/c06/openfga/authorization-model.v1.json",
  );

  assert.equal(model.schema_version, "1.1");
  assert.deepEqual(
    model.type_definitions.map(({ type }) => type),
    [
      "human",
      "workload",
      "purpose_scope",
      "protected_resource",
      "tool_operation",
      "sandbox_profile",
    ],
  );
});

test("every protected operation maps Human, Actor and purpose to direct typed relations", async () => {
  const model = await load(
    "implementation/p1/c06/openfga/authorization-model.v1.json",
  );
  const operations = await load(
    "implementation/p1/c06/protected-operations.v1.json",
  );
  const definitions = typeMap(model);
  const expectedSubjectType = {
    human_relation: "human",
    actor_relation: "workload",
    purpose_relation: "purpose_scope",
  };

  for (const operation of operations.operations) {
    const definition = definitions.get(operation.resource_type);
    assert.ok(definition, `${operation.resource_type} must exist`);
    for (const [field, subjectType] of Object.entries(expectedSubjectType)) {
      const relation = operation[field];
      assert.deepEqual(
        definition.relations[relation],
        { this: {} },
        `${operation.surface}.${relation} must be direct`,
      );
      assert.deepEqual(
        definition.metadata.relations[relation]
          .directly_related_user_types,
        [{ type: subjectType }],
        `${operation.surface}.${relation} must accept only ${subjectType}`,
      );
    }
  }
});

test("the model freezes exactly 18 direct relationships", async () => {
  const model = await load(
    "implementation/p1/c06/openfga/authorization-model.v1.json",
  );

  const resourceDefinitions = model.type_definitions.filter(
    ({ relations }) => relations,
  );
  const relationCount = resourceDefinitions.reduce(
    (count, definition) => count + Object.keys(definition.relations).length,
    0,
  );

  assert.equal(relationCount, 18);
  for (const definition of resourceDefinitions) {
    assert.deepEqual(
      Object.keys(definition.relations).sort(),
      Object.keys(definition.metadata.relations).sort(),
    );
  }
});

test("the authorization model does not encode enterprise identities or application roles", async () => {
  const model = await load(
    "implementation/p1/c06/openfga/authorization-model.v1.json",
  );
  const serialized = JSON.stringify(model).toLowerCase();

  for (const forbidden of [
    "email",
    "department",
    "employee",
    "group",
    "portal",
    "role",
    "skill",
    "mcp",
    "allowed_tools",
  ]) {
    assert.equal(
      serialized.includes(forbidden),
      false,
      `${forbidden} belongs outside the frozen C06 model`,
    );
  }
});

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { validateF04ArchitectureThreatCrosswalk } from "../scripts/validate-f04-architecture-threat-crosswalk.mjs";

const root = new URL("../", import.meta.url);

async function readJson(relativePath) {
  return JSON.parse(await readFile(new URL(relativePath, root), "utf8"));
}

test("F04 architecture-to-case crosswalk is closed with zero unmapped records", async () => {
  const inventory = await readJson(
    "implementation/p0/f04/architecture-inventory.v1.json",
  );
  const crosswalk = await readJson(
    "implementation/p0/f04/architecture-threat-crosswalk.v1.json",
  );

  const result = validateF04ArchitectureThreatCrosswalk(inventory, crosswalk);

  assert.equal(result.status, "PASS");
  assert.deepEqual(result.errors, []);
  assert.equal(result.unmapped_count, 0);
  assert.deepEqual(result.unmapped, {
    architecture_component_ids: [],
    asset_ids: [],
    trust_boundary_ids: [],
    data_flow_ids: [],
    threat_ids: [],
    case_ids: [],
  });
  assert.deepEqual(result.counts, {
    architecture_components: 9,
    assets: 7,
    trust_boundaries: 7,
    data_flows: 10,
    threats: 10,
    cases: 10,
    mappings: 10,
  });
});

test("F04 validator fails closed when one required mapping is deleted", async () => {
  const inventory = await readJson(
    "implementation/p0/f04/architecture-inventory.v1.json",
  );
  const crosswalk = await readJson(
    "implementation/p0/f04/architecture-threat-crosswalk.v1.json",
  );
  const incomplete = structuredClone(crosswalk);
  incomplete.mappings = incomplete.mappings.filter(
    ({ mapping_id }) => mapping_id !== "F04-MAP-010",
  );

  const result = validateF04ArchitectureThreatCrosswalk(inventory, incomplete);

  assert.equal(result.status, "FAIL");
  assert.ok(result.unmapped_count > 0);
  assert.deepEqual(result.unmapped.data_flow_ids, ["F04-DF-010"]);
  assert.deepEqual(result.unmapped.threat_ids, ["F04-THR-010"]);
  assert.deepEqual(result.unmapped.case_ids, ["F04-E010"]);
  assert.ok(
    result.errors.some((error) =>
      error.includes("each required case must have exactly one mapping"),
    ),
  );
});

test("F04 crosswalk must reference the registered architecture inventory", async () => {
  const inventory = await readJson(
    "implementation/p0/f04/architecture-inventory.v1.json",
  );
  const crosswalk = await readJson(
    "implementation/p0/f04/architecture-threat-crosswalk.v1.json",
  );
  const wrongReference = structuredClone(crosswalk);
  wrongReference.inventory_ref =
    "implementation/p0/f04/missing-architecture-inventory.json";

  const result = validateF04ArchitectureThreatCrosswalk(
    inventory,
    wrongReference,
  );

  assert.equal(result.status, "FAIL");
  assert.ok(
    result.errors.includes(
      "crosswalk must reference architecture-inventory.v1.json",
    ),
  );
});

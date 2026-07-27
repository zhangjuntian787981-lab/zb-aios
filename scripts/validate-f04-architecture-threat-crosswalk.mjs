#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const APPROVED_PLAN_BASELINE = {
  path: "docs/plans/通用多企业AI员工平台_完备工程级方案_v5.3.md",
  sha256:
    "sha256:bae704aa9fc8cf4275b8d85f8593139f1d83f8913c03d330227690eea98d43f3",
};

const REQUIRED_F04_CASE_IDS = Array.from(
  { length: 10 },
  (_, index) => `F04-E${String(index + 1).padStart(3, "0")}`,
);
const ARCHITECTURE_INVENTORY_REF =
  "implementation/p0/f04/architecture-inventory.v1.json";

function entries(value, key, errors) {
  if (!Array.isArray(value?.[key])) {
    errors.push(`${key} must be an array`);
    return [];
  }
  return value[key];
}

function ids(records, key = "id") {
  return records.map((record) => record?.[key]).filter(Boolean);
}

function validateUniqueStableIds(records, key, pattern, label, errors) {
  const values = ids(records, key);
  if (values.length !== records.length) {
    errors.push(`${label} must have a stable ID`);
  }
  if (new Set(values).size !== values.length) {
    errors.push(`${label} IDs must be unique`);
  }
  for (const value of values) {
    if (!pattern.test(value)) {
      errors.push(`${label} has invalid stable ID: ${value}`);
    }
  }
}

function validateBaseline(artifact, label, errors) {
  if (
    artifact?.approved_plan_baseline?.path !== APPROVED_PLAN_BASELINE.path ||
    artifact?.approved_plan_baseline?.sha256 !==
      APPROVED_PLAN_BASELINE.sha256
  ) {
    errors.push(`${label} must bind the exact approved v5.3 SHA-256`);
  }
}

function countBy(values) {
  const counts = new Map();
  for (const value of values) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return counts;
}

function missingFrom(allIds, mappedIds) {
  const mapped = new Set(mappedIds);
  return allIds.filter((id) => !mapped.has(id)).sort();
}

export function validateF04ArchitectureThreatCrosswalk(
  inventory,
  crosswalk,
) {
  const errors = [];
  validateBaseline(inventory, "inventory", errors);
  validateBaseline(crosswalk, "crosswalk", errors);
  if (crosswalk?.inventory_ref !== ARCHITECTURE_INVENTORY_REF) {
    errors.push("crosswalk must reference architecture-inventory.v1.json");
  }

  if (
    inventory?.scope !== "P0_P2_SYNTHETIC_ONLY" ||
    crosswalk?.scope !== "P0_P2_SYNTHETIC_ONLY" ||
    inventory?.enterprise_data_used !== false ||
    crosswalk?.enterprise_data_used !== false
  ) {
    errors.push("inventory and crosswalk must remain Synthetic-only");
  }

  const components = entries(
    inventory,
    "architecture_components",
    errors,
  );
  const assets = entries(inventory, "assets", errors);
  const boundaries = entries(inventory, "trust_boundaries", errors);
  const flows = entries(inventory, "data_flows", errors);
  const threats = entries(crosswalk, "threats", errors);
  const mappings = entries(crosswalk, "mappings", errors);

  validateUniqueStableIds(
    components,
    "id",
    /^F04-CMP-\d{3}$/,
    "architecture component",
    errors,
  );
  validateUniqueStableIds(
    assets,
    "id",
    /^F04-AST-\d{3}$/,
    "asset",
    errors,
  );
  validateUniqueStableIds(
    boundaries,
    "id",
    /^F04-TB-\d{3}$/,
    "trust boundary",
    errors,
  );
  validateUniqueStableIds(
    flows,
    "id",
    /^F04-DF-\d{3}$/,
    "data flow",
    errors,
  );
  validateUniqueStableIds(
    threats,
    "id",
    /^F04-THR-\d{3}$/,
    "threat",
    errors,
  );
  validateUniqueStableIds(
    mappings,
    "mapping_id",
    /^F04-MAP-\d{3}$/,
    "mapping",
    errors,
  );

  const componentIds = ids(components);
  const assetIds = ids(assets);
  const boundaryIds = ids(boundaries);
  const flowIds = ids(flows);
  const threatIds = ids(threats);
  const componentIdSet = new Set(componentIds);
  const assetIdSet = new Set(assetIds);
  const boundaryIdSet = new Set(boundaryIds);
  const flowIdSet = new Set(flowIds);
  const threatIdSet = new Set(threatIds);

  for (const asset of assets) {
    if (!Array.isArray(asset.component_ids) || asset.component_ids.length === 0) {
      errors.push(`${asset.id} must reference at least one component`);
      continue;
    }
    for (const componentId of asset.component_ids) {
      if (!componentIdSet.has(componentId)) {
        errors.push(`${asset.id} references missing component ${componentId}`);
      }
    }
  }

  for (const boundary of boundaries) {
    if (
      !Array.isArray(boundary.trusted_component_ids) ||
      boundary.trusted_component_ids.length === 0
    ) {
      errors.push(`${boundary.id} must reference at least one component`);
      continue;
    }
    for (const componentId of boundary.trusted_component_ids) {
      if (!componentIdSet.has(componentId)) {
        errors.push(
          `${boundary.id} references missing component ${componentId}`,
        );
      }
    }
  }

  const flowById = new Map(flows.map((flow) => [flow.id, flow]));
  const assetById = new Map(assets.map((asset) => [asset.id, asset]));
  const boundaryById = new Map(
    boundaries.map((boundary) => [boundary.id, boundary]),
  );
  for (const flow of flows) {
    if (!componentIdSet.has(flow.component_id)) {
      errors.push(`${flow.id} references missing component ${flow.component_id}`);
    }
    if (!assetIdSet.has(flow.asset_id)) {
      errors.push(`${flow.id} references missing asset ${flow.asset_id}`);
    }
    if (!boundaryIdSet.has(flow.trust_boundary_id)) {
      errors.push(
        `${flow.id} references missing trust boundary ${flow.trust_boundary_id}`,
      );
    }
    if (
      assetById.has(flow.asset_id) &&
      !assetById.get(flow.asset_id).component_ids.includes(flow.component_id)
    ) {
      errors.push(`${flow.id} component is not registered for ${flow.asset_id}`);
    }
    if (
      boundaryById.has(flow.trust_boundary_id) &&
      !boundaryById
        .get(flow.trust_boundary_id)
        .trusted_component_ids.includes(flow.component_id)
    ) {
      errors.push(
        `${flow.id} component is not registered for ${flow.trust_boundary_id}`,
      );
    }
  }

  const threatById = new Map(threats.map((threat) => [threat.id, threat]));
  const threatCaseIds = ids(threats, "case_id").sort();
  if (
    threatCaseIds.length !== REQUIRED_F04_CASE_IDS.length ||
    threatCaseIds.some(
      (caseId, index) => caseId !== REQUIRED_F04_CASE_IDS[index],
    )
  ) {
    errors.push("threats must cover F04-E001 through F04-E010 exactly once");
  }

  for (const mapping of mappings) {
    if (!componentIdSet.has(mapping.architecture_component_id)) {
      errors.push(
        `${mapping.mapping_id} references missing component ${mapping.architecture_component_id}`,
      );
    }
    if (!assetIdSet.has(mapping.asset_id)) {
      errors.push(
        `${mapping.mapping_id} references missing asset ${mapping.asset_id}`,
      );
    }
    if (!boundaryIdSet.has(mapping.trust_boundary_id)) {
      errors.push(
        `${mapping.mapping_id} references missing trust boundary ${mapping.trust_boundary_id}`,
      );
    }
    if (!flowIdSet.has(mapping.data_flow_id)) {
      errors.push(
        `${mapping.mapping_id} references missing data flow ${mapping.data_flow_id}`,
      );
    }
    if (!threatIdSet.has(mapping.threat_id)) {
      errors.push(
        `${mapping.mapping_id} references missing threat ${mapping.threat_id}`,
      );
    }

    const flow = flowById.get(mapping.data_flow_id);
    if (
      flow &&
      (flow.component_id !== mapping.architecture_component_id ||
        flow.asset_id !== mapping.asset_id ||
        flow.trust_boundary_id !== mapping.trust_boundary_id)
    ) {
      errors.push(`${mapping.mapping_id} does not match its data-flow chain`);
    }
    const threat = threatById.get(mapping.threat_id);
    if (threat && threat.case_id !== mapping.case_id) {
      errors.push(`${mapping.mapping_id} does not match its threat case`);
    }
  }

  const mappingCaseCounts = countBy(ids(mappings, "case_id"));
  if (
    REQUIRED_F04_CASE_IDS.some(
      (caseId) => mappingCaseCounts.get(caseId) !== 1,
    )
  ) {
    errors.push("each required case must have exactly one mapping");
  }

  const unmapped = {
    architecture_component_ids: missingFrom(
      componentIds,
      ids(mappings, "architecture_component_id"),
    ),
    asset_ids: missingFrom(assetIds, ids(mappings, "asset_id")),
    trust_boundary_ids: missingFrom(
      boundaryIds,
      ids(mappings, "trust_boundary_id"),
    ),
    data_flow_ids: missingFrom(flowIds, ids(mappings, "data_flow_id")),
    threat_ids: missingFrom(threatIds, ids(mappings, "threat_id")),
    case_ids: missingFrom(
      REQUIRED_F04_CASE_IDS,
      ids(mappings, "case_id"),
    ),
  };
  const unmappedCount = Object.values(unmapped).reduce(
    (total, values) => total + values.length,
    0,
  );
  if (unmappedCount > 0) {
    errors.push(`crosswalk has ${unmappedCount} unmapped records`);
  }

  return {
    status: errors.length === 0 ? "PASS" : "FAIL",
    errors,
    unmapped_count: unmappedCount,
    unmapped,
    counts: {
      architecture_components: components.length,
      assets: assets.length,
      trust_boundaries: boundaries.length,
      data_flows: flows.length,
      threats: threats.length,
      cases: new Set(ids(threats, "case_id")).size,
      mappings: mappings.length,
    },
  };
}

async function runCli() {
  const inventoryPath =
    process.argv[2] ?? "implementation/p0/f04/architecture-inventory.v1.json";
  const crosswalkPath =
    process.argv[3] ??
    "implementation/p0/f04/architecture-threat-crosswalk.v1.json";
  const [inventory, crosswalk] = await Promise.all([
    readFile(inventoryPath, "utf8").then(JSON.parse),
    readFile(crosswalkPath, "utf8").then(JSON.parse),
  ]);
  const result = validateF04ArchitectureThreatCrosswalk(inventory, crosswalk);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.status === "PASS" ? 0 : 1;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await runCli();
}

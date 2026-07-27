#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const DEFAULT_INVENTORY_PATH =
  "implementation/p0/f02/protected-surface-inventory.v1.json";
const DEFAULT_POLICY_PATH =
  "implementation/p0/f02/protected-surface-policy.v2.json";
const VALID_STAGES = new Set(["PREBUILD", "RELEASE", "ALL"]);
const EXPECTED_SURFACES = Object.freeze({
  SOURCE_CODE: Object.freeze({
    stage: "PREBUILD",
    syntheticMarkerRequired: false,
  }),
  SYNTHETIC_FIXTURES: Object.freeze({
    stage: "PREBUILD",
    syntheticMarkerRequired: true,
  }),
  EVALUATION_GROUND_TRUTH: Object.freeze({
    stage: "PREBUILD",
    syntheticMarkerRequired: true,
  }),
  RUNTIME_STORE: Object.freeze({
    stage: "PREBUILD",
    syntheticMarkerRequired: true,
  }),
  RUNTIME_LOG: Object.freeze({
    stage: "PREBUILD",
    syntheticMarkerRequired: true,
  }),
  TRACE: Object.freeze({
    stage: "PREBUILD",
    syntheticMarkerRequired: true,
  }),
  RELEASE_PACKAGE: Object.freeze({
    stage: "RELEASE",
    syntheticMarkerRequired: false,
  }),
});
const EXPECTED_CONTENT_RULES = Object.freeze([
  "ENTERPRISE_IDENTIFIER",
  "TOKEN",
  "PRIVATE_KEY",
  "CONNECTION_STRING",
]);

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function pathIsWithin(parentPath, childPath) {
  const relative = path.relative(parentPath, childPath);
  return (
    relative === "" ||
    (!relative.startsWith("..") && !path.isAbsolute(relative))
  );
}

async function collectDirectoryFiles(rootPath) {
  const files = [];
  for (const entry of (
    await readdir(rootPath, { withFileTypes: true })
  ).sort((left, right) => left.name.localeCompare(right.name))) {
    const entryPath = path.join(rootPath, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectDirectoryFiles(entryPath)));
    } else if (entry.isFile()) {
      files.push(entryPath);
    }
  }
  return files;
}

function matchesDirectoryRule(filePath, rule) {
  if (
    Array.isArray(rule.include_extensions) &&
    !rule.include_extensions.includes(path.extname(filePath))
  ) {
    return false;
  }
  if (
    rule.filename_regex &&
    !new RegExp(rule.filename_regex).test(path.basename(filePath))
  ) {
    return false;
  }
  if (
    rule.exclude_path_regex &&
    new RegExp(rule.exclude_path_regex).test(filePath)
  ) {
    return false;
  }
  return true;
}

function addFinding(findings, surfaceId, document, code, ruleId) {
  findings.push({
    surface_id: surfaceId,
    document,
    code,
    rule_id: ruleId,
  });
}

function validateConfiguration(inventory, policy) {
  if (
    inventory?.schema_version !== "1.0.0" ||
    inventory.scope !== "P0_P2_SYNTHETIC_ONLY" ||
    inventory.enterprise_data_used !== false ||
    !Array.isArray(inventory.protected_surfaces) ||
    policy?.policy_version !== "2.0.0" ||
    policy.classification !== "F02_PROTECTED_SURFACE_POLICY" ||
    policy.scope !== "P0_P2_SYNTHETIC_ONLY" ||
    typeof policy.synthetic_marker_regex !== "string" ||
    policy.synthetic_marker_regex.length === 0 ||
    typeof policy.assurance_limit !== "string" ||
    policy.assurance_limit.length === 0 ||
    !Array.isArray(policy.content_rules)
  ) {
    throw new Error("F02 protected-surface configuration is invalid");
  }
  const surfaces = new Map();
  for (const surface of inventory.protected_surfaces) {
    if (
      typeof surface?.id !== "string" ||
      surfaces.has(surface.id)
    ) {
      throw new Error("F02 protected-surface IDs must be unique");
    }
    surfaces.set(surface.id, surface);
  }
  if (
    surfaces.size !== Object.keys(EXPECTED_SURFACES).length ||
    Object.entries(EXPECTED_SURFACES).some(
      ([surfaceId, expected]) => {
        const surface = surfaces.get(surfaceId);
        return (
          !surface ||
          surface.stage !== expected.stage ||
          surface.synthetic_marker_required !==
            expected.syntheticMarkerRequired ||
          !(
            (Array.isArray(surface.files) &&
              surface.files.length > 0) ||
            (Array.isArray(surface.directories) &&
              surface.directories.length > 0)
          )
        );
      },
    )
  ) {
    throw new Error("F02 protected-surface inventory is not closed");
  }
  if (
    policy.content_rules.length !== EXPECTED_CONTENT_RULES.length ||
    policy.content_rules.some(
      (rule, index) =>
        rule?.id !== EXPECTED_CONTENT_RULES[index] ||
        typeof rule.category !== "string" ||
        typeof rule.regex !== "string" ||
        rule.regex.length === 0,
    )
  ) {
    throw new Error("F02 protected-surface content rules are not closed");
  }
}

async function resolveSurfaceFiles(repositoryRoot, surface, findings) {
  const root = path.resolve(repositoryRoot);
  const files = [];

  for (const relativePath of surface.files ?? []) {
    const absolutePath = path.resolve(root, relativePath);
    if (!pathIsWithin(root, absolutePath)) {
      addFinding(
        findings,
        surface.id,
        relativePath,
        "INVALID_SURFACE_PATH",
        "REPOSITORY_ROOT_CONTAINMENT",
      );
      continue;
    }
    try {
      await readFile(absolutePath);
      files.push(absolutePath);
    } catch {
      addFinding(
        findings,
        surface.id,
        relativePath,
        "SURFACE_FILE_MISSING",
        "REGISTERED_FILE_REQUIRED",
      );
    }
  }

  for (const rule of surface.directories ?? []) {
    const directoryPath = path.resolve(root, rule.path);
    if (!pathIsWithin(root, directoryPath)) {
      addFinding(
        findings,
        surface.id,
        rule.path,
        "INVALID_SURFACE_PATH",
        "REPOSITORY_ROOT_CONTAINMENT",
      );
      continue;
    }
    try {
      const directoryFiles = await collectDirectoryFiles(directoryPath);
      files.push(
        ...directoryFiles.filter((filePath) =>
          matchesDirectoryRule(
            path.relative(root, filePath).split(path.sep).join("/"),
            rule,
          ),
        ),
      );
    } catch {
      addFinding(
        findings,
        surface.id,
        rule.path,
        "SURFACE_DIRECTORY_MISSING",
        "REGISTERED_DIRECTORY_REQUIRED",
      );
    }
  }

  const uniqueFiles = [...new Set(files)].sort((left, right) =>
    left.localeCompare(right),
  );
  if (uniqueFiles.length === 0) {
    addFinding(
      findings,
      surface.id,
      "$",
      "SURFACE_HAS_NO_FILES",
      "NON_EMPTY_REGISTERED_SURFACE",
    );
  }
  return uniqueFiles;
}

export async function scanProtectedSurfaceInventory({
  repositoryRoot,
  inventory,
  policy,
  stage = "ALL",
}) {
  if (!VALID_STAGES.has(stage)) {
    throw new Error(`Unsupported protected-surface stage: ${stage}`);
  }
  validateConfiguration(inventory, policy);

  const findings = [];
  const selectedSurfaces = inventory.protected_surfaces.filter(
    (surface) => stage === "ALL" || surface.stage === stage,
  );
  const receipts = [];
  let syntheticMarkerRequiredFileCount = 0;
  let syntheticMarkerMissingFileCount = 0;
  const syntheticMarker = new RegExp(policy.synthetic_marker_regex, "i");

  for (const surface of selectedSurfaces) {
    const files = await resolveSurfaceFiles(
      repositoryRoot,
      surface,
      findings,
    );
    const fileReceipts = [];

    for (const filePath of files) {
      const contents = await readFile(filePath);
      const text = contents.toString("utf8");
      const relativePath = path
        .relative(path.resolve(repositoryRoot), filePath)
        .split(path.sep)
        .join("/");

      if (surface.synthetic_marker_required) {
        syntheticMarkerRequiredFileCount += 1;
        if (!syntheticMarker.test(text)) {
          syntheticMarkerMissingFileCount += 1;
          addFinding(
            findings,
            surface.id,
            relativePath,
            "MISSING_SYNTHETIC_MARKER",
            "SYNTHETIC_MARKER",
          );
        }
      }

      for (const rule of policy.content_rules) {
        if (new RegExp(rule.regex, "i").test(text)) {
          addFinding(
            findings,
            surface.id,
            relativePath,
            "ENTERPRISE_DATA_OR_CREDENTIAL",
            rule.id,
          );
        }
      }

      fileReceipts.push({
        path: relativePath,
        sha256: sha256(contents),
      });
    }

    const digestInput = fileReceipts
      .map(({ path: filePath, sha256: digest }) => `${filePath}\0${digest}\n`)
      .join("");
    receipts.push({
      surface_id: surface.id,
      stage: surface.stage,
      synthetic_marker_required: surface.synthetic_marker_required,
      scanned_file_count: fileReceipts.length,
      aggregate_sha256: sha256(digestInput),
    });
  }

  findings.sort((left, right) =>
    `${left.surface_id}:${left.document}:${left.code}:${left.rule_id}`.localeCompare(
      `${right.surface_id}:${right.document}:${right.code}:${right.rule_id}`,
    ),
  );
  const enterpriseDataOrCredentialFindingCount = findings.filter(
    ({ code }) => code === "ENTERPRISE_DATA_OR_CREDENTIAL",
  ).length;

  return {
    schema_version: "1.0.0",
    scope: "P0_P2_SYNTHETIC_ONLY",
    stage,
    status: findings.length === 0 ? "PASS" : "BLOCKED",
    surface_count: selectedSurfaces.length,
    scanned_file_count: receipts.reduce(
      (total, receipt) => total + receipt.scanned_file_count,
      0,
    ),
    synthetic_marker_required_file_count:
      syntheticMarkerRequiredFileCount,
    synthetic_marker_missing_file_count: syntheticMarkerMissingFileCount,
    enterprise_data_or_credential_finding_count:
      enterpriseDataOrCredentialFindingCount,
    findings,
    surface_receipts: receipts,
    assurance_limit: policy.assurance_limit,
  };
}

async function runCli() {
  const stageIndex = process.argv.indexOf("--stage");
  const stage = stageIndex === -1 ? "ALL" : process.argv[stageIndex + 1];
  const repositoryRoot = process.cwd();
  const [inventory, policy] = await Promise.all([
    readFile(path.join(repositoryRoot, DEFAULT_INVENTORY_PATH), "utf8").then(
      JSON.parse,
    ),
    readFile(path.join(repositoryRoot, DEFAULT_POLICY_PATH), "utf8").then(
      JSON.parse,
    ),
  ]);
  const result = await scanProtectedSurfaceInventory({
    repositoryRoot,
    inventory,
    policy,
    stage,
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.status === "PASS" ? 0 : 1;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await runCli();
}

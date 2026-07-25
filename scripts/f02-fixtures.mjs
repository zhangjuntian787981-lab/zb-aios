import { createHash } from "node:crypto";
import {
  mkdir,
  readFile,
  readFileSync,
  readdir,
  writeFile,
} from "node:fs";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";

const mkdirAsync = promisify(mkdir);
const readFileAsync = promisify(readFile);
const readdirAsync = promisify(readdir);
const writeFileAsync = promisify(writeFile);

const F02_ROOT = new URL("../implementation/p0/f02/", import.meta.url);
const GENERATED_AT = "2026-07-26T00:00:00.000Z";
const WATERMARK = "SYNTHETIC";

const seedCatalog = JSON.parse(
  readFileSync(new URL("seed-catalog.v1.json", F02_ROOT), "utf8"),
);
const defaultPolicy = JSON.parse(
  readFileSync(new URL("protected-surface-policy.v1.json", F02_ROOT), "utf8"),
);

function jsonText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function fixtureHash(value) {
  return sha256(jsonText(value));
}

function seededInteger(seed, offset, minimum, maximum) {
  let state = (seed + offset) >>> 0;
  state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
  return minimum + (state % (maximum - minimum + 1));
}

function record(tenantId, values) {
  return {
    ...values,
    tenant_id: tenantId,
    watermark: WATERMARK,
  };
}

function buildTenantFixture(seed) {
  const tenantId = `tenant-${seed.tenant_slug}`;
  const prefix = seed.tenant_slug;
  const salesOrgId = `${prefix}-org-sales`;
  const operationsOrgId = `${prefix}-org-operations`;
  const salesUserId = `${prefix}-user-ava`;
  const operationsUserId = `${prefix}-user-noah`;
  const qualityUserId = `${prefix}-user-mia`;

  return {
    schema_version: "1.0",
    fixture_id: `synthetic-tenant-${seed.tenant_slug}`,
    seed_id: seed.seed_id,
    watermark: WATERMARK,
    provenance: {
      kind: "GENERATED_SYNTHETIC",
      generator: "scripts/f02-fixtures.mjs",
      numeric_seed: seed.numeric_seed,
      generated_at: GENERATED_AT,
      enterprise_data_used: false,
    },
    tenant: {
      id: tenantId,
      display_name: seed.tenant_name,
      domain: seed.domain,
      watermark: WATERMARK,
    },
    records: {
      org_units: [
        record(tenantId, {
          id: salesOrgId,
          name: "Synthetic Sales",
          parent_id: null,
        }),
        record(tenantId, {
          id: operationsOrgId,
          name: "Synthetic Operations",
          parent_id: null,
        }),
      ],
      users: [
        record(tenantId, {
          id: salesUserId,
          org_unit_id: salesOrgId,
          display_name: "Ava Example",
          email: `ava@${seed.domain}`,
          role: "sales_analyst",
        }),
        record(tenantId, {
          id: operationsUserId,
          org_unit_id: operationsOrgId,
          display_name: "Noah Example",
          email: `noah@${seed.domain}`,
          role: "operations_planner",
        }),
        record(tenantId, {
          id: qualityUserId,
          org_unit_id: operationsOrgId,
          display_name: "Mia Example",
          email: `mia@${seed.domain}`,
          role: "quality_reviewer",
        }),
      ],
      knowledge: [
        record(tenantId, {
          id: `${prefix}-knowledge-catalog`,
          visibility_org_unit_id: salesOrgId,
          title: "Synthetic product catalog",
          body: "Fictional catalog entries for deterministic fixture tests.",
          source_kind: "SYNTHETIC_GENERATOR",
        }),
        record(tenantId, {
          id: `${prefix}-knowledge-quality`,
          visibility_org_unit_id: operationsOrgId,
          title: "Synthetic quality checklist",
          body: "Fictional inspection steps for deterministic fixture tests.",
          source_kind: "SYNTHETIC_GENERATOR",
        }),
      ],
      permissions: [
        record(tenantId, {
          id: `${prefix}-permission-sales-read`,
          subject_id: salesUserId,
          resource: "knowledge:catalog",
          action: "read",
          effect: "allow",
        }),
        record(tenantId, {
          id: `${prefix}-permission-operations-run`,
          subject_id: operationsUserId,
          resource: "workflow:planning",
          action: "run",
          effect: "allow",
        }),
        record(tenantId, {
          id: `${prefix}-permission-quality-review`,
          subject_id: qualityUserId,
          resource: "workflow:quality",
          action: "review",
          effect: "allow",
        }),
      ],
      workflows: [
        record(tenantId, {
          id: `${prefix}-workflow-inquiry`,
          owner_user_id: salesUserId,
          name: "Synthetic inquiry review",
          states: ["received", "reviewed", "closed"],
        }),
        record(tenantId, {
          id: `${prefix}-workflow-quality`,
          owner_user_id: qualityUserId,
          name: "Synthetic quality review",
          states: ["queued", "checked", "approved"],
        }),
      ],
      metrics: [
        record(tenantId, {
          id: `${prefix}-metric-inquiries`,
          org_unit_id: salesOrgId,
          metric_key: "synthetic_inquiries",
          value: seededInteger(seed.numeric_seed, 1, 20, 80),
          unit: "count",
          period: "2026-07",
        }),
        record(tenantId, {
          id: `${prefix}-metric-yield`,
          org_unit_id: operationsOrgId,
          metric_key: "synthetic_first_pass_yield",
          value: seededInteger(seed.numeric_seed, 2, 850, 970) / 10,
          unit: "percent",
          period: "2026-07",
        }),
      ],
      connector_responses: [
        record(tenantId, {
          id: `${prefix}-connector-erp`,
          requested_by_user_id: operationsUserId,
          connector_kind: "ERP_TEMPLATE",
          endpoint: `https://erp.${seed.domain}/synthetic/orders`,
          response_mode: WATERMARK,
          result_summary: "Two fictional open orders returned.",
        }),
        record(tenantId, {
          id: `${prefix}-connector-bi`,
          requested_by_user_id: salesUserId,
          connector_kind: "BI_TEMPLATE",
          endpoint: `https://bi.${seed.domain}/synthetic/metrics`,
          response_mode: WATERMARK,
          result_summary: "Two fictional certified metrics returned.",
        }),
      ],
    },
  };
}

function assertSeedCatalog(catalog) {
  if (
    catalog.classification !== "SYNTHETIC_ONLY" ||
    catalog.enterprise_data_used !== false ||
    !Array.isArray(catalog.seeds) ||
    catalog.seeds.length !== 3
  ) {
    throw new Error("F02 seed catalog must contain exactly three synthetic-only seeds");
  }

  const ids = new Set();
  for (const seed of catalog.seeds) {
    if (
      ids.has(seed.seed_id) ||
      !Number.isInteger(seed.numeric_seed) ||
      !seed.domain.endsWith(".example")
    ) {
      throw new Error(`Invalid F02 seed: ${seed.seed_id ?? "unknown"}`);
    }
    ids.add(seed.seed_id);
  }
}

export function generateSyntheticTenants() {
  assertSeedCatalog(seedCatalog);
  return seedCatalog.seeds.map(buildTenantFixture);
}

export function buildFixtureInventory(fixtures) {
  return {
    inventory_version: "1.0",
    classification: "SYNTHETIC_ONLY",
    generated_by: "scripts/f02-fixtures.mjs",
    generated_at: GENERATED_AT,
    fixture_count: fixtures.length,
    fixtures: fixtures.map((fixture) => ({
      fixture_id: fixture.fixture_id,
      seed_id: fixture.seed_id,
      watermark: fixture.watermark,
      sha256: fixtureHash(fixture),
      record_counts: Object.fromEntries(
        Object.entries(fixture.records).map(([name, records]) => [
          name,
          records.length,
        ]),
      ),
    })),
  };
}

function addFinding(findings, documentPath, valuePath, code, rule) {
  findings.push({
    code,
    document: documentPath,
    path: valuePath,
    rule,
  });
}

function scanValue(value, valuePath, documentPath, policy, findings) {
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      scanValue(item, `${valuePath}[${index}]`, documentPath, policy, findings),
    );
    return;
  }

  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      const childPath = valuePath ? `${valuePath}.${key}` : key;
      for (const pattern of policy.credential_key_patterns) {
        if (new RegExp(pattern, "i").test(key)) {
          addFinding(
            findings,
            documentPath,
            childPath,
            "CREDENTIAL_KEY",
            pattern,
          );
        }
      }
      scanValue(child, childPath, documentPath, policy, findings);
    }
    return;
  }

  if (typeof value !== "string") {
    return;
  }

  for (const pattern of policy.credential_value_patterns) {
    if (new RegExp(pattern.regex, "i").test(value)) {
      addFinding(
        findings,
        documentPath,
        valuePath,
        "CREDENTIAL_VALUE",
        pattern.id,
      );
    }
  }

  for (const identifier of policy.forbidden_enterprise_identifiers) {
    if (value.toLowerCase().includes(identifier.toLowerCase())) {
      addFinding(
        findings,
        documentPath,
        valuePath,
        "FORBIDDEN_ENTERPRISE_IDENTIFIER",
        identifier,
      );
    }
  }

  if (value.includes(policy.public_context_marker)) {
    addFinding(
      findings,
      documentPath,
      valuePath,
      "PUBLIC_CONTEXT_IN_PROTECTED_SURFACE",
      policy.public_context_marker,
    );
  }
}

function scanWatermarks(content, documentPath, policy, findings) {
  if (!content || typeof content !== "object" || Array.isArray(content)) {
    return;
  }

  if (
    Object.hasOwn(content, "fixture_id") &&
    content.watermark !== policy.required_watermark
  ) {
    addFinding(
      findings,
      documentPath,
      "$",
      "MISSING_SYNTHETIC_WATERMARK",
      policy.required_watermark,
    );
  }

  if (
    content.tenant &&
    content.tenant.watermark !== policy.required_watermark
  ) {
    addFinding(
      findings,
      documentPath,
      "tenant",
      "MISSING_SYNTHETIC_WATERMARK",
      policy.required_watermark,
    );
  }

  if (!content.records || typeof content.records !== "object") {
    return;
  }

  for (const [collection, records] of Object.entries(content.records)) {
    if (!Array.isArray(records)) {
      addFinding(
        findings,
        documentPath,
        `records.${collection}`,
        "INVALID_RECORD_COLLECTION",
        "array-required",
      );
      continue;
    }
    records.forEach((item, index) => {
      if (
        !item ||
        typeof item !== "object" ||
        item.watermark !== policy.required_watermark
      ) {
        addFinding(
          findings,
          documentPath,
          `records.${collection}[${index}]`,
          "MISSING_SYNTHETIC_WATERMARK",
          policy.required_watermark,
        );
      }
    });
  }
}

export function scanProtectedSurface({
  documents,
  policy = defaultPolicy,
}) {
  const findings = [];

  for (const document of documents) {
    const content =
      typeof document.content === "string"
        ? document.content
        : document.content;
    scanValue(content, "$", document.path, policy, findings);
    scanWatermarks(content, document.path, policy, findings);
  }

  findings.sort((left, right) =>
    `${left.document}:${left.path}:${left.code}`.localeCompare(
      `${right.document}:${right.path}:${right.code}`,
    ),
  );

  return {
    report_version: "1.0",
    generated_at: GENERATED_AT,
    status: findings.length === 0 ? "PASS" : "BLOCKED",
    protected_surfaces: policy.protected_surfaces,
    scanned_documents: documents.length,
    findings,
    assurance_limit: policy.assurance_limit_en,
  };
}

function filesystemPath(value) {
  return value instanceof URL ? fileURLToPath(value) : path.resolve(value);
}

function pathIsWithin(parentPath, childPath) {
  const relative = path.relative(parentPath, childPath);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

async function collectFiles(rootPath) {
  const files = [];
  const entries = await readdirAsync(rootPath, { withFileTypes: true });

  for (const entry of entries.sort((left, right) =>
    left.name.localeCompare(right.name),
  )) {
    const entryPath = path.join(rootPath, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectFiles(entryPath)));
    } else if (entry.isFile()) {
      files.push(entryPath);
    }
  }

  return files;
}

async function packageContainsPublicContext(packageRoot, registry) {
  const findings = [];
  const markers = [
    "PUBLIC_EXTERNAL_CONTEXT",
    ...registry.entries.flatMap((entry) => [
      entry.id,
      entry.content_sha256,
      entry.artifact_path,
    ]),
  ];

  for (const filePath of await collectFiles(packageRoot)) {
    const contents = await readFileAsync(filePath, "utf8");
    if (markers.some((marker) => contents.includes(marker))) {
      findings.push({
        code: "PUBLIC_CONTEXT_IN_PRODUCT_PACKAGE",
        document: path.relative(packageRoot, filePath),
        path: "$",
        rule: "registry-content-must-not-be-packaged",
      });
    }
  }

  return findings;
}

export async function checkPublicContextContainment({
  registry,
  registryRoot,
  packageRoot,
}) {
  const findings = [];
  const resolvedRegistryRoot = filesystemPath(registryRoot);
  const resolvedPackageRoot = filesystemPath(packageRoot);

  if (pathIsWithin(resolvedPackageRoot, resolvedRegistryRoot)) {
    addFinding(
      findings,
      "public-context-registry",
      "$",
      "REGISTRY_INSIDE_PRODUCT_PACKAGE",
      "external-registry-only",
    );
  }

  if (
    registry.classification !== "PUBLIC_EXTERNAL_CONTEXT_REGISTRY" ||
    registry.packaging_policy !== "EXCLUDE_FROM_PRODUCT_PACKAGE" ||
    !Array.isArray(registry.entries)
  ) {
    addFinding(
      findings,
      "public-context-registry",
      "$",
      "INVALID_PUBLIC_CONTEXT_REGISTRY",
      "registry-contract-v1",
    );
  } else {
    for (const entry of registry.entries) {
      let validSource = false;
      try {
        const source = new URL(entry.source_url);
        validSource = source.protocol === "https:" || source.protocol === "http:";
      } catch {
        validSource = false;
      }

      if (
        entry.classification !== "PUBLIC_EXTERNAL_CONTEXT" ||
        !validSource ||
        !entry.source_title ||
        !entry.retrieved_at ||
        !/^sha256:[a-f0-9]{64}$/.test(entry.content_sha256 ?? "")
      ) {
        addFinding(
          findings,
          "public-context-registry",
          entry.id ?? "$",
          "INCOMPLETE_PUBLIC_CONTEXT_PROVENANCE",
          "public-context-entry-v1",
        );
        continue;
      }

      const artifactPath = path.resolve(
        resolvedRegistryRoot,
        entry.artifact_path,
      );
      if (!pathIsWithin(resolvedRegistryRoot, artifactPath)) {
        addFinding(
          findings,
          "public-context-registry",
          entry.id,
          "PUBLIC_CONTEXT_PATH_ESCAPE",
          "registry-root-containment",
        );
        continue;
      }

      try {
        const artifact = await readFileAsync(artifactPath);
        if (sha256(artifact) !== entry.content_sha256) {
          addFinding(
            findings,
            "public-context-registry",
            entry.id,
            "PUBLIC_CONTEXT_HASH_MISMATCH",
            "sha256",
          );
        }
      } catch {
        addFinding(
          findings,
          "public-context-registry",
          entry.id,
          "PUBLIC_CONTEXT_ARTIFACT_MISSING",
          entry.artifact_path,
        );
      }
    }

    findings.push(
      ...(await packageContainsPublicContext(resolvedPackageRoot, registry)),
    );
  }

  findings.sort((left, right) =>
    `${left.document}:${left.path}:${left.code}`.localeCompare(
      `${right.document}:${right.path}:${right.code}`,
    ),
  );

  return {
    report_version: "1.0",
    generated_at: GENERATED_AT,
    status: findings.length === 0 ? "PASS" : "BLOCKED",
    registry_classification: registry.classification,
    package_root: path.basename(resolvedPackageRoot),
    checked_entries: Array.isArray(registry.entries)
      ? registry.entries.length
      : 0,
    findings,
    assurance_limit:
      "Containment checks configured paths and markers only; a passing result does not prove the absence of enterprise data.",
  };
}

async function writeGeneratedFixtures(outputRoot) {
  const fixtures = generateSyntheticTenants();
  await mkdirAsync(outputRoot, { recursive: true });

  for (const fixture of fixtures) {
    await writeFileAsync(
      path.join(outputRoot, `${fixture.fixture_id}.json`),
      jsonText(fixture),
    );
  }
  await writeFileAsync(
    path.join(outputRoot, "fixture-inventory.v1.json"),
    jsonText(buildFixtureInventory(fixtures)),
  );
  return fixtures;
}

async function readProtectedDocuments(rootPath) {
  const documents = [];
  for (const filePath of await collectFiles(rootPath)) {
    const relativePath = path.relative(rootPath, filePath);
    const text = await readFileAsync(filePath, "utf8");
    let content = text;
    if (filePath.endsWith(".json")) {
      try {
        content = JSON.parse(text);
      } catch {
        content = text;
      }
    }
    documents.push({ path: relativePath, content });
  }
  return documents;
}

async function refreshEvidence() {
  const generatedRoot = fileURLToPath(new URL("generated/", F02_ROOT));
  const reportsRoot = fileURLToPath(new URL("reports/", F02_ROOT));
  const fixtures = await writeGeneratedFixtures(generatedRoot);
  await mkdirAsync(reportsRoot, { recursive: true });
  await writeFileAsync(
    fileURLToPath(new URL("fixture-inventory.v1.json", F02_ROOT)),
    jsonText(buildFixtureInventory(fixtures)),
  );

  const protectedReport = scanProtectedSurface({
    documents: fixtures.map((content) => ({
      path: `generated/${content.fixture_id}.json`,
      content,
    })),
  });
  await writeFileAsync(
    path.join(reportsRoot, "protected-surface-scan.sample.json"),
    jsonText(protectedReport),
  );

  const registry = JSON.parse(
    await readFileAsync(
      fileURLToPath(
        new URL("public-context-registry/registry.sample.json", F02_ROOT),
      ),
      "utf8",
    ),
  );
  const containmentReport = await checkPublicContextContainment({
    registry,
    registryRoot: new URL("public-context-registry/", F02_ROOT),
    packageRoot: generatedRoot,
  });
  await writeFileAsync(
    path.join(reportsRoot, "public-context-containment.sample.json"),
    jsonText(containmentReport),
  );
}

async function runCli(args) {
  const [command, ...values] = args;

  if (command === "generate" && values[0]) {
    await writeGeneratedFixtures(path.resolve(values[0]));
    return;
  }

  if (command === "scan" && values[0]) {
    const rootPath = path.resolve(values[0]);
    const result = scanProtectedSurface({
      documents: await readProtectedDocuments(rootPath),
    });
    console.log(jsonText(result));
    if (result.status !== "PASS") {
      process.exitCode = 1;
    }
    return;
  }

  if (command === "refresh-evidence") {
    await refreshEvidence();
    return;
  }

  throw new Error(
    "Usage: node scripts/f02-fixtures.mjs generate <output-dir> | scan <root> | refresh-evidence",
  );
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  await runCli(process.argv.slice(2));
}

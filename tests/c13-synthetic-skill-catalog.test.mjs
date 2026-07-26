import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createC13SyntheticSkillCatalog,
} from "../lib/c13-synthetic-skill-catalog.mjs";

const raw = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c13/synthetic-skill-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

test("C13 catalog is frozen to three Synthetic Tenants and the F04 suite", () => {
  const catalog = createC13SyntheticSkillCatalog(raw);
  assert.deepEqual(catalog.summary(), {
    tenantCount: 3,
    releaseCount: 4,
    suiteId: "f04-frozen-evaluation-suite-v1",
    suiteSha256:
      "sha256:628503bc3001d50d8eb30d89ce4f45e184918c63ba4fc0e8d3f6594d345a3259",
    scriptExecution: "DISABLED",
    allowedToolsGrantAuthorization: false,
  });
});

test("C13 catalog binds source review and evaluation to tenant, version and digest", () => {
  const catalog = createC13SyntheticSkillCatalog(raw);
  const tenant = raw.tenants[0];
  const release = tenant.releases[0];
  assert.equal(
    catalog.verifySource({
      tenantId: tenant.tenantId,
      manifest: release.manifest,
      contentSha256: release.contentSha256,
      sourceReviewRef: release.sourceReviewRef,
      sourceReviewSha256: release.sourceReviewSha256,
    }).contentSha256,
    release.contentSha256,
  );
  assert.equal(
    catalog.evaluate({
      tenantId: tenant.tenantId,
      name: release.manifest.name,
      version: release.manifest.version,
      contentSha256: release.contentSha256,
      suiteId: raw.frozenEvaluationSuite.suiteId,
      suiteSha256: raw.frozenEvaluationSuite.suiteSha256,
    }).status,
    "PASS",
  );
  assert.throws(
    () =>
      catalog.evaluate({
        tenantId: tenant.tenantId,
        name: release.manifest.name,
        version: release.manifest.version,
        contentSha256:
          "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        suiteId: raw.frozenEvaluationSuite.suiteId,
        suiteSha256: raw.frozenEvaluationSuite.suiteSha256,
      }),
    { code: "EVALUATION_UNAVAILABLE" },
  );
});

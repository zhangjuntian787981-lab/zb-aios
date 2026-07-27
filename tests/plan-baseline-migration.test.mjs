import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const planPath =
  "docs/plans/通用多企业AI员工平台_完备工程级方案_v5.1.md";
const planHash =
  "386a5778defc045dedf7c6b79a20e23111dde53f81485f4767a9c0ddd59e7cc0";
const migrationPath =
  "drizzle/0002_approve_v5_1_plan_baseline.sql";

test("the v5.1 approval migration appends one hash-bound revision without changing delivery state", async () => {
  const [plan, migration, journal] = await Promise.all([
    readFile(new URL(planPath, root)),
    readFile(new URL(migrationPath, root), "utf8"),
    readFile(new URL("drizzle/meta/_journal.json", root), "utf8").then(
      JSON.parse,
    ),
  ]);

  assert.equal(createHash("sha256").update(plan).digest("hex"), planHash);
  assert.equal(
    migration.match(/INSERT INTO `governance_events`/g)?.length,
    1,
  );
  assert.match(migration, /\n  64,\n  'PLAN_BASELINE_APPROVED',/);
  assert.match(migration, new RegExp(`sha256:${planHash}`));
  assert.match(
    migration,
    /approve-plan-baseline-v5\.1-386a5778/,
  );
  assert.doesNotMatch(migration, /\b(?:UPDATE|DELETE)\b/i);
  assert.equal(
    journal.entries.at(-1).tag,
    "0002_approve_v5_1_plan_baseline",
  );
});

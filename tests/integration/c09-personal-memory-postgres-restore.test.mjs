import assert from "node:assert/strict";
import test from "node:test";
import pg from "pg";

const { Pool } = pg;

function configuration() {
  if (process.env.C09_TEST_EPHEMERAL !== "1") {
    throw new Error("C09_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C09_TEST_PGHOST",
    "C09_TEST_PGPORT",
    "C09_TEST_PGDATABASE",
    "C09_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C09_TEST_PGHOST,
    port: Number(process.env.C09_TEST_PGPORT),
    database: process.env.C09_TEST_PGDATABASE,
    user: process.env.C09_TEST_PGUSER,
  };
}

test("restored PostgreSQL keeps terminal state scrubbed and events opaque", async () => {
  const pool = new Pool(configuration());
  try {
    const terminal = await pool.query(
      `SELECT count(*)::integer AS total,
              count(*) FILTER (WHERE content IS NOT NULL)::integer
                AS plaintext
         FROM aios_personal_memory.personal_memory
        WHERE state IN ('EXPIRED','DELETED')`,
    );
    assert.ok(terminal.rows[0].total > 0);
    assert.equal(terminal.rows[0].plaintext, 0);

    const checkpoint = await pool.query(
      `SELECT count(*)::integer AS terminal_references
         FROM aios_personal_memory.conversation_checkpoint AS checkpoint
         CROSS JOIN LATERAL unnest(checkpoint.memory_ids)
           AS reference(memory_id)
         JOIN aios_personal_memory.personal_memory AS memory
           ON memory.tenant_id=checkpoint.tenant_id
          AND memory.principal_id=checkpoint.principal_id
          AND memory.memory_id=reference.memory_id
        WHERE memory.state IN ('EXPIRED','DELETED')`,
    );
    assert.equal(checkpoint.rows[0].terminal_references, 0);

    const events = await pool.query(
      `SELECT count(*)::integer AS total,
              count(*) FILTER (
                WHERE human_consent_evidence IS NOT NULL
              )::integer AS consent_events,
              count(*) FILTER (
                WHERE to_jsonb(event) ? 'content'
                   OR human_consent_evidence ? 'humanConsentToken'
                   OR to_jsonb(event)::text
                        ~ 'hct_[0-9a-f-]{36}'
                   OR to_jsonb(event)::text LIKE '%Synthetic preference:%'
                   OR to_jsonb(event)::text LIKE '%Synthetic work state:%'
              )::integer AS plaintext_leaks
         FROM aios_personal_memory.memory_event AS event`,
    );
    assert.ok(events.rows[0].total > 0);
    assert.ok(events.rows[0].consent_events > 0);
    assert.equal(events.rows[0].plaintext_leaks, 0);
  } finally {
    await pool.end();
  }
});

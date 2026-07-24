import { env } from "cloudflare:workers";
import { drizzle } from "drizzle-orm/d1";
import * as schema from "./schema";

export function getDb() {
  if (!env.DB) {
    throw new Error(
      "Cloudflare D1 binding `DB` is unavailable. Set the `d1` field in .openai/hosting.json to `DB` or let your control plane inject the real binding values before using the database."
    );
  }

  return drizzle(env.DB, { schema });
}

export async function ensureDatabase() {
  if (!env.DB) {
    throw new Error("项目进度数据库暂不可用。");
  }

  await env.DB.batch([
    env.DB
      .prepare(
        `CREATE TABLE IF NOT EXISTS projects (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          scope_version TEXT NOT NULL,
          current_phase TEXT NOT NULL,
          status TEXT NOT NULL,
          summary TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`,
      ),
    env.DB
      .prepare(
        `CREATE TABLE IF NOT EXISTS tasks (
          id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL,
          phase TEXT NOT NULL,
          title TEXT NOT NULL,
          plain_summary TEXT NOT NULL,
          acceptance TEXT NOT NULL,
          status TEXT NOT NULL,
          owner TEXT NOT NULL,
          weight INTEGER NOT NULL,
          next_step TEXT NOT NULL,
          blocked_reason TEXT,
          evidence TEXT,
          updated_at TEXT NOT NULL
        )`,
      ),
    env.DB
      .prepare(
        `CREATE TABLE IF NOT EXISTS connectors (
          id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL,
          name TEXT NOT NULL,
          maturity TEXT NOT NULL,
          status_label TEXT NOT NULL,
          data_mode TEXT NOT NULL,
          resume_condition TEXT NOT NULL,
          note TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`,
      ),
    env.DB
      .prepare(
        `CREATE TABLE IF NOT EXISTS task_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          project_id TEXT NOT NULL,
          task_id TEXT,
          connector_id TEXT,
          event_type TEXT NOT NULL,
          message TEXT NOT NULL,
          actor TEXT NOT NULL,
          idempotency_key TEXT NOT NULL UNIQUE,
          created_at TEXT NOT NULL
        )`,
      ),
    env.DB.prepare(
      "CREATE INDEX IF NOT EXISTS tasks_project_phase_idx ON tasks(project_id, phase)",
    ),
    env.DB.prepare(
      "CREATE INDEX IF NOT EXISTS events_project_created_idx ON task_events(project_id, created_at DESC)",
    ),
  ]);

  return env.DB;
}

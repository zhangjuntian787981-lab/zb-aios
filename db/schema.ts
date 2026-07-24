import { integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const projects = sqliteTable("projects", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  scopeVersion: text("scope_version").notNull(),
  currentPhase: text("current_phase").notNull(),
  status: text("status").notNull(),
  summary: text("summary").notNull(),
  updatedAt: text("updated_at").notNull(),
});

export const tasks = sqliteTable("tasks", {
  id: text("id").primaryKey(),
  projectId: text("project_id").notNull(),
  phase: text("phase").notNull(),
  title: text("title").notNull(),
  plainSummary: text("plain_summary").notNull(),
  acceptance: text("acceptance").notNull(),
  status: text("status").notNull(),
  owner: text("owner").notNull(),
  weight: integer("weight").notNull(),
  nextStep: text("next_step").notNull(),
  blockedReason: text("blocked_reason"),
  evidence: text("evidence"),
  updatedAt: text("updated_at").notNull(),
});

export const connectors = sqliteTable("connectors", {
  id: text("id").primaryKey(),
  projectId: text("project_id").notNull(),
  name: text("name").notNull(),
  maturity: text("maturity").notNull(),
  statusLabel: text("status_label").notNull(),
  dataMode: text("data_mode").notNull(),
  resumeCondition: text("resume_condition").notNull(),
  note: text("note").notNull(),
  updatedAt: text("updated_at").notNull(),
});

export const taskEvents = sqliteTable(
  "task_events",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    projectId: text("project_id").notNull(),
    taskId: text("task_id"),
    connectorId: text("connector_id"),
    eventType: text("event_type").notNull(),
    message: text("message").notNull(),
    actor: text("actor").notNull(),
    idempotencyKey: text("idempotency_key").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("task_events_idempotency_idx").on(table.idempotencyKey),
  ],
);

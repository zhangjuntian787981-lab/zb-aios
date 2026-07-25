import { env } from "cloudflare:workers";

type GovernanceEventRow = {
  id: string;
  revision: number;
  event_type: string;
  payload: string;
  actor_id: string;
  idempotency_key: string;
  command_hash: string;
  created_at: string;
};

function journalError(code: string, message: string) {
  return Object.assign(new Error(message), { code });
}

function eventFromRow(row: GovernanceEventRow) {
  return {
    id: row.id,
    revision: row.revision,
    type: row.event_type,
    payload: JSON.parse(row.payload) as unknown,
    actorId: row.actor_id,
    idempotencyKey: row.idempotency_key,
    commandHash: row.command_hash,
    createdAt: row.created_at,
  };
}

export function createD1GovernanceJournal() {
  const d1 = env.DB;
  if (!d1) {
    throw journalError("STORE_UNAVAILABLE", "项目治理数据库暂不可用。");
  }

  return {
    async load(projectId: string) {
      const result = await d1
        .prepare(
          `SELECT id, revision, event_type, payload, actor_id,
                  idempotency_key, command_hash, created_at
           FROM governance_events
           WHERE project_id = ?
           ORDER BY revision ASC`,
        )
        .bind(projectId)
        .all<GovernanceEventRow>();
      const events = result.results.map(eventFromRow);
      return {
        revision: events.at(-1)?.revision ?? 0,
        events,
      };
    },

    async append({
      projectId,
      expectedRevision,
      idempotencyKey,
      commandHash,
      event,
    }: {
      projectId: string;
      expectedRevision: number;
      idempotencyKey: string;
      commandHash: string;
      event: {
        id: string;
        type: string;
        payload: unknown;
        actorId: string;
        createdAt: string;
      };
    }) {
      const existing = await d1
        .prepare(
          `SELECT id, revision, event_type, payload, actor_id,
                  idempotency_key, command_hash, created_at
           FROM governance_events
           WHERE project_id = ? AND idempotency_key = ?
           LIMIT 1`,
        )
        .bind(projectId, idempotencyKey)
        .first<GovernanceEventRow>();
      if (existing) {
        if (existing.command_hash !== commandHash) {
          throw journalError(
            "IDEMPOTENCY_CONFLICT",
            "本次更新编号已经用于另一条命令。",
          );
        }
        return { duplicate: true, event: eventFromRow(existing) };
      }

      const latest = await d1
        .prepare(
          "SELECT COALESCE(MAX(revision), 0) AS revision FROM governance_events WHERE project_id = ?",
        )
        .bind(projectId)
        .first<{ revision: number }>();
      if ((latest?.revision ?? 0) !== expectedRevision) {
        throw journalError("STALE_REVISION", "进度已经变化，请刷新后重试。");
      }

      try {
        await d1
          .prepare(
            `INSERT INTO governance_events
              (id, project_id, revision, event_type, payload, actor_id,
               idempotency_key, command_hash, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(
            event.id,
            projectId,
            expectedRevision + 1,
            event.type,
            JSON.stringify(event.payload),
            event.actorId,
            idempotencyKey,
            commandHash,
            event.createdAt,
          )
          .run();
      } catch {
        const replay = await d1
          .prepare(
            `SELECT id, revision, event_type, payload, actor_id,
                    idempotency_key, command_hash, created_at
             FROM governance_events
             WHERE project_id = ? AND idempotency_key = ?
             LIMIT 1`,
          )
          .bind(projectId, idempotencyKey)
          .first<GovernanceEventRow>();
        if (replay?.command_hash === commandHash) {
          return { duplicate: true, event: eventFromRow(replay) };
        }
        throw journalError("STALE_REVISION", "进度已经变化，请刷新后重试。");
      }

      return {
        duplicate: false,
        event: {
          ...event,
          revision: expectedRevision + 1,
          idempotencyKey,
          commandHash,
        },
      };
    },
  };
}

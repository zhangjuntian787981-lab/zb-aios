import { env } from "cloudflare:workers";
import { asc, desc, eq } from "drizzle-orm";
import { ensureDatabase, getDb } from "../../../db";
import { createD1GovernanceJournal } from "../../../db/governance-journal";
import { connectors, projects, taskEvents } from "../../../db/schema";
import manifest from "../../../implementation/governance/work-package-manifest.v1.json";
import humanBaselineCandidate from "../../../implementation/p0/f04/human-baseline-candidate.v1.json";
import { createProjectControl } from "../../../lib/project-control.mjs";
import {
  isProductOwner,
  isValidConnectorAdvanceEvidence,
} from "../../../scripts/project-policy.mjs";

export const dynamic = "force-dynamic";

const PROJECT_ID = manifest.project_id;
const HUMAN_BASELINE_CANDIDATE_PATH =
  "implementation/p0/f04/human-baseline-candidate.v1.json";
const HUMAN_BASELINE_CANDIDATE_HASH =
  "sha256:1ac738d40ed6fb0bdaadb876c92b4f3cbde0d722142093bb786447365c9c5de0";
const PHASES = [
  { code: "P0", title: "产品边界与技术基线" },
  { code: "P1", title: "通用多租户核心建设" },
  { code: "P2", title: "产品化与生产加固" },
  { code: "P3", title: "目标企业接入与验收" },
] as const;
const CONNECTOR_STAGES = ["C0", "C1", "C2", "C3"] as const;
type ConnectorStage = (typeof CONNECTOR_STAGES)[number];

const CONNECTOR_PRESENTATION: Record<
  ConnectorStage,
  { statusLabel: string; dataMode: string }
> = {
  C0: { statusLabel: "P3 前锁定，未接入企业", dataMode: "DISABLED" },
  C1: { statusLabel: "P3 企业批准快照", dataMode: "APPROVED_SNAPSHOT" },
  C2: { statusLabel: "P3 企业真实只读", dataMode: "REAL_READ" },
  C3: { statusLabel: "P3 企业受控写回", dataMode: "CONTROLLED_WRITE" },
};

function connectorSeeds(now: string) {
  return [
    { id: "v5-connector-approval-collaboration", name: "审批/协同系统模板" },
    { id: "v5-connector-erp-business", name: "ERP/业务系统模板" },
    { id: "v5-connector-bi-metrics", name: "BI/指标系统模板" },
  ].map(({ id, name }) => ({
    id,
    projectId: PROJECT_ID,
    name,
    maturity: "C0",
    statusLabel: CONNECTOR_PRESENTATION.C0.statusLabel,
    dataMode: CONNECTOR_PRESENTATION.C0.dataMode,
    resumeCondition:
      "G2 获得产品所有者批准并进入 P3 后，还需企业授权、最小权限身份和逐级测试证据。",
    note: "P0—P2 只建设通用模板；没有目标企业凭据、地址或网络。",
    updatedAt: now,
  }));
}

async function seedIfNeeded() {
  const db = getDb();
  const now = new Date().toISOString();
  await db
    .insert(projects)
    .values({
      id: PROJECT_ID,
      name: "通用多企业 AI 员工平台",
      scopeVersion: `manifest-${manifest.manifest_version}`,
      currentPhase: "P0",
      status: "moving",
      summary:
        "37 个工作包由唯一 Manifest 与只追加治理账本计算；P0—P2 只使用合成数据，P3 才接入目标企业。",
      updatedAt: now,
    })
    .onConflictDoNothing();
  await db.insert(connectors).values(connectorSeeds(now)).onConflictDoNothing();
  await db
    .insert(taskEvents)
    .values({
      projectId: PROJECT_ID,
      eventType: "manifest_installed",
      message:
        "v5 已启用 37 项机器清单；旧版粗粒度完成率只保留为历史，不计入当前进度。",
      actor: "产品建设代理",
      idempotencyKey: "v5-manifest-installed-v1",
      createdAt: now,
    })
    .onConflictDoNothing();
}

function configuredProductOwner() {
  return (env as unknown as { PROJECT_OWNER_EMAIL?: string })
    .PROJECT_OWNER_EMAIL;
}

async function productOwnerActor(actor: string) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(actor.trim().toLowerCase()),
  );
  const fingerprint = Array.from(new Uint8Array(digest).slice(0, 6))
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
  return `外部产品所有者 · ${fingerprint}`;
}

function taskStatus(item: {
  implementationStatus: string;
  verificationStatus: string;
}) {
  if (item.verificationStatus === "VERIFIED") return "verified";
  if (item.implementationStatus === "IMPLEMENTED") return "implemented";
  if (item.implementationStatus === "IN_PROGRESS") return "in_progress";
  return "not_started";
}

function gateTitle(gate: { id: string; phase: string; opensPhase: string | null }) {
  return gate.opensPhase
    ? `${gate.id} · ${gate.phase} → ${gate.opensPhase}`
    : `${gate.id} · ${gate.phase} 最终验收`;
}

function gateNextStep(gate: {
  status: string;
  missingWorkPackages: string[];
  unresolvedApplicability: string[];
}) {
  if (gate.status === "APPROVED") return "该阶段决定已经冻结。";
  if (gate.status === "AWAITING_DECISION")
    return "冻结包已提交，等待产品所有者对准确哈希作决定。";
  if (gate.status === "READY_TO_SUBMIT")
    return "生成冻结证据包和 SHA-256 后提交产品所有者。";
  if (gate.unresolvedApplicability.length > 0)
    return `先确定适用性：${gate.unresolvedApplicability.join("、")}`;
  return `仍缺：${gate.missingWorkPackages.join("、")}`;
}

async function controlSnapshot() {
  const control = createProjectControl({
    manifest,
    journal: createD1GovernanceJournal(),
  });
  return { control, snapshot: await control.snapshot() };
}

async function dashboardData(actor: string | null) {
  await ensureDatabase();
  await seedIfNeeded();
  const db = getDb();
  const { snapshot } = await controlSnapshot();
  const [projectRows, connectorRows, legacyEvents] = await Promise.all([
    db.select().from(projects).where(eq(projects.id, PROJECT_ID)).limit(1),
    db
      .select()
      .from(connectors)
      .where(eq(connectors.projectId, PROJECT_ID))
      .orderBy(asc(connectors.name)),
    db
      .select()
      .from(taskEvents)
      .where(eq(taskEvents.projectId, PROJECT_ID))
      .orderBy(desc(taskEvents.createdAt), desc(taskEvents.id))
      .limit(20),
  ]);

  const workPackages = snapshot.workPackages.map(
    (item: {
      id: string;
      phase: string;
      title: string;
      applicability: string;
      planStatus: string;
      implementationStatus: string;
      verificationStatus: string;
      acceptanceAssertions: string[];
      responsibleRole: string;
      size: string;
      dependencies: string[];
      allowedToStart: boolean;
      blockers: string[];
      evidenceRefs: string[];
      evidenceHashes: string[];
      verifiedAt: string | null;
      updatedAt: string;
    }) => ({
      id: item.id,
      phase: item.phase,
      title: `${item.id} ${item.title}`,
      plainSummary: item.acceptanceAssertions[0],
      acceptance: item.acceptanceAssertions.join(" "),
      status: taskStatus(item),
      planStatus: item.planStatus,
      implementationStatus: item.implementationStatus,
      verificationStatus: item.verificationStatus,
      applicability: item.applicability,
      owner: item.responsibleRole,
      size: item.size,
      weight: 1,
      nextStep:
        item.verificationStatus === "VERIFIED"
          ? "证据已冻结；等待同阶段其余工作包完成。"
          : item.allowedToStart
            ? "依赖已满足，可以开始或继续。"
            : `等待 ${item.blockers.join("、")}`,
      blockedReason:
        item.blockers.length > 0 ? item.blockers.join("、") : null,
      dependencies: item.dependencies,
      blockers: item.blockers,
      allowedToStart: item.allowedToStart,
      evidence:
        [...item.evidenceRefs, ...item.evidenceHashes].join("\n") || null,
      updatedAt: item.updatedAt,
    }),
  );

  const phaseProgress = PHASES.map((phase) => {
    const items = workPackages.filter((item) => item.phase === phase.code);
    const verified = items.filter(
      (item) => item.verificationStatus === "VERIFIED",
    ).length;
    return {
      ...phase,
      accepted: verified,
      total: items.length,
      percentage: Math.round((verified / items.length) * 100),
    };
  });
  const currentPhase =
    snapshot.gates.find((gate: { status: string }) => gate.status !== "APPROVED")
      ?.phase ?? "P3";
  const gates = snapshot.gates.map(
    (gate: {
      id: string;
      phase: string;
      opensPhase: string | null;
      status: string;
      missingWorkPackages: string[];
      unresolvedApplicability: string[];
      latestSubmission: unknown;
      latestDecision: unknown;
    }) => ({
      ...gate,
      title: gateTitle(gate),
      nextStep: gateNextStep(gate),
    }),
  );

  const governanceEvents = snapshot.events.map(
    (event: {
      id: string;
      type: string;
      payload: { note?: string; workPackageId?: string; gateId?: string };
      actorId: string;
      createdAt: string;
    }) => ({
      id: event.id,
      eventType: event.type,
      message:
        event.payload.note ||
        `${event.payload.workPackageId ?? event.payload.gateId ?? "治理记录"}：${event.type}`,
      actor: event.actorId,
      createdAt: event.createdAt,
    }),
  );
  const events = [...governanceEvents, ...legacyEvents]
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .slice(0, 20);
  const awaitingDecision = gates.filter(
    (gate: { status: string }) => gate.status === "AWAITING_DECISION",
  );
  const updatedAt =
    [...workPackages.map((item) => item.updatedAt), ...events.map((item) => item.createdAt)]
      .sort()
      .at(-1) ?? projectRows[0]?.updatedAt;
  const f04 = workPackages.find((item) => item.id === "F04");

  return {
    revision: snapshot.revision,
    project: {
      ...projectRows[0],
      currentPhase,
      status:
        awaitingDecision.length > 0 ? "awaiting_confirmation" : "moving",
      updatedAt,
    },
    summary: {
      verifiedProgress: snapshot.progress.portfolio.percentage,
      acceptedTasks: snapshot.progress.portfolio.verified,
      totalTasks: snapshot.progress.portfolio.total,
      nowDoing: workPackages.filter((item) =>
        ["in_progress", "implemented"].includes(item.status),
      ),
      recentlyCompleted: workPackages
        .filter((item) => item.status === "verified")
        .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
        .slice(0, 2),
      decisions: awaitingDecision,
    },
    policy: {
      soleApprover: "外部产品所有者",
      targetEnterpriseRelationship: "NOT_AN_ENTERPRISE_EMPLOYEE",
      enterpriseInputsRequiredNow: currentPhase === "P3",
      enterpriseInputsAllowedFromPhase: "P3",
      publicExternalContextAllowed: true,
      connectorActivationReady: snapshot.phaseEntry.P3,
      mutationAuthorized: isProductOwner(actor, configuredProductOwner()),
    },
    humanBaselineReview: {
      status:
        f04?.verificationStatus === "VERIFIED"
          ? "VALIDATED"
          : "AWAITING_HUMAN_VALIDATION",
      candidateId: humanBaselineCandidate.candidate_id,
      candidateHash: HUMAN_BASELINE_CANDIDATE_HASH,
      plainLanguageNote: humanBaselineCandidate.plain_language_note,
      items: humanBaselineCandidate.items,
      canValidate:
        f04?.implementationStatus === "IMPLEMENTED" &&
        f04.verificationStatus !== "VERIFIED",
    },
    phaseProgress,
    tasks: workPackages,
    gates,
    connectors: connectorRows,
    events,
    serverTime: new Date().toISOString(),
  };
}

function responseStatus(error: unknown) {
  const code = (error as { code?: string })?.code;
  if (
    ["INVALID_COMMAND", "UNKNOWN_ID", "EVIDENCE_INCOMPLETE"].includes(
      code ?? "",
    )
  ) {
    return 400;
  }
  if (
    [
      "DEPENDENCY_BLOCKED",
      "INVALID_TRANSITION",
      "STALE_REVISION",
      "IDEMPOTENCY_CONFLICT",
      "GATE_NOT_READY",
      "DECISION_EXISTS",
      "HASH_MISMATCH",
      "INVALID_EXCLUSION",
      "INVALID_SUPERSEDES",
      "UNCHANGED_SUBMISSION",
      "STALE_SUBMISSION",
    ].includes(code ?? "")
  ) {
    return 409;
  }
  return 500;
}

export async function GET(request: Request) {
  try {
    return Response.json(
      await dashboardData(request.headers.get("oai-authenticated-user-email")),
    );
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "读取产品进度失败。";
    return Response.json({ error: message }, { status: 500 });
  }
}

export async function POST(request: Request) {
  const actor = request.headers.get("oai-authenticated-user-email");
  if (!actor) {
    return Response.json({ error: "需要先通过工作区身份验证。" }, { status: 401 });
  }
  const productOwner = configuredProductOwner();
  if (!productOwner) {
    return Response.json(
      { error: "产品所有者身份尚未配置，当前拒绝修改进度。" },
      { status: 503 },
    );
  }
  if (!isProductOwner(actor, productOwner)) {
    return Response.json(
      { error: "只有外部产品所有者的更新才会被记录。" },
      { status: 403 },
    );
  }

  try {
    const payload = (await request.json()) as {
      action?: string;
      taskId?: string;
      connectorId?: string;
      gateId?: string;
      submissionId?: string;
      packageHash?: string;
      decision?: string;
      supersedes?: string;
      status?: string;
      maturity?: string;
      note?: string;
      evidence?: string;
      confirmed?: boolean;
      idempotencyKey?: string;
      expectedRevision?: number;
    };
    const idempotencyKey = payload.idempotencyKey?.trim() ?? "";
    if (!idempotencyKey) {
      return Response.json({ error: "缺少本次更新的唯一编号。" }, { status: 400 });
    }
    await ensureDatabase();
    await seedIfNeeded();
    const { control, snapshot } = await controlSnapshot();

    if (payload.action === "validate_human_baseline") {
      const f04 = snapshot.workPackages.find(
        (item: { id: string }) => item.id === "F04",
      );
      if (
        !payload.confirmed ||
        payload.packageHash !== HUMAN_BASELINE_CANDIDATE_HASH
      ) {
        return Response.json(
          { error: "必须确认当前页面显示的准确人工基线 SHA-256。" },
          { status: 400 },
        );
      }
      if (
        !f04 ||
        f04.implementationStatus !== "IMPLEMENTED" ||
        f04.verificationStatus === "VERIFIED"
      ) {
        return Response.json(
          { error: "F04 尚未完成工程实现，或人工基线已经确认。" },
          { status: 409 },
        );
      }
      const receipt = await control.execute(
        { actorId: "external_product_owner", roles: ["PRODUCT_OWNER"] },
        {
          kind: "RECORD_WORK_PACKAGE",
          workPackageId: "F04",
          implementationStatus: "IMPLEMENTED",
          verificationStatus: "VERIFIED",
          evidenceRefs: [
            ...new Set([
              ...f04.evidenceRefs,
              HUMAN_BASELINE_CANDIDATE_PATH,
            ]),
          ],
          evidenceHashes: [
            ...new Set([
              ...f04.evidenceHashes,
              HUMAN_BASELINE_CANDIDATE_HASH,
            ]),
          ],
          note: `外部产品所有者确认十项 F04 人工基线：${HUMAN_BASELINE_CANDIDATE_HASH}`,
          expectedRevision: payload.expectedRevision ?? snapshot.revision,
          idempotencyKey,
        },
      );
      return Response.json({ ok: true, ...receipt });
    }

    if (payload.action === "submit_gate") {
      const gateId = payload.gateId?.trim() ?? "";
      const gate = snapshot.gates.find(
        (item: { id: string }) => item.id === gateId,
      );
      const evidenceRefs = [
        ...new Set(
          gate?.workPackageScope.flatMap(
            (item: { evidence_refs: string[] }) => item.evidence_refs,
          ) ?? [],
        ),
      ];
      if (!gateId || evidenceRefs.length === 0) {
        return Response.json(
          { error: "阶段门无效，或当前范围没有可冻结的证据。" },
          { status: 400 },
        );
      }
      const receipt = await control.execute(
        { actorId: "external_product_owner", roles: ["PRODUCT_OWNER"] },
        {
          kind: "SUBMIT_GATE",
          gateId,
          evidenceRefs,
          supersedes: payload.supersedes?.trim() || null,
          expectedRevision: payload.expectedRevision ?? snapshot.revision,
          idempotencyKey,
        },
      );
      return Response.json({ ok: true, ...receipt });
    }

    if (payload.action === "decide_gate") {
      const submissionId = payload.submissionId?.trim() ?? "";
      const packageHash = payload.packageHash?.trim() ?? "";
      const allowedDecisions = ["APPROVE", "RETURN", "HOLD"];
      if (
        !submissionId ||
        !/^sha256:[a-f0-9]{64}$/.test(packageHash) ||
        !allowedDecisions.includes(payload.decision ?? "")
      ) {
        return Response.json(
          { error: "提交编号、准确 SHA-256 和阶段决定均为必填。" },
          { status: 400 },
        );
      }
      const receipt = await control.execute(
        { actorId: "external_product_owner", roles: ["PRODUCT_OWNER"] },
        {
          kind: "DECIDE_GATE",
          submissionId,
          expectedPackageHash: packageHash,
          decision: payload.decision,
          acceptedExclusions: [],
          evidenceRefs: [
            `product-owner-decision:${submissionId}:${packageHash}`,
          ],
          expectedRevision: payload.expectedRevision ?? snapshot.revision,
          idempotencyKey,
        },
      );
      return Response.json({ ok: true, ...receipt });
    }

    if (payload.action === "update_task") {
      const statusMap: Record<
        string,
        { implementationStatus: string; verificationStatus: string }
      > = {
        in_progress: {
          implementationStatus: "IN_PROGRESS",
          verificationStatus: "NOT_VERIFIED",
        },
        implemented: {
          implementationStatus: "IMPLEMENTED",
          verificationStatus: "NOT_VERIFIED",
        },
        ready_for_acceptance: {
          implementationStatus: "IMPLEMENTED",
          verificationStatus: "NOT_VERIFIED",
        },
        verified: {
          implementationStatus: "IMPLEMENTED",
          verificationStatus: "VERIFIED",
        },
        accepted: {
          implementationStatus: "IMPLEMENTED",
          verificationStatus: "VERIFIED",
        },
      };
      const target = payload.status ? statusMap[payload.status] : undefined;
      const note = payload.note?.trim() ?? "";
      const evidence = payload.evidence?.trim() ?? "";
      if (!target || !payload.taskId || !note) {
        return Response.json(
          { error: "工作包、目标状态和本次说明均为必填。" },
          { status: 400 },
        );
      }
      if (
        target.verificationStatus === "VERIFIED" &&
        (!payload.confirmed || evidence.length < 5)
      ) {
        return Response.json(
          { error: "标记为证据已验证前，必须确认并填写证据与 SHA-256。" },
          { status: 400 },
        );
      }
      const hashes =
        evidence.match(/sha256:[a-f0-9]{64}/gi)?.map((value) => value.toLowerCase()) ??
        [];
      const receipt = await control.execute(
        { actorId: "external_product_owner", roles: ["PRODUCT_OWNER"] },
        {
          kind: "RECORD_WORK_PACKAGE",
          workPackageId: payload.taskId,
          ...target,
          evidenceRefs: evidence ? [evidence] : [],
          evidenceHashes: hashes,
          note,
          expectedRevision: payload.expectedRevision ?? snapshot.revision,
          idempotencyKey,
        },
      );
      return Response.json({ ok: true, ...receipt });
    }

    if (payload.action === "update_connector") {
      const db = getDb();
      const nextStage = payload.maturity as ConnectorStage;
      const [connector] = await db
        .select()
        .from(connectors)
        .where(eq(connectors.id, payload.connectorId?.trim() ?? ""))
        .limit(1);
      if (
        !connector ||
        connector.projectId !== PROJECT_ID ||
        !CONNECTOR_STAGES.includes(nextStage)
      ) {
        return Response.json(
          { error: "Connector 或目标阶段无效。" },
          { status: 400 },
        );
      }
      const currentIndex = CONNECTOR_STAGES.indexOf(
        connector.maturity as ConnectorStage,
      );
      const nextIndex = CONNECTOR_STAGES.indexOf(nextStage);
      if (nextIndex > currentIndex + 1) {
        return Response.json(
          { error: "Connector 不能跳过中间门禁。" },
          { status: 409 },
        );
      }
      if (nextIndex > currentIndex && !snapshot.phaseEntry.P3) {
        return Response.json(
          { error: "G2 尚未获产品所有者批准，企业 Connector 保持 C0。" },
          { status: 409 },
        );
      }
      const note = payload.note?.trim() ?? "";
      const evidence = payload.evidence?.trim() ?? "";
      if (note.length < 5) {
        return Response.json(
          { error: "请说明升级、降级或暂缓的证据与原因。" },
          { status: 400 },
        );
      }
      if (
        nextIndex > currentIndex &&
        (!payload.confirmed ||
          !isValidConnectorAdvanceEvidence(
            connector.maturity,
            nextStage,
            evidence,
          ))
      ) {
        return Response.json(
          {
            error:
              currentIndex === 0
                ? "首次接入必须包含 enterprise-authorization: 引用和 sha256: 哈希。"
                : "向前升级必须包含 sha256: 验收哈希。",
          },
          { status: 400 },
        );
      }
      const actorLabel = await productOwnerActor(actor);
      const now = new Date().toISOString();
      const presentation = CONNECTOR_PRESENTATION[nextStage];
      const eventType = `connector_${nextStage.toLowerCase()}`;
      const message = `${connector.name}：${note}；证据：${evidence || "不适用"}`;
      const [existingEvent] = await db
        .select()
        .from(taskEvents)
        .where(eq(taskEvents.idempotencyKey, idempotencyKey))
        .limit(1);
      if (existingEvent) {
        const sameCommand =
          existingEvent.connectorId === connector.id &&
          existingEvent.eventType === eventType &&
          existingEvent.message === message;
        return sameCommand
          ? Response.json({ ok: true, duplicate: true })
          : Response.json(
              { error: "本次更新编号已经用于另一条命令。" },
              { status: 409 },
            );
      }
      try {
        await env.DB.batch([
          env.DB
            .prepare(
              `UPDATE connectors
               SET maturity = ?, status_label = ?, data_mode = ?, note = ?, updated_at = ?
               WHERE id = ? AND project_id = ?`,
            )
            .bind(
              nextStage,
              presentation.statusLabel,
              presentation.dataMode,
              note,
              now,
              connector.id,
              PROJECT_ID,
            ),
          env.DB
            .prepare(
              `INSERT INTO task_events
                (project_id, connector_id, event_type, message, actor, idempotency_key, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)`,
            )
            .bind(
              PROJECT_ID,
              connector.id,
              eventType,
              message,
              actorLabel,
              idempotencyKey,
              now,
            ),
        ]);
      } catch (error) {
        if (
          error instanceof Error &&
          error.message.includes("task_events.idempotency_key")
        ) {
          return Response.json(
            { error: "进度刚刚发生变化，请刷新后重试。" },
            { status: 409 },
          );
        }
        throw error;
      }
      return Response.json({ ok: true });
    }

    return Response.json({ error: "不支持的更新类型。" }, { status: 400 });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "更新产品进度失败。";
    return Response.json({ error: message }, { status: responseStatus(error) });
  }
}

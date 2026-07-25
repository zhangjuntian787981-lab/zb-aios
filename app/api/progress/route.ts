import { env } from "cloudflare:workers";
import { asc, desc, eq } from "drizzle-orm";
import { ensureDatabase, getDb } from "../../../db";
import { connectors, projects, taskEvents, tasks } from "../../../db/schema";
import {
  canAcceptStageGate,
  canAdvanceConnector,
  canStartPhase,
  isProductOwner,
  isValidConnectorAdvanceEvidence,
  isValidStageApprovalEvidence,
} from "../../../scripts/project-policy.mjs";

export const dynamic = "force-dynamic";

const PROJECT_ID = "generic-multi-enterprise-ai-platform-v4";
const SCOPE_VERSION = "v4.0-GENERIC-PRODUCT-P3-ONBOARDING";
const PHASES = [
  { code: "P0", title: "产品边界与技术基线" },
  { code: "P1", title: "通用多租户核心建设" },
  { code: "P2", title: "产品化、打包与生产加固" },
  { code: "P3", title: "目标企业接入与验收" },
] as const;

const TASK_STATUSES = [
  "not_started",
  "in_progress",
  "ready_for_acceptance",
  "awaiting_confirmation",
  "waiting_external",
  "accepted",
  "needs_attention",
  "deferred",
] as const;

type TaskStatus = (typeof TASK_STATUSES)[number];

const ALLOWED_TRANSITIONS: Record<TaskStatus, TaskStatus[]> = {
  not_started: [
    "in_progress",
    "awaiting_confirmation",
    "waiting_external",
    "deferred",
  ],
  in_progress: [
    "ready_for_acceptance",
    "awaiting_confirmation",
    "waiting_external",
    "needs_attention",
    "deferred",
  ],
  ready_for_acceptance: ["accepted", "in_progress", "needs_attention"],
  awaiting_confirmation: ["accepted", "in_progress", "needs_attention"],
  waiting_external: ["in_progress", "deferred", "needs_attention"],
  accepted: [],
  needs_attention: ["in_progress", "waiting_external", "deferred"],
  deferred: ["in_progress", "waiting_external"],
};

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

function taskSeeds(now: string) {
  return [
    {
      id: "v4-p0-01-engineering-plan",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "通用多企业产品工程方案 v4.0",
      plainSummary:
        "已经把 P0—P2 通用建设、P3 企业接入和可打包交付写成工程基线。",
      acceptance:
        "方案明确多租户、身份、权限、知识、Skills、Connector、沙箱、打包和阶段验收。",
      status: "accepted",
      owner: "产品建设代理",
      weight: 5,
      nextStep: "作为后续产品实现与验收基线。",
      evidence:
        "docs/plans/通用多企业AI员工平台_完备工程级方案_v4.0.md",
      updatedAt: now,
    },
    {
      id: "v4-p0-02-beginner-plan",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "通用产品小白易懂方案 v2.0",
      plainSummary:
        "用非技术语言解释为什么先造通用产品、最后才接入具体企业。",
      acceptance:
        "非技术读者能理解四阶段、资料边界、产品化价值和唯一审批方式。",
      status: "accepted",
      owner: "产品建设代理",
      weight: 3,
      nextStep: "用于产品所有者查看和对外解释。",
      evidence:
        "docs/plans/通用多企业AI员工平台_小白易懂方案_v2.0.md",
      updatedAt: now,
    },
    {
      id: "v4-p0-03-progress-center",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "产品实时进度中心 v4",
      plainSummary:
        "展示通用产品建设、单一阶段审批和 P3 企业接入锁定状态。",
      acceptance:
        "构建、数据保存、精确审批身份、阶段跳转和 Connector 锁定全部验证通过。",
      status: "ready_for_acceptance",
      owner: "产品建设代理",
      weight: 4,
      nextStep: "私有发布并验证后，纳入 P0 阶段验收。",
      evidence:
        "npm test 17/17、lint 和生产构建通过；私有生产版本与地址记录在发布交接中。",
      updatedAt: now,
    },
    {
      id: "v4-p0-04-product-owner",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "外部产品所有者与单一阶段审批",
      plainSummary:
        "你是外部产品所有者，不是目标企业员工；每个阶段只记录你的最终审批。",
      acceptance:
        "角色、企业关系、阶段审批权和不追踪其他部门审批的边界可追溯。",
      status: "accepted",
      owner: "外部产品所有者（你）",
      weight: 6,
      nextStep: "P0 完成时由你作一次阶段审批。",
      evidence:
        "implementation/p0/evidence/product-model-directive-2026-07-25.md",
      updatedAt: now,
    },
    {
      id: "v4-p0-05-synthetic-boundary",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "P0-P2 零企业内部资料",
      plainSummary:
        "P0—P2 不请求企业资料、真实员工或系统信息，只使用合成数据建设产品。",
      acceptance:
        "内部资料、用户、凭据、企业网络和 Connector 大于 C0 都会触发安全阻断。",
      status: "accepted",
      owner: "外部产品所有者（你）",
      weight: 6,
      nextStep: "保持该边界直到 P3。",
      evidence:
        "implementation/p0/evidence/product-model-directive-2026-07-25.md",
      updatedAt: now,
    },
    {
      id: "v4-p0-06-tenant-boundary",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "通用租户、身份与数据边界",
      plainSummary:
        "建立产品所有者、目标企业、Tenant、Enterprise User 和运行权限的清晰边界。",
      acceptance:
        "领域词汇、Tenant 隔离、稳定身份、权限执行点和数据模式契约均有验证证据。",
      status: "in_progress",
      owner: "产品建设代理",
      weight: 6,
      nextStep: "完成合成身份 PoC、权限矩阵和跨 Tenant 拒绝测试。",
      evidence:
        "CONTEXT.md 与 docs/adr/0001-generic-product-before-enterprise-onboarding.md",
      updatedAt: now,
    },
    {
      id: "v4-p0-07-public-context",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "公开企业信息预收集规则",
      plainSummary:
        "P3 前可以收集公开外部信息，但不能把它当作企业内部事实或用于激活 Tenant。",
      acceptance:
        "PUBLIC_EXTERNAL_CONTEXT 的来源、日期、用途和禁止事项已经冻结。",
      status: "accepted",
      owner: "外部产品所有者（你）",
      weight: 5,
      nextStep: "如后续提供公开信息，按来源和日期登记。",
      evidence:
        "implementation/p0/evidence/product-model-directive-2026-07-25.md",
      updatedAt: now,
    },
    {
      id: "v4-p0-08-technical-gates",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "建立通用产品技术阶段门",
      plainSummary:
        "用测试证明零企业数据、阶段不能跳级、只有你能审批、Connector 只能在 P3 激活。",
      acceptance: "全部 P0 技术门为 VERIFIED，npm run p0:gate 返回 READY。",
      status: "in_progress",
      owner: "产品建设代理",
      weight: 5,
      nextStep: "继续完成身份、权限、基础设施和 SLI/SLO 证据。",
      evidence:
        "阶段门与策略测试已建立；当前因剩余技术证据和 P0 阶段审批未完成而 NOT_READY。",
      updatedAt: now,
    },
    {
      id: "v4-p0-09-stage-approval",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "产品所有者 P0 阶段审批",
      plainSummary:
        "所有 P0 建设和技术证据完成后，由你一次决定是否进入 P1。",
      acceptance:
        "你的审批绑定 P0 版本、完整内容哈希、时间、排除项和证据。",
      status: "not_started",
      owner: "外部产品所有者（唯一阶段审批人）",
      weight: 4,
      nextStep: "等待其余 P0 任务全部验收后，由你审批。",
      updatedAt: now,
    },
    {
      id: "v4-p1-01-core",
      projectId: PROJECT_ID,
      phase: "P1",
      title: "建设通用多租户 AI 核心",
      plainSummary:
        "建设个人 AI、身份、权限、知识、Skills、模型路由和审计核心。",
      acceptance:
        "至少三个合成 Tenant 的主路径可用，跨 Tenant 和跨用户泄露为零。",
      status: "not_started",
      owner: "产品建设代理",
      weight: 14,
      nextStep: "只有 P0 阶段审批通过后才能开始。",
      updatedAt: now,
    },
    {
      id: "v4-p1-02-synthetic-validation",
      projectId: PROJECT_ID,
      phase: "P1",
      title: "合成租户端到端验证",
      plainSummary:
        "用虚构用户、知识、Skills、流程和系统响应验证产品功能与隔离。",
      acceptance:
        "功能、拒绝、撤权、审计、恢复和成本测试达到冻结基线。",
      status: "not_started",
      owner: "产品建设代理",
      weight: 14,
      nextStep: "通用核心主路径完成后启动。",
      updatedAt: now,
    },
    {
      id: "v4-p1-03-stage-approval",
      projectId: PROJECT_ID,
      phase: "P1",
      title: "产品所有者 P1 阶段审批",
      plainSummary:
        "P1 合成功能和隔离证据完成后，由你决定是否进入产品化阶段。",
      acceptance: "你的 P1 审批绑定版本、哈希、证据和时间。",
      status: "not_started",
      owner: "外部产品所有者（唯一阶段审批人）",
      weight: 10,
      nextStep: "等待 P1 两项建设任务验收。",
      updatedAt: now,
    },
    {
      id: "v4-p2-01-product-hardening",
      projectId: PROJECT_ID,
      phase: "P2",
      title: "产品化、打包与生产加固",
      plainSummary:
        "完成安装、升级回滚、安全、恢复、压测、沙箱和 Connector Templates。",
      acceptance:
        "可重复部署的产品包通过预生产、安全、恢复和运维验收。",
      status: "not_started",
      owner: "产品建设代理",
      weight: 7,
      nextStep: "只有 P1 阶段审批通过后才能开始。",
      updatedAt: now,
    },
    {
      id: "v4-p2-02-stage-approval",
      projectId: PROJECT_ID,
      phase: "P2",
      title: "产品所有者 P2 阶段审批",
      plainSummary:
        "产品加固证据完成后，由你决定是否开放目标企业接入阶段。",
      acceptance:
        "你的 P2 审批绑定冻结产品包版本、完整内容哈希、时间和证据。",
      status: "not_started",
      owner: "外部产品所有者（唯一阶段审批人）",
      weight: 3,
      nextStep: "等待产品化、打包与生产加固任务验收。",
      updatedAt: now,
    },
    {
      id: "v4-p3-01-enterprise-onboarding",
      projectId: PROJECT_ID,
      phase: "P3",
      title: "目标企业接入、真实验收与上线",
      plainSummary:
        "目标企业通过授权渠道提供接入包，创建 Tenant，导入用户和知识，逐级激活 Connector。",
      acceptance:
        "企业接入包、真实权限、质量、安全、恢复和 Connector 证据通过。",
      status: "not_started",
      owner: "产品实施团队",
      weight: 6,
      nextStep: "只有 P2 产品就绪审批通过后才接收企业内部资料。",
      updatedAt: now,
    },
    {
      id: "v4-p3-02-stage-approval",
      projectId: PROJECT_ID,
      phase: "P3",
      title: "产品所有者 P3 最终审批",
      plainSummary:
        "企业接入和真实验收完成后，由你决定接受、退回或暂缓上线结果。",
      acceptance:
        "你的最终审批绑定 Tenant、上线版本、完整内容哈希、时间和证据。",
      status: "not_started",
      owner: "外部产品所有者（唯一阶段审批人）",
      weight: 2,
      nextStep: "等待目标企业接入和真实验收任务完成。",
      updatedAt: now,
    },
  ];
}

function connectorSeeds(now: string) {
  return [
    {
      id: "v4-connector-approval-collaboration",
      name: "审批/协同系统模板",
    },
    { id: "v4-connector-erp-business", name: "ERP/业务系统模板" },
    { id: "v4-connector-bi-metrics", name: "BI/指标系统模板" },
  ].map(({ id, name }) => ({
    id,
    projectId: PROJECT_ID,
    name,
    maturity: "C0",
    statusLabel: CONNECTOR_PRESENTATION.C0.statusLabel,
    dataMode: CONNECTOR_PRESENTATION.C0.dataMode,
    resumeCondition:
      "产品所有者批准 P2 后进入 P3，并具备企业接入授权、最小权限身份和逐级测试证据。",
    note: "P0—P2 只建设 Connector Template；无目标企业凭据、地址和网络。",
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
      scopeVersion: SCOPE_VERSION,
      currentPhase: "P0",
      status: "moving",
      summary:
        "P0—P2 只建设通用产品并使用合成数据；P3 才接入目标企业。你是外部产品所有者和唯一阶段审批人。",
      updatedAt: now,
    })
    .onConflictDoNothing();

  const seeds = taskSeeds(now);
  await db.insert(tasks).values(seeds.slice(0, 7)).onConflictDoNothing();
  await db.insert(tasks).values(seeds.slice(7)).onConflictDoNothing();
  await db.insert(connectors).values(connectorSeeds(now)).onConflictDoNothing();

  await db
    .insert(taskEvents)
    .values([
      {
        projectId: PROJECT_ID,
        eventType: "scope_replaced",
        message:
          "v4.0 已取代旧企业内部试点范围；旧项目和事件保留为历史，不计入当前进度。",
        actor: "产品所有者指令",
        idempotencyKey: "v4-scope-replaced-v1",
        createdAt: now,
      },
      {
        projectId: PROJECT_ID,
        taskId: "v4-p0-01-engineering-plan",
        eventType: "accepted",
        message: "通用多企业产品工程方案 v4.0 已形成。",
        actor: "产品建设代理",
        idempotencyKey: "v4-engineering-plan-accepted-v1",
        createdAt: now,
      },
      {
        projectId: PROJECT_ID,
        taskId: "v4-p0-02-beginner-plan",
        eventType: "accepted",
        message: "通用产品小白易懂方案 v2.0 已形成。",
        actor: "产品建设代理",
        idempotencyKey: "v4-beginner-plan-accepted-v1",
        createdAt: now,
      },
      {
        projectId: PROJECT_ID,
        taskId: "v4-p0-03-progress-center",
        eventType: "ready_for_acceptance",
        message:
          "产品进度中心 v4 已完成实现和本地验证，正在进行私有生产发布。",
        actor: "产品建设代理",
        idempotencyKey: "v4-progress-center-ready-v1",
        createdAt: now,
      },
      {
        projectId: PROJECT_ID,
        taskId: "v4-p0-04-product-owner",
        eventType: "product_model_confirmed",
        message:
          "确认当前用户为外部产品所有者和唯一阶段审批人，不是目标企业员工。",
        actor: "外部产品所有者",
        idempotencyKey: "product-model-v4.0",
        createdAt: now,
      },
      {
        projectId: PROJECT_ID,
        taskId: "v4-p0-05-synthetic-boundary",
        eventType: "synthetic_boundary_confirmed",
        message: "确认 P0—P2 零企业内部资料，P3 才接入目标企业。",
        actor: "外部产品所有者",
        idempotencyKey: "v4-synthetic-boundary-v1",
        createdAt: now,
      },
      {
        projectId: PROJECT_ID,
        taskId: "v4-p0-07-public-context",
        eventType: "public_context_confirmed",
        message:
          "确认 P3 前可以收集有来源的公开企业信息，但不得作为内部事实。",
        actor: "外部产品所有者",
        idempotencyKey: "v4-public-context-v1",
        createdAt: now,
      },
    ])
    .onConflictDoNothing();
}

function percentage(completed: number, total: number) {
  return total === 0 ? 0 : Math.round((completed / total) * 100);
}

function isDuplicateEvent(error: unknown) {
  return (
    error instanceof Error &&
    error.message.includes("task_events.idempotency_key")
  );
}

function configuredProductOwner() {
  return (
    env as unknown as {
      PROJECT_OWNER_EMAIL?: string;
    }
  ).PROJECT_OWNER_EMAIL;
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

async function dashboardData(actor: string | null) {
  await ensureDatabase();
  await seedIfNeeded();
  const db = getDb();

  const [projectRows, taskRows, connectorRows, eventRows] = await Promise.all([
    db.select().from(projects).where(eq(projects.id, PROJECT_ID)).limit(1),
    db
      .select()
      .from(tasks)
      .where(eq(tasks.projectId, PROJECT_ID))
      .orderBy(asc(tasks.phase), asc(tasks.id)),
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

  const phaseProgress = PHASES.map((phase) => {
    const phaseTasks = taskRows.filter((task) => task.phase === phase.code);
    const totalWeight = phaseTasks.reduce((sum, task) => sum + task.weight, 0);
    const acceptedWeight = phaseTasks
      .filter((task) => task.status === "accepted")
      .reduce((sum, task) => sum + task.weight, 0);
    return {
      ...phase,
      accepted: phaseTasks.filter((task) => task.status === "accepted").length,
      total: phaseTasks.length,
      percentage: percentage(acceptedWeight, totalWeight),
    };
  });

  const totalWeight = taskRows.reduce((sum, task) => sum + task.weight, 0);
  const acceptedWeight = taskRows
    .filter((task) => task.status === "accepted")
    .reduce((sum, task) => sum + task.weight, 0);
  const statuses = Object.fromEntries(
    taskRows.map((task) => [task.id, task.status]),
  );
  const currentPhase =
    phaseProgress.find((phase) => phase.percentage < 100)?.code ?? "P3";
  const needsDecision = taskRows.filter(
    (task) => task.status === "awaiting_confirmation",
  );
  const needsAttention = taskRows.filter(
    (task) => task.status === "needs_attention",
  );
  const projectStatus =
    needsAttention.length > 0
      ? "needs_attention"
      : needsDecision.length > 0
        ? "awaiting_confirmation"
        : "moving";
  const lastUpdated = [
    ...taskRows.map((task) => task.updatedAt),
    ...connectorRows.map((connector) => connector.updatedAt),
    ...eventRows.map((event) => event.createdAt),
  ]
    .sort()
    .at(-1);

  return {
    project: {
      ...projectRows[0],
      currentPhase,
      status: projectStatus,
      updatedAt: lastUpdated ?? projectRows[0]?.updatedAt,
    },
    summary: {
      verifiedProgress: percentage(acceptedWeight, totalWeight),
      acceptedTasks: taskRows.filter((task) => task.status === "accepted")
        .length,
      totalTasks: taskRows.length,
      nowDoing: taskRows.filter((task) =>
        ["in_progress", "ready_for_acceptance"].includes(task.status),
      ),
      recentlyCompleted: taskRows
        .filter((task) => task.status === "accepted")
        .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
        .slice(0, 2),
      decisions: needsDecision,
    },
    policy: {
      soleApprover: "外部产品所有者",
      targetEnterpriseRelationship: "NOT_AN_ENTERPRISE_EMPLOYEE",
      enterpriseInputsRequiredNow: currentPhase === "P3",
      enterpriseInputsAllowedFromPhase: "P3",
      publicExternalContextAllowed: true,
      connectorActivationReady: canAdvanceConnector(statuses),
      mutationAuthorized: isProductOwner(actor, configuredProductOwner()),
    },
    phaseProgress,
    tasks: taskRows,
    connectors: connectorRows,
    events: eventRows,
    serverTime: new Date().toISOString(),
  };
}

export async function GET(request: Request) {
  try {
    return Response.json(
      await dashboardData(
        request.headers.get("oai-authenticated-user-email"),
      ),
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
    return Response.json(
      { error: "需要先通过工作区身份验证。" },
      { status: 401 },
    );
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
      { error: "只有外部产品所有者的审批和更新才会被记录。" },
      { status: 403 },
    );
  }
  const actorLabel = await productOwnerActor(actor);

  try {
    const payload = (await request.json()) as {
      action?: string;
      taskId?: string;
      connectorId?: string;
      status?: string;
      maturity?: string;
      note?: string;
      evidence?: string;
      confirmed?: boolean;
      idempotencyKey?: string;
    };
    const idempotencyKey = payload.idempotencyKey?.trim() ?? "";
    if (!idempotencyKey) {
      return Response.json(
        { error: "缺少本次更新的唯一编号。" },
        { status: 400 },
      );
    }

    await ensureDatabase();
    await seedIfNeeded();
    const db = getDb();
    const [duplicate] = await db
      .select({ id: taskEvents.id })
      .from(taskEvents)
      .where(eq(taskEvents.idempotencyKey, idempotencyKey))
      .limit(1);
    if (duplicate) {
      return Response.json({ ok: true, duplicate: true });
    }

    const taskRows = await db
      .select({ id: tasks.id, status: tasks.status })
      .from(tasks)
      .where(eq(tasks.projectId, PROJECT_ID));
    const statuses = Object.fromEntries(
      taskRows.map((task) => [task.id, task.status]),
    );
    const now = new Date().toISOString();
    const d1 = await ensureDatabase();

    if (payload.action === "update_task") {
      const taskId = payload.taskId?.trim() ?? "";
      const nextStatus = payload.status as TaskStatus;
      const [task] = await db
        .select()
        .from(tasks)
        .where(eq(tasks.id, taskId))
        .limit(1);

      if (
        !task ||
        task.projectId !== PROJECT_ID ||
        !TASK_STATUSES.includes(nextStatus)
      ) {
        return Response.json(
          { error: "任务或目标状态无效。" },
          { status: 400 },
        );
      }
      if (
        !ALLOWED_TRANSITIONS[task.status as TaskStatus].includes(nextStatus)
      ) {
        return Response.json(
          { error: "不能从当前状态直接变更到目标状态。" },
          { status: 409 },
        );
      }
      if (
        !["not_started", "deferred"].includes(nextStatus) &&
        !canStartPhase(task.phase, statuses)
      ) {
        return Response.json(
          { error: `${task.phase} 尚未获得上一阶段的产品所有者审批。` },
          { status: 409 },
        );
      }

      const note = payload.note?.trim() ?? "";
      const evidence = payload.evidence?.trim() ?? "";
      if (!note) {
        return Response.json(
          { error: "请用一句话说明这次发生了什么。" },
          { status: 400 },
        );
      }
      if (
        nextStatus === "accepted" &&
        (!payload.confirmed || evidence.length < 5)
      ) {
        return Response.json(
          { error: "标记为已验收前，必须确认并填写证据。" },
          { status: 400 },
        );
      }
      if (
        nextStatus === "accepted" &&
        !isValidStageApprovalEvidence(task.id, evidence)
      ) {
        return Response.json(
          {
            error:
              "阶段审批证据必须包含冻结验收包的 sha256: 内容哈希。",
          },
          { status: 400 },
        );
      }
      if (
        nextStatus === "accepted" &&
        !canAcceptStageGate(task.id, statuses)
      ) {
        return Response.json(
          { error: "该阶段的建设任务尚未全部验收，不能进行阶段审批。" },
          { status: 409 },
        );
      }

      try {
        await d1.batch([
          d1
            .prepare(
              "UPDATE tasks SET status = ?, evidence = ?, updated_at = ? WHERE id = ? AND project_id = ?",
            )
            .bind(
              nextStatus,
              evidence || task.evidence || null,
              now,
              task.id,
              PROJECT_ID,
            ),
          d1
            .prepare(
              `INSERT INTO task_events
                (project_id, task_id, event_type, message, actor, idempotency_key, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)`,
            )
            .bind(
              PROJECT_ID,
              task.id,
              nextStatus,
              note,
              actorLabel,
              idempotencyKey,
              now,
            ),
          d1
            .prepare(
              "UPDATE projects SET updated_at = ?, current_phase = ? WHERE id = ?",
            )
            .bind(now, task.phase, PROJECT_ID),
        ]);
      } catch (error) {
        if (isDuplicateEvent(error)) {
          return Response.json({ ok: true, duplicate: true });
        }
        throw error;
      }
      return Response.json({ ok: true });
    }

    if (payload.action === "update_connector") {
      const connectorId = payload.connectorId?.trim() ?? "";
      const nextStage = payload.maturity as ConnectorStage;
      const [connector] = await db
        .select()
        .from(connectors)
        .where(eq(connectors.id, connectorId))
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
      if (nextIndex > currentIndex && !canAdvanceConnector(statuses)) {
        return Response.json(
          { error: "P2 尚未获产品所有者批准，P3 企业 Connector 保持锁定。" },
          { status: 409 },
        );
      }

      const note = payload.note?.trim() ?? "";
      if (note.length < 5) {
        return Response.json(
          { error: "请说明升级、降级或暂缓的证据与原因。" },
          { status: 400 },
        );
      }
      const evidence = payload.evidence?.trim() ?? "";
      if (
        nextIndex > currentIndex &&
        (!payload.confirmed || evidence.length < 5)
      ) {
        return Response.json(
          { error: "接入阶段向前升级前，必须确认并填写验收证据。" },
          { status: 400 },
        );
      }
      if (
        !isValidConnectorAdvanceEvidence(
          connector.maturity,
          nextStage,
          evidence,
        )
      ) {
        return Response.json(
          {
            error:
              currentIndex === 0
                ? "首次企业接入必须填写 enterprise-authorization: 授权引用和 sha256: 验收哈希。"
                : "Connector 向前升级必须填写 sha256: 验收哈希。",
          },
          { status: 400 },
        );
      }
      const presentation = CONNECTOR_PRESENTATION[nextStage];
      try {
        await d1.batch([
          d1
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
          d1
            .prepare(
              `INSERT INTO task_events
                (project_id, connector_id, event_type, message, actor, idempotency_key, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)`,
            )
            .bind(
              PROJECT_ID,
              connector.id,
              `connector_${nextStage.toLowerCase()}`,
              `${connector.name}：${note}；证据：${evidence || "不适用"}`,
              actorLabel,
              idempotencyKey,
              now,
            ),
          d1
            .prepare("UPDATE projects SET updated_at = ? WHERE id = ?")
            .bind(now, PROJECT_ID),
        ]);
      } catch (error) {
        if (isDuplicateEvent(error)) {
          return Response.json({ ok: true, duplicate: true });
        }
        throw error;
      }
      return Response.json({ ok: true });
    }

    return Response.json({ error: "不支持的更新类型。" }, { status: 400 });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "更新产品进度失败。";
    return Response.json({ error: message }, { status: 500 });
  }
}

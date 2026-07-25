import { asc, desc, eq } from "drizzle-orm";
import { ensureDatabase, getDb } from "../../../db";
import { connectors, projects, taskEvents, tasks } from "../../../db/schema";

export const dynamic = "force-dynamic";

const PROJECT_ID = "zhongbao-ai-platform";
const PHASES = [
  { code: "P0", title: "准备与边界确认" },
  { code: "P1", title: "20—50 人知识助手试点" },
  { code: "P2", title: "部门级生产" },
  { code: "P3", title: "公司级推广" },
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
  accepted: ["in_progress", "needs_attention"],
  needs_attention: ["in_progress", "waiting_external", "deferred"],
  deferred: ["in_progress", "waiting_external"],
};

const CONNECTOR_STAGES = ["C0", "C1", "C2", "C3"] as const;
type ConnectorStage = (typeof CONNECTOR_STAGES)[number];

const CONNECTOR_PRESENTATION: Record<
  ConnectorStage,
  { statusLabel: string; dataMode: string }
> = {
  C0: { statusLabel: "暂缓，尚未接入", dataMode: "DISABLED" },
  C1: { statusLabel: "批准快照", dataMode: "APPROVED_SNAPSHOT" },
  C2: { statusLabel: "真实只读，需判断新鲜度", dataMode: "REAL_READ" },
  C3: { statusLabel: "受控写回", dataMode: "CONTROLLED_WRITE" },
};

async function seedIfNeeded() {
  const db = getDb();
  const now = new Date().toISOString();
  await db
    .insert(projects)
    .values({
      id: PROJECT_ID,
      name: "中宝企业 AI 员工平台",
      scopeVersion: "v3.3-PRE-P0-CENTRAL-REVIEW",
      currentPhase: "P0",
      status: "awaiting_confirmation",
      summary:
        "AI 推荐包已形成；等待总经理授权集中审批人、责任 Owner 核实事实后由你一次性审批；OA、U9、BI 保持 C0。",
      updatedAt: now,
    })
    .onConflictDoNothing();

  const taskSeeds = [
    {
      id: "p0-01-engineering-plan",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "完备工程方案 v3.0",
      plainSummary: "已经把平台先行、以后再接 OA/U9/BI 写成正式工程边界。",
      acceptance: "方案通过独立工程复核，无 P0/P1 问题。",
      status: "accepted",
      owner: "项目提议人（当前唯一执行者）",
      weight: 5,
      nextStep: "作为后续实施和验收基线。",
      evidence: "工程方案 v3.0 已生成并通过独立复核；不代表公司已批准立项。",
      updatedAt: now,
    },
    {
      id: "p0-02-beginner-plan",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "纯小白易懂方案",
      plainSummary: "用非技术语言说明现在做什么、以后怎么接系统。",
      acceptance: "非技术读者能够理解范围、时间、责任和真假进度。",
      status: "accepted",
      owner: "项目提议人（当前唯一执行者）",
      weight: 3,
      nextStep: "用于公司内部沟通和决策。",
      evidence: "小白版方案已生成并通过易读性复核；不代表公司已批准立项。",
      updatedAt: now,
    },
    {
      id: "p0-03-progress-center",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "实时任务进度中心",
      plainSummary: "用一页看清正在做什么、等谁确认、哪些系统暂未接入。",
      acceptance: "构建、数据保存、自动刷新、进度规则和私有发布全部验证通过。",
      status: "ready_for_acceptance",
      owner: "项目提议人（当前唯一执行者）",
      weight: 4,
      nextStep: "私有发布后，由项目负责人确认验收。",
      evidence: "npm test 10/10 通过；API 权限、状态门禁和幂等更新验证通过。",
      updatedAt: now,
    },
    {
      id: "p0-04-pilot-scope",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "总经理授权 P0、任命责任人并指定两级审批人",
      plainSummary:
        "公司先决定是否投入 2—3 周做准备，再实名任命责任人、P0 集中审批人和 P1 阶段门审批人。",
      acceptance:
        "总经理书面决定是否批准；批准时明确人员、投入时间、候选部门、红线、P0 集中审批人和 P1 Go / No-Go 审批人。",
      status: "awaiting_confirmation",
      owner: "总经理（审批）；公司项目负责人待任命",
      weight: 6,
      nextStep: "提交首次审批说明与签批单；未批准前不要求其他员工投入。",
      updatedAt: now,
    },
    {
      id: "p0-05-knowledge-owners",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "收集资料并生成 P0 集中推荐包",
      plainSummary:
        "已把现在、总经理批准后和进入 P1 前所需资料，以及推荐默认值集中成一个包。",
      acceptance:
        "清单覆盖三个阶段、推荐默认值、禁止提交资料和集中审批边界，并可追溯到版本化文件。",
      status: "ready_for_acceptance",
      owner: "项目提议人（当前唯一执行者）",
      weight: 6,
      nextStep: "由你补充当前五类非敏感信息，再提交总经理审批。",
      evidence:
        "implementation/p0/materials-and-recommendations.v1.json 与对应小白版说明已生成。",
      updatedAt: now,
    },
    {
      id: "p0-06-identity-boundary",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "责任 Owner 一次性核实事实并接受责任",
      plainSummary:
        "业务、资料、IT 和安全负责人只核实各自掌握的事实，不再分别审批整套方案。",
      acceptance:
        "每个相关领域都有实名 Owner、事实核实记录、异议或修订项和接受责任记录。",
      status: "not_started",
      owner: "待总经理任命：业务 / 资料 / IT / 安全 Owner",
      weight: 6,
      nextStep: "总经理批准并任命责任人后，一次收集事实核实。",
      updatedAt: now,
    },
    {
      id: "p0-07-data-boundary",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "由你一次性审批冻结推荐包",
      plainSummary:
        "Owner 核实事实后，由总经理书面授权的集中审批人一次性批准、排除或退回整包。",
      acceptance:
        "审批记录绑定推荐包版本、完整内容哈希、审批人、时间、排除项和证据。",
      status: "waiting_external",
      owner: "项目提议人（待总经理书面授权为 P0 集中审批人）",
      weight: 5,
      nextStep: "等待总经理授权和 Owner 事实核实；授权前不得生效。",
      updatedAt: now,
    },
    {
      id: "p0-08-technical-gates",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "建立 P0 技术阶段门",
      plainSummary:
        "用可执行测试证明未接系统、未存凭据、未开出站，并阻止未确认时误进 P1。",
      acceptance: "所有技术门均为 VERIFIED，npm run p0:gate 退出码为 0。",
      status: "in_progress",
      owner: "项目提议人（独立准备技术证据）",
      weight: 5,
      nextStep: "继续完成身份、权限、威胁模型、基础设施和 SLI/SLO 证据。",
      evidence:
        "阶段门 8 项测试、npm 总计 10/10 通过；因总经理授权、Owner 事实核实、集中审批和 P1 最终决定未完成，结果为 NOT_READY。",
      updatedAt: now,
    },
    {
      id: "p0-09-go-no-go",
      projectId: PROJECT_ID,
      phase: "P0",
      title: "P0 Go / No-Go 评审",
      plainSummary: "公司确认和技术证据全部齐全后，才决定是否进入 P1。",
      acceptance: "授权负责人签署 GO，且阶段门自动返回 READY。",
      status: "not_started",
      owner: "总经理书面指定的 P1 阶段门审批人",
      weight: 4,
      nextStep: "等待总经理授权、Owner 事实核实、集中审批和全部技术证据完成。",
      updatedAt: now,
    },
    {
      id: "p1-01-platform",
      projectId: PROJECT_ID,
      phase: "P1",
      title: "建设个人 AI 与控制平台",
      plainSummary: "建立员工入口、个人状态、权限、模型和审计。",
      acceptance: "跨员工和跨部门泄露为零，禁用账号按时失效。",
      status: "not_started",
      owner: "待任命：技术负责人",
      weight: 14,
      nextStep: "P0 范围确认后进入开发。",
      updatedAt: now,
    },
    {
      id: "p1-02-knowledge",
      projectId: PROJECT_ID,
      phase: "P1",
      title: "发布首批知识与 Skills",
      plainSummary: "让 20—50 名员工使用经过批准的资料和 3—5 个工作方法。",
      acceptance: "回答带来源、版本和有效期，真实员工完成真实任务。",
      status: "not_started",
      owner: "待任命：知识与业务负责人",
      weight: 14,
      nextStep: "等待资料和 Skills 清单。",
      updatedAt: now,
    },
    {
      id: "p1-03-pilot",
      projectId: PROJECT_ID,
      phase: "P1",
      title: "完成 20—50 人试点验收",
      plainSummary: "验证真实工作效果，不把模拟演示当作完成。",
      acceptance: "权限、安全、恢复、质量和业务指标全部达到冻结基线。",
      status: "not_started",
      owner: "待任命：试点部门与 QA",
      weight: 10,
      nextStep: "平台和知识准备完成后启动。",
      updatedAt: now,
    },
    {
      id: "p2-01-department-production",
      projectId: PROJECT_ID,
      phase: "P2",
      title: "部门级生产",
      plainSummary: "扩展到 100—200 人，完成高可用、恢复和运营责任。",
      acceptance: "2 倍峰值、故障恢复、连续 30 天运行和高危问题关闭。",
      status: "not_started",
      owner: "待任命：平台与部门 Owner",
      weight: 10,
      nextStep: "P1 通过后进入。",
      updatedAt: now,
    },
    {
      id: "p3-01-company-rollout",
      projectId: PROJECT_ID,
      phase: "P3",
      title: "公司级推广",
      plainSummary: "扩展到 200—500 人，形成稳定运营和费用治理。",
      acceptance: "公司级 SLO、值班、权限复核和成本可持续。",
      status: "not_started",
      owner: "待任命：公司项目组",
      weight: 8,
      nextStep: "P2 通过后逐部门推广。",
      updatedAt: now,
    },
  ];
  await db.insert(tasks).values(taskSeeds.slice(0, 7)).onConflictDoNothing();
  await db.insert(tasks).values(taskSeeds.slice(7)).onConflictDoNothing();

  await db
    .insert(connectors)
    .values(
      ["OA", "U9", "BI"].map((name) => ({
        id: `connector-${name.toLowerCase()}`,
        projectId: PROJECT_ID,
        name,
        maturity: "C0",
        statusLabel: "暂缓，尚未接入",
        dataMode: "DISABLED",
        resumeCondition:
          "系统 Owner 批准，具备正式接口、测试环境、只读身份和权限测试条件。",
        note: "不保存生产凭据，不开放出站网络；当前可选批准快照。",
        updatedAt: now,
      })),
    )
    .onConflictDoNothing();

  await db
    .insert(taskEvents)
    .values([
      {
        projectId: PROJECT_ID,
        taskId: "p0-01-engineering-plan",
        eventType: "accepted",
        message: "完备工程方案 v3.0 已生成并通过独立复核。",
        actor: "项目提议人",
        idempotencyKey: "seed-engineering-plan-v3",
        createdAt: now,
      },
      {
        projectId: PROJECT_ID,
        taskId: "p0-02-beginner-plan",
        eventType: "accepted",
        message: "纯小白易懂方案已生成并通过复核。",
        actor: "项目提议人",
        idempotencyKey: "seed-beginner-plan-v1",
        createdAt: now,
      },
      {
        projectId: PROJECT_ID,
        taskId: "p0-03-progress-center",
        eventType: "ready_for_acceptance",
        message: "实时任务进度中心已通过本地验证，等待私有发布后确认验收。",
        actor: "项目提议人",
        idempotencyKey: "seed-progress-center-ready-v1",
        createdAt: now,
      },
      {
        projectId: PROJECT_ID,
        taskId: "p0-04-pilot-scope",
        eventType: "awaiting_executive_approval",
        message:
          "确认当前只有 1 名项目提议人：公司立项、人员投入和负责人任命均待总经理审批。",
        actor: "项目提议人",
        idempotencyKey: "p0-governance-v3.2",
        createdAt: now,
      },
      {
        projectId: PROJECT_ID,
        taskId: "p0-05-knowledge-owners",
        eventType: "recommendation_package_ready",
        message:
          "P0 分阶段资料清单和 AI 推荐默认值已形成，等待授权、Owner 事实核实和集中审批。",
        actor: "项目提议人",
        idempotencyKey: "p0-central-review-v3.3",
        createdAt: now,
      },
    ])
    .onConflictDoNothing();

  const [project] = await db
    .select()
    .from(projects)
    .where(eq(projects.id, PROJECT_ID))
    .limit(1);
  if (
    project &&
    ["v3.0", "v3.1-P0", "v3.2-PRE-P0-GOV"].includes(project.scopeVersion)
  ) {
    const d1 = await ensureDatabase();
    await d1.batch([
      d1
        .prepare(
          `UPDATE projects
           SET scope_version = ?, summary = ?, updated_at = ?
           WHERE id = ? AND scope_version IN (?, ?, ?)`,
        )
        .bind(
          "v3.3-PRE-P0-CENTRAL-REVIEW",
          "AI 推荐包已形成；等待总经理授权集中审批人、责任 Owner 核实事实后由你一次性审批；OA、U9、BI 保持 C0。",
          now,
          PROJECT_ID,
          "v3.0",
          "v3.1-P0",
          "v3.2-PRE-P0-GOV",
        ),
      d1
        .prepare(
          "UPDATE tasks SET owner = ?, evidence = ?, weight = ?, updated_at = ? WHERE id = ?",
        )
        .bind(
          "项目提议人（当前唯一执行者）",
          "工程方案 v3.0 已生成并通过独立复核；不代表公司已批准立项。",
          5,
          now,
          "p0-01-engineering-plan",
        ),
      d1
        .prepare(
          "UPDATE tasks SET owner = ?, evidence = ?, weight = ?, updated_at = ? WHERE id = ?",
        )
        .bind(
          "项目提议人（当前唯一执行者）",
          "小白版方案已生成并通过易读性复核；不代表公司已批准立项。",
          3,
          now,
          "p0-02-beginner-plan",
        ),
      d1
        .prepare(
          "UPDATE tasks SET owner = ?, weight = ?, evidence = ?, updated_at = ? WHERE id = ?",
        )
        .bind(
          "项目提议人（当前唯一执行者）",
          4,
          "npm test 10/10 通过；API 权限、状态门禁和幂等更新验证通过。",
          now,
          "p0-03-progress-center",
        ),
      d1
        .prepare(
          `UPDATE tasks
           SET title = ?, plain_summary = ?, acceptance = ?, owner = ?,
               weight = ?, next_step = ?, updated_at = ?
           WHERE id = ?`,
        )
        .bind(
          "总经理授权 P0、任命责任人并指定两级审批人",
          "公司先决定是否投入 2—3 周做准备，再实名任命责任人、P0 集中审批人和 P1 阶段门审批人。",
          "总经理书面决定是否批准；批准时明确人员、投入时间、候选部门、红线、P0 集中审批人和 P1 Go / No-Go 审批人。",
          "总经理（审批）；公司项目负责人待任命",
          6,
          "提交首次审批说明与签批单；未批准前不要求其他员工投入。",
          now,
          "p0-04-pilot-scope",
        ),
      d1
        .prepare(
          `UPDATE tasks
           SET title = ?, plain_summary = ?, acceptance = ?,
               status = CASE
                 WHEN status IN ('not_started', 'awaiting_confirmation') AND evidence IS NULL
                   THEN 'ready_for_acceptance'
                 ELSE status
               END,
               owner = ?, weight = ?, next_step = ?,
               evidence = COALESCE(evidence, ?), updated_at = ?
           WHERE id = ?`,
        )
        .bind(
          "收集资料并生成 P0 集中推荐包",
          "已把现在、总经理批准后和进入 P1 前所需资料，以及推荐默认值集中成一个包。",
          "清单覆盖三个阶段、推荐默认值、禁止提交资料和集中审批边界，并可追溯到版本化文件。",
          "项目提议人（当前唯一执行者）",
          6,
          "由你补充当前五类非敏感信息，再提交总经理审批。",
          "implementation/p0/materials-and-recommendations.v1.json 与对应小白版说明已生成。",
          now,
          "p0-05-knowledge-owners",
        ),
      d1
        .prepare(
          `UPDATE tasks
           SET title = ?, plain_summary = ?, acceptance = ?,
               status = CASE
                 WHEN status = 'awaiting_confirmation' AND evidence IS NULL THEN 'not_started'
                 ELSE status
               END,
               owner = ?, weight = ?, next_step = ?, updated_at = ?
           WHERE id = ?`,
        )
        .bind(
          "责任 Owner 一次性核实事实并接受责任",
          "业务、资料、IT 和安全负责人只核实各自掌握的事实，不再分别审批整套方案。",
          "每个相关领域都有实名 Owner、事实核实记录、异议或修订项和接受责任记录。",
          "待总经理任命：业务 / 资料 / IT / 安全 Owner",
          6,
          "总经理批准并任命责任人后，一次收集事实核实。",
          now,
          "p0-06-identity-boundary",
        ),
      d1
        .prepare(
          `UPDATE tasks
           SET title = ?, plain_summary = ?, acceptance = ?,
               status = CASE
                 WHEN status IN ('not_started', 'awaiting_confirmation') AND evidence IS NULL
                   THEN 'waiting_external'
                 ELSE status
               END,
               owner = ?, weight = ?, next_step = ?, updated_at = ?
           WHERE id = ?`,
        )
        .bind(
          "由你一次性审批冻结推荐包",
          "Owner 核实事实后，由总经理书面授权的集中审批人一次性批准、排除或退回整包。",
          "审批记录绑定推荐包版本、完整内容哈希、审批人、时间、排除项和证据。",
          "项目提议人（待总经理书面授权为 P0 集中审批人）",
          5,
          "等待总经理授权和 Owner 事实核实；授权前不得生效。",
          now,
          "p0-07-data-boundary",
        ),
      d1
        .prepare(
          "UPDATE tasks SET owner = ?, evidence = ?, updated_at = ? WHERE id = ?",
        )
        .bind(
          "项目提议人（独立准备技术证据）",
          "阶段门 8 项测试、npm 总计 10/10 通过；因总经理授权、Owner 事实核实、集中审批和 P1 最终决定未完成，结果为 NOT_READY。",
          now,
          "p0-08-technical-gates",
        ),
      d1
        .prepare(
          `UPDATE tasks
           SET status = CASE
                 WHEN status = 'waiting_external' AND evidence IS NULL THEN 'not_started'
                 ELSE status
               END,
               owner = ?, next_step = ?, updated_at = ?
           WHERE id = ?`,
        )
        .bind(
          "总经理书面指定的 P1 阶段门审批人",
          "等待总经理授权、Owner 事实核实、集中审批和全部技术证据完成。",
          now,
          "p0-09-go-no-go",
        ),
      d1
        .prepare("UPDATE tasks SET owner = ?, updated_at = ? WHERE id = ?")
        .bind("待任命：技术负责人", now, "p1-01-platform"),
      d1
        .prepare("UPDATE tasks SET owner = ?, updated_at = ? WHERE id = ?")
        .bind("待任命：知识与业务负责人", now, "p1-02-knowledge"),
      d1
        .prepare("UPDATE tasks SET owner = ?, updated_at = ? WHERE id = ?")
        .bind("待任命：试点部门与 QA", now, "p1-03-pilot"),
      d1
        .prepare("UPDATE tasks SET owner = ?, updated_at = ? WHERE id = ?")
        .bind("待任命：平台与部门 Owner", now, "p2-01-department-production"),
      d1
        .prepare("UPDATE tasks SET owner = ?, updated_at = ? WHERE id = ?")
        .bind("待任命：公司项目组", now, "p3-01-company-rollout"),
      d1
        .prepare(
          `UPDATE task_events
           SET actor = ?
           WHERE idempotency_key IN (?, ?, ?) AND actor = ?`,
        )
        .bind(
          "项目提议人",
          "seed-engineering-plan-v3",
          "seed-beginner-plan-v1",
          "seed-progress-center-ready-v1",
          "项目组",
        ),
      d1
        .prepare(
          `UPDATE task_events
           SET event_type = ?, message = ?, actor = ?
           WHERE idempotency_key = ?`,
        )
        .bind(
          "non_production_preparation_started",
          "个人发起的 P0 非生产准备开始；不代表公司已立项，OA、U9、BI 继续保持 C0。",
          "项目提议人",
          "p0-kickoff-v3.1",
        ),
      d1
        .prepare(
          `INSERT OR IGNORE INTO task_events
            (project_id, event_type, message, actor, idempotency_key, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          PROJECT_ID,
          "awaiting_executive_approval",
          "确认当前只有 1 名项目提议人：公司立项、人员投入和负责人任命均待总经理审批。",
          "项目提议人",
          "p0-governance-v3.2",
          now,
        ),
      d1
        .prepare(
          `INSERT OR IGNORE INTO task_events
            (project_id, task_id, event_type, message, actor, idempotency_key, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          PROJECT_ID,
          "p0-05-knowledge-owners",
          "recommendation_package_ready",
          "P0 分阶段资料清单和 AI 推荐默认值已形成，等待授权、Owner 事实核实和集中审批。",
          "项目提议人",
          "p0-central-review-v3.3",
          now,
        ),
    ]);
  }
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

async function dashboardData() {
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
    phaseProgress,
    tasks: taskRows,
    connectors: connectorRows,
    events: eventRows,
    serverTime: new Date().toISOString(),
  };
}

export async function GET() {
  try {
    return Response.json(await dashboardData());
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "读取项目进度失败。";
    return Response.json({ error: message }, { status: 500 });
  }
}

export async function POST(request: Request) {
  const actor = request.headers.get("oai-authenticated-user-email");
  if (!actor) {
    return Response.json(
      { error: "只有通过工作区身份验证的项目负责人可以更新进度。" },
      { status: 401 },
    );
  }

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

      if (!task || !TASK_STATUSES.includes(nextStatus)) {
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
          { error: "标记为已验收前，必须确认验收并填写证据。" },
          { status: 400 },
        );
      }

      try {
        await d1.batch([
          d1
            .prepare(
              "UPDATE tasks SET status = ?, evidence = ?, updated_at = ? WHERE id = ?",
            )
            .bind(nextStatus, evidence || task.evidence || null, now, task.id),
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
              actor,
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
      if (!connector || !CONNECTOR_STAGES.includes(nextStage)) {
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
      const presentation = CONNECTOR_PRESENTATION[nextStage];
      try {
        await d1.batch([
          d1
            .prepare(
              `UPDATE connectors
               SET maturity = ?, status_label = ?, data_mode = ?, note = ?, updated_at = ?
               WHERE id = ?`,
            )
            .bind(
              nextStage,
              presentation.statusLabel,
              presentation.dataMode,
              note,
              now,
              connector.id,
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
              actor,
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
      error instanceof Error ? error.message : "更新项目进度失败。";
    return Response.json({ error: message }, { status: 500 });
  }
}

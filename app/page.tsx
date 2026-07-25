"use client";

import {
  type CSSProperties,
  type FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

type TaskStatus =
  | "not_started"
  | "in_progress"
  | "ready_for_acceptance"
  | "awaiting_confirmation"
  | "waiting_external"
  | "accepted"
  | "needs_attention"
  | "deferred";

type Task = {
  id: string;
  phase: string;
  title: string;
  plainSummary: string;
  acceptance: string;
  status: TaskStatus;
  owner: string;
  weight: number;
  nextStep: string;
  blockedReason: string | null;
  evidence: string | null;
  updatedAt: string;
};

type Connector = {
  id: string;
  name: string;
  maturity: "C0" | "C1" | "C2" | "C3";
  statusLabel: string;
  dataMode: string;
  resumeCondition: string;
  note: string;
  updatedAt: string;
};

type EventItem = {
  id: number;
  eventType: string;
  message: string;
  actor: string;
  createdAt: string;
};

type DashboardData = {
  project: {
    name: string;
    scopeVersion: string;
    currentPhase: string;
    status: string;
    summary: string;
    updatedAt: string;
  };
  summary: {
    verifiedProgress: number;
    acceptedTasks: number;
    totalTasks: number;
    nowDoing: Task[];
    recentlyCompleted: Task[];
    decisions: Task[];
  };
  policy: {
    soleApprover: string;
    targetEnterpriseRelationship: string;
    enterpriseInputsRequiredNow: boolean;
    enterpriseInputsAllowedFromPhase: string;
    publicExternalContextAllowed: boolean;
    connectorActivationReady: boolean;
    mutationAuthorized: boolean;
  };
  phaseProgress: Array<{
    code: string;
    title: string;
    accepted: number;
    total: number;
    percentage: number;
  }>;
  tasks: Task[];
  connectors: Connector[];
  events: EventItem[];
  serverTime: string;
};

const STATUS_LABELS: Record<TaskStatus, string> = {
  not_started: "未开始",
  in_progress: "正在进行",
  ready_for_acceptance: "待验收",
  awaiting_confirmation: "等待产品所有者审批",
  waiting_external: "等待外部条件",
  accepted: "已验收",
  needs_attention: "需要处理",
  deferred: "已暂缓",
};

const STATUS_GROUPS = [
  { key: "all", label: "全部任务" },
  { key: "in_progress", label: "正在进行" },
  { key: "awaiting_confirmation", label: "等待产品所有者审批" },
  { key: "waiting_external", label: "等待外部条件" },
  { key: "accepted", label: "已验收" },
] as const;

const TASK_TRANSITIONS: Record<TaskStatus, TaskStatus[]> = {
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

function formatTime(value?: string) {
  if (!value) return "尚无记录";
  return new Intl.DateTimeFormat("zh-CN", {
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function statusTone(status: TaskStatus) {
  if (status === "accepted") return "green";
  if (status === "awaiting_confirmation") return "amber";
  if (status === "needs_attention") return "red";
  if (status === "waiting_external" || status === "deferred") return "gray";
  if (status === "in_progress" || status === "ready_for_acceptance")
    return "blue";
  return "neutral";
}

function uniqueKey() {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
}

export default function Home() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [connected, setConnected] = useState(true);
  const [lastSync, setLastSync] = useState<Date | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [editingTask, setEditingTask] = useState<Task | null>(null);
  const [editingConnector, setEditingConnector] = useState<Connector | null>(
    null,
  );
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);
  const [formIdempotencyKey, setFormIdempotencyKey] = useState("");

  const load = useCallback(async () => {
    try {
      const response = await fetch("/api/progress", { cache: "no-store" });
      const result = (await response.json()) as DashboardData & {
        error?: string;
      };
      if (!response.ok) throw new Error(result.error ?? "读取失败");
      setData(result);
      setConnected(true);
      setLastSync(new Date());
    } catch {
      setConnected(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const initialLoad = window.setTimeout(() => void load(), 0);
    const timer = window.setInterval(() => void load(), 5000);
    const onOnline = () => void load();
    const onOffline = () => setConnected(false);
    window.addEventListener("online", onOnline);
    window.addEventListener("offline", onOffline);
    return () => {
      window.clearTimeout(initialLoad);
      window.clearInterval(timer);
      window.removeEventListener("online", onOnline);
      window.removeEventListener("offline", onOffline);
    };
  }, [load]);

  const filteredTasks = useMemo(() => {
    if (!data) return [];
    if (filter === "all") return data.tasks;
    if (filter === "in_progress") {
      return data.tasks.filter((task) =>
        ["in_progress", "ready_for_acceptance"].includes(task.status),
      );
    }
    if (filter === "waiting_external") {
      return data.tasks.filter((task) =>
        ["waiting_external", "deferred"].includes(task.status),
      );
    }
    return data.tasks.filter((task) => task.status === filter);
  }, [data, filter]);

  async function submitTask(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editingTask) return;
    setSaving(true);
    setFormError("");
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/progress", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          action: "update_task",
          taskId: editingTask.id,
          status: form.get("status"),
          note: form.get("note"),
          evidence: form.get("evidence"),
          confirmed: form.get("confirmed") === "on",
          idempotencyKey: formIdempotencyKey,
        }),
      });
      const result = (await response.json()) as { error?: string };
      if (!response.ok) throw new Error(result.error ?? "更新失败");
      setEditingTask(null);
      await load();
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "更新失败");
    } finally {
      setSaving(false);
    }
  }

  async function submitConnector(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editingConnector) return;
    setSaving(true);
    setFormError("");
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/progress", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          action: "update_connector",
          connectorId: editingConnector.id,
          maturity: form.get("maturity"),
          note: form.get("note"),
          evidence: form.get("evidence"),
          confirmed: form.get("confirmed") === "on",
          idempotencyKey: formIdempotencyKey,
        }),
      });
      const result = (await response.json()) as { error?: string };
      if (!response.ok) throw new Error(result.error ?? "更新失败");
      setEditingConnector(null);
      await load();
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "更新失败");
    } finally {
      setSaving(false);
    }
  }

  if (loading && !data) {
    return (
      <main className="loading-screen" aria-live="polite">
        <div className="loading-mark">多企业 AI</div>
        <p>正在读取真实任务状态…</p>
      </main>
    );
  }

  if (!data) {
    return (
      <main className="loading-screen">
        <div className="loading-mark error">暂时无法读取</div>
        <p>请检查网络后重试。当前页面没有继续播放虚假的进度。</p>
        <button className="primary-button" onClick={() => void load()}>
          重新连接
        </button>
      </main>
    );
  }

  const progressStyle = {
    "--progress": `${data.summary.verifiedProgress}%`,
  } as CSSProperties;
  const topDoing = data.summary.nowDoing[0];
  const recent = data.summary.recentlyCompleted[0];
  const decision = data.summary.decisions[0];

  return (
    <main>
      <header className="topbar">
        <div>
          <span className="eyebrow">通用多企业产品 · AI 平台</span>
          <h1>产品建设进度中心</h1>
        </div>
        <div className="sync-box" aria-live="polite">
          <span
            className={`connection-dot ${connected ? "online" : "offline"}`}
          />
          <div>
            <strong>{connected ? "实时连接正常" : "当前不是实时数据"}</strong>
            <small>
              {lastSync
                ? `上次同步 ${formatTime(lastSync.toISOString())}`
                : "尚未同步"}
            </small>
          </div>
          <button className="icon-button" onClick={() => void load()}>
            刷新
          </button>
        </div>
      </header>

      <section className="hero">
        <div className="hero-copy">
          <div className="phase-pill">
            当前阶段 {data.project.currentPhase} ·{" "}
            {data.project.status === "awaiting_confirmation"
              ? "等待产品所有者审批"
              : data.project.status === "needs_attention"
                ? "需要处理"
                : "正常推进"}
          </div>
          <h2>P0-P2 只使用合成数据建设通用产品；P3 才接入目标企业。</h2>
          <p>{data.project.summary}</p>
          <div className="truth-note">
            你是外部产品所有者；你不是目标企业员工。每个阶段只记录你的最终审批结果，不追踪其他部门审批过程。进度只计算“已验收”的任务。
            {data.policy.mutationAuthorized
              ? " 当前审批身份已验证。"
              : " 当前会话是只读状态，只有被配置的产品所有者身份可以更新。"}
          </div>
        </div>
        <div className="progress-panel">
          <div className="progress-ring" style={progressStyle}>
            <div>
              <strong>{data.summary.verifiedProgress}%</strong>
              <span>已验证进度</span>
            </div>
          </div>
          <p>
            {data.summary.acceptedTasks} / {data.summary.totalTasks}{" "}
            项任务已验收
          </p>
          <small>P3 前不接收企业内部资料，也不激活企业 Connector</small>
          <small>范围版本 {data.project.scopeVersion}</small>
        </div>
      </section>

      <section className="three-things" aria-labelledby="three-things-title">
        <div className="section-heading">
          <span>产品所有者视角</span>
          <h2 id="three-things-title">你现在只需要知道三件事</h2>
        </div>
        <div className="three-grid">
          <article className="focus-card blue-card">
            <span>正在做什么</span>
            <h3>{topDoing?.title ?? "当前没有进行中的任务"}</h3>
            <p>{topDoing?.plainSummary ?? "等待下一项任务开始。"}</p>
          </article>
          <article className="focus-card green-card">
            <span>最近完成</span>
            <h3>{recent?.title ?? "尚无已验收任务"}</h3>
            <p>{recent?.evidence ?? "完成后会显示验收证据。"}</p>
          </article>
          <article className="focus-card amber-card">
            <span>下一项待审批</span>
            <h3>{decision?.title ?? "当前无待你审批事项"}</h3>
            <p>{decision?.nextStep ?? "阶段验收条件满足后会在这里出现。"}</p>
          </article>
        </div>
      </section>

      <section className="roadmap" aria-labelledby="roadmap-title">
        <div className="section-heading inline-heading">
          <div>
            <span>路线图</span>
            <h2 id="roadmap-title">P0—P3 阶段进度</h2>
          </div>
          <p>P0—P2 建系统和产品包；P3 才接企业、真实用户与系统。</p>
        </div>
        <div className="phase-grid">
          {data.phaseProgress.map((phase) => (
            <article
              className={`phase-card ${
                phase.code === data.project.currentPhase ? "current" : ""
              }`}
              key={phase.code}
            >
              <div className="phase-topline">
                <strong>{phase.code}</strong>
                <span>{phase.percentage}%</span>
              </div>
              <h3>{phase.title}</h3>
              <div className="mini-progress">
                <span style={{ width: `${phase.percentage}%` }} />
              </div>
              <p>
                {phase.accepted} / {phase.total} 项已验收
              </p>
            </article>
          ))}
        </div>
      </section>

      <section className="task-section" aria-labelledby="tasks-title">
        <div className="section-heading inline-heading">
          <div>
            <span>任务</span>
            <h2 id="tasks-title">真实任务状态</h2>
          </div>
          <p>点击任务可查看验收条件和证据。</p>
        </div>
        <div className="filters" role="group" aria-label="筛选任务">
          {STATUS_GROUPS.map((item) => (
            <button
              className={filter === item.key ? "active" : ""}
              key={item.key}
              onClick={() => setFilter(item.key)}
            >
              {item.label}
            </button>
          ))}
        </div>
        <div className="task-grid">
          {filteredTasks.map((task) => (
            <article className="task-card" key={task.id}>
              <div className="task-card-top">
                <span className="phase-label">{task.phase}</span>
                <span className={`status-badge ${statusTone(task.status)}`}>
                  {STATUS_LABELS[task.status]}
                </span>
              </div>
              <h3>{task.title}</h3>
              <p>{task.plainSummary}</p>
              <dl>
                <div>
                  <dt>负责人</dt>
                  <dd>{task.owner}</dd>
                </div>
                <div>
                  <dt>下一步</dt>
                  <dd>{task.nextStep}</dd>
                </div>
              </dl>
              <details>
                <summary>查看验收条件与证据</summary>
                <p>
                  <strong>验收条件：</strong>
                  {task.acceptance}
                </p>
                <p>
                  <strong>当前证据：</strong>
                  {task.evidence ?? "尚未提交验收证据"}
                </p>
                <p className="updated">更新于 {formatTime(task.updatedAt)}</p>
              </details>
              <button
                className="secondary-button"
                disabled={
                  task.status === "accepted" ||
                  !data.policy.mutationAuthorized
                }
                onClick={() => {
                  setFormError("");
                  setFormIdempotencyKey(uniqueKey());
                  setEditingTask(task);
                }}
              >
                {task.status === "accepted"
                  ? "验收记录已冻结"
                  : data.policy.mutationAuthorized
                    ? "更新这项任务"
                    : "仅产品所有者可更新"}
              </button>
            </article>
          ))}
        </div>
      </section>

      <section className="connector-section" aria-labelledby="connectors-title">
        <div className="section-heading inline-heading">
          <div>
            <span>企业接入（P3）</span>
            <h2 id="connectors-title">企业 Connector 接入状态</h2>
          </div>
          <p>P2 未批准前保持 C0，只建设可复用的 Connector Template。</p>
        </div>
        <div className="connector-grid">
          {data.connectors.map((connector) => (
            <article className="connector-card" key={connector.id}>
              <div className="connector-name">
                <strong>{connector.name}</strong>
                <span>{connector.maturity}</span>
              </div>
              <h3>{connector.statusLabel}</h3>
              <p>{connector.note}</p>
              <div className="resume-box">
                <span>恢复条件</span>
                <p>{connector.resumeCondition}</p>
              </div>
              <button
                className="secondary-button"
                disabled={!data.policy.mutationAuthorized}
                onClick={() => {
                  setFormError("");
                  setFormIdempotencyKey(uniqueKey());
                  setEditingConnector(connector);
                }}
              >
                {data.policy.mutationAuthorized
                  ? "更新接入状态"
                  : "仅产品所有者可更新"}
              </button>
            </article>
          ))}
        </div>
      </section>

      <section className="activity-section" aria-labelledby="activity-title">
        <div className="section-heading">
          <span>记录</span>
          <h2 id="activity-title">最近活动与证据</h2>
        </div>
        <div className="timeline">
          {data.events.map((item) => (
            <article key={item.id}>
              <span className="timeline-dot" />
              <div>
                <strong>{item.message}</strong>
                <p>
                  {item.actor} · {formatTime(item.createdAt)}
                </p>
              </div>
            </article>
          ))}
        </div>
      </section>

      <details className="rules">
        <summary>看板如何防止“假进度”</summary>
        <ul>
          <li>进行中不增加总完成度，只有“已验收”才计入。</li>
          <li>标记已验收必须填写证据并再次确认。</li>
          <li>P0—P2 只使用合成数据，不接收任何企业内部资料。</li>
          <li>有来源的公开企业信息可预先收集，但不作为企业内部事实。</li>
          <li>只有你能批准阶段；其他部门的过程不在本项目中追踪。</li>
          <li>企业 Connector 在 P3 前固定为 C0，不能跳过中间门禁。</li>
          <li>网络中断会显示上次同步时间，不继续宣称实时。</li>
          <li>已验收记录不可覆盖；发现问题时建立新版本并保留原证据。</li>
        </ul>
      </details>

      <footer>
        <strong>通用多企业 AI 员工平台</strong>
        <span>上次真实更新 {formatTime(data.project.updatedAt)}</span>
      </footer>

      {editingTask && (
        <div className="modal-backdrop" role="presentation">
          <form className="modal" onSubmit={submitTask}>
            <div className="modal-heading">
              <div>
                <span>{editingTask.phase} · 更新任务</span>
                <h2>{editingTask.title}</h2>
              </div>
              <button
                type="button"
                className="close-button"
                aria-label="关闭"
                onClick={() => setEditingTask(null)}
              >
                ×
              </button>
            </div>
            <label>
              新状态
              <select name="status" required defaultValue="">
                <option value="" disabled>
                  请选择
                </option>
                {TASK_TRANSITIONS[editingTask.status].map((status) => (
                  <option key={status} value={status}>
                    {STATUS_LABELS[status]}
                  </option>
                ))}
              </select>
            </label>
            <label>
              这次发生了什么
              <textarea
                name="note"
                required
                placeholder="例如：该项合成数据验收已完成。"
              />
            </label>
            <label>
              验收证据
              <textarea
                name="evidence"
                placeholder="标记为已验收时必填，可填写报告、测试结果或确认记录。"
              />
            </label>
            <label className="checkbox-row">
              <input type="checkbox" name="confirmed" />
              我确认：如果选择“已验收”，上述证据真实有效。
            </label>
            {formError && <p className="form-error">{formError}</p>}
            <button className="primary-button" disabled={saving}>
              {saving ? "正在保存…" : "保存真实进度"}
            </button>
          </form>
        </div>
      )}

      {editingConnector && (
        <div className="modal-backdrop" role="presentation">
          <form className="modal" onSubmit={submitConnector}>
            <div className="modal-heading">
              <div>
                <span>更新 Connector</span>
                <h2>{editingConnector.name}</h2>
              </div>
              <button
                type="button"
                className="close-button"
                aria-label="关闭"
                onClick={() => setEditingConnector(null)}
              >
                ×
              </button>
            </div>
            <label>
              接入阶段
              <select
                name="maturity"
                required
                defaultValue={editingConnector.maturity}
              >
                <option value="C0">C0 · 尚未接入</option>
                <option
                  value="C1"
                  disabled={!data.policy.connectorActivationReady}
                >
                  C1 · 企业批准快照
                </option>
                <option
                  value="C2"
                  disabled={!data.policy.connectorActivationReady}
                >
                  C2 · 企业真实只读
                </option>
                <option
                  value="C3"
                  disabled={!data.policy.connectorActivationReady}
                >
                  C3 · 企业受控写回
                </option>
              </select>
            </label>
            <label>
              证据与原因
              <textarea
                name="note"
                required
                placeholder="说明 P3 接入授权、测试证据或暂缓原因。"
              />
            </label>
            <label>
              向前升级的证据
              <textarea
                name="evidence"
                placeholder="向前升级需填写 sha256: 哈希；首次 C0→C1 还需 enterprise-authorization: 授权引用。"
              />
            </label>
            <label className="checkbox-row">
              <input type="checkbox" name="confirmed" />
              我确认：如果接入阶段向前升级，上述证据真实有效。
            </label>
            <p className="form-hint">
              {data.policy.connectorActivationReady
                ? "系统不能从 C0 跳过 C1 直接进入 C2。"
                : "P2 产品就绪审批尚未通过，C1—C3 仍被锁定。"}
            </p>
            {formError && <p className="form-error">{formError}</p>}
            <button className="primary-button" disabled={saving}>
              {saving ? "正在保存…" : "保存接入状态"}
            </button>
          </form>
        </div>
      )}
    </main>
  );
}

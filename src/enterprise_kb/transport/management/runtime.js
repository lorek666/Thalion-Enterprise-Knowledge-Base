const ui = Object.fromEntries([
  "lock", "access", "token", "lock-message", "workspace", "title", "refresh", "logout", "status", "stages",
].map(name => [name, document.getElementById(`runtime-${name}`)]));

const stages = { parse: "资料解析", synthetic_model_excerpts: "合成模型任务", other: "其他任务" };
const states = {
  external_budget_blocked: "预算阻断", awaiting_external: "等待外部回执", retry_delayed: "延时重试",
  lease_expired: "租约已过期", inconsistent: "状态待核对", ready: "待领取", leased: "租约有效",
};
const warn = new Set(["external_budget_blocked", "awaiting_external", "lease_expired", "inconsistent"]);
const time = new Intl.DateTimeFormat("zh-CN", {
  timeZone: "UTC", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit",
  minute: "2-digit", second: "2-digit", hourCycle: "h23",
});
let session = null;

function text(tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  return node;
}

function resetSnapshot() {
  ui.stages.replaceChildren();
  ui.stages.setAttribute("aria-busy", "false");
  ui.status.textContent = "";
}

function lock(message = "", focus = false) {
  if (session !== null) {
    session.pending?.abort();
    session.token = "";
  }
  session = null;
  ui.token.value = "";
  resetSnapshot();
  ui.workspace.hidden = true;
  ui.lock.hidden = false;
  ui["lock-message"].textContent = message;
  if (focus) ui.token.focus();
}

function metric(label, value, warning = false) {
  const item = document.createElement("div");
  const name = text("dt", label, warning ? "wiki-state" : "");
  if (warning) name.dataset.state = "needs_rebuild";
  item.append(name, text("dd", value));
  return item;
}

function ageLabel(ageMs) {
  const minutes = Math.floor(ageMs / 60_000);
  if (!minutes) return "不足 1 分钟";
  const hours = Math.floor(minutes / 60);
  return hours ? `${hours} 小时 ${minutes % 60} 分钟` : `${minutes} 分钟`;
}

function stageRow(stage, backlog, throughput) {
  const row = text("li", "", "wiki-topic");
  const heading = text("div", "", "wiki-topic-header");
  heading.append(text("h3", stages[stage] ?? stages.other),
    text("span", `未完成 ${backlog?.unfinished ?? 0}`, "wiki-generation"));
  const counters = text("dl", "", "wiki-counts");
  const succeeded = throughput?.succeeded ?? 0;
  counters.append(metric("近一小时已知入队", throughput?.enqueued ?? 0), metric("近一小时成功完成", succeeded));
  for (const [state, label] of Object.entries(states)) {
    const count = backlog?.states[state];
    if (count) counters.append(metric(label, count, warn.has(state)));
  }
  const age = backlog?.oldest_known_age_ms;
  if (age != null) counters.append(metric("最长已知队龄", ageLabel(age)));
  if (backlog?.unknown_enqueue_time) {
    counters.append(metric("入队时间未知", backlog.unknown_enqueue_time));
  }
  row.append(heading, counters);
  if (age >= 3_600_000 && succeeded === 0) {
    row.append(text("p", "存在已入队一小时以上的任务，近一小时无成功完成。", "wiki-generation"));
  }
  if (backlog?.next_retry_at) {
    const retry = text("p", "", "wiki-generation");
    retry.append(text("strong", "最早计划重试"), ` ${time.format(new Date(backlog.next_retry_at))} UTC`);
    row.append(retry);
  }
  if (backlog) {
    const minutes = backlog.estimated_clear_minutes;
    const estimate = minutes == null ? "暂无可靠估计" : `约 ${minutes} 分钟（按近一小时速率）`;
    row.append(text("p", `预计清空：${estimate}`, "wiki-generation"));
  }
  return row;
}

async function load() {
  const owner = session;
  if (owner === null) return;
  owner.pending?.abort();
  const controller = new AbortController();
  owner.pending = controller;
  const current = () => session === owner && owner.pending === controller && !controller.signal.aborted;
  resetSnapshot();
  ui.stages.setAttribute("aria-busy", "true");
  ui.status.textContent = "正在读取任务积压…";
  try {
    const response = await fetch("/internal/runtime/backlog", {
      headers: { Authorization: `Bearer ${owner.token}` }, signal: controller.signal, cache: "no-store",
      credentials: "omit", mode: "same-origin", redirect: "error", referrerPolicy: "no-referrer",
    });
    if (!current()) return;
    if (response.status === 401) return lock("凭据无效或已过期，请重新载入。", true);
    if (response.status === 403) return lock("当前凭据无权查看任务积压。", true);
    if (!response.ok) throw new Error("Runtime backlog is unavailable.");
    const { observed_at: observedAt, job_backlog_by_stage: backlog, job_throughput_by_stage: throughput } =
      await response.json();
    if (!current()) return;
    const observed = `快照 ${time.format(new Date(observedAt))} UTC`;
    const unfinished = new Map(backlog.map(entry => [entry.stage, entry]));
    const recent = new Map(throughput.map(entry => [entry.stage, entry]));
    ui.stages.replaceChildren(...Object.keys(stages)
      .filter(stage => unfinished.has(stage) || recent.has(stage))
      .map(stage => stageRow(stage, unfinished.get(stage), recent.get(stage))));
    ui.status.textContent = backlog.length ? observed : `没有未完成的任务。${observed}`;
  } catch {
    if (current()) ui.status.textContent = "暂时无法读取任务积压，请刷新重试。";
  } finally {
    if (current()) {
      ui.stages.setAttribute("aria-busy", "false");
      owner.pending = null;
    }
  }
}

ui.access.addEventListener("submit", event => {
  event.preventDefault();
  const token = ui.token.value.trim();
  lock();
  if (!/^[A-Za-z0-9_.-]{32,16384}$/.test(token)) return lock("请输入完整的本机管理测试凭据。", true);
  session = { token, pending: null };
  ui.lock.hidden = true;
  ui.workspace.hidden = false;
  ui.title.focus();
  load();
});
ui.refresh.addEventListener("click", load);
ui.logout.addEventListener("click", () => lock("已退出，凭据与快照已清除。", true));
window.addEventListener("pagehide", () => lock());
window.addEventListener("pageshow", event => {
  if (event.persisted) lock("页面已重新锁定，请载入凭据。");
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) lock("页面已锁定，请重新载入凭据。");
});
lock();

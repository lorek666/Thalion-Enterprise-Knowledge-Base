const ui = Object.fromEntries([
  "lock", "login", "token", "lock-message", "workspace", "board-title", "refresh", "logout", "list-status",
  "items", "next", "action-status", "detail", "detail-title", "selection", "read", "evidence", "assign",
  "assignee", "process", "correction-label", "correction", "corrected", "explain", "conclusion-fields", "conclusion",
  "verify", "retest", "quality", "quarantine",
].map(name => [name, document.getElementById(`work-${name}`)]));

const states = { pending: "待核对", awaiting_retest: "已修正待复测" };
const categories = { incorrect_evidence: "引用有疑点", missing_evidence: "缺少依据" };
const confirmations = {
  assign: "已保存分派。", mark_corrected: "已登记修正，等待提交人复测。",
  explain: "已记录解释决定。", verify_correction: "已复核并关闭工单。", quarantine: "已隔离转录批次。工单仍待处理。",
};
const opaqueRef = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const endpoint = "/internal/feedback";
let session = null;

function text(tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  return node;
}

function clearDetail() {
  if (session) {
    session.selected = null;
    session.basis = null;
    session.write = null;
    session.saving = false;
  }
  ui.detail.hidden = true;
  ui.selection.textContent = "";
  ui.evidence.replaceChildren();
  ui.assignee.value = "";
  ui.correction.value = "";
  ui.retest.value = "";
  ui.conclusion.value = "";
  ui.conclusion.disabled = true;
  ui.explain.disabled = true;
  ui.quality.hidden = true;
}

function lock(message = "", focus = false) {
  if (session) {
    session.task?.abort();
    session.token = "";
  }
  clearDetail();
  session = null;
  ui.workspace.hidden = true;
  ui.lock.hidden = false;
  ui.token.value = "";
  ui.items.replaceChildren();
  ui.items.setAttribute("aria-busy", "false");
  ui.next.hidden = true;
  ui["list-status"].textContent = "";
  ui["action-status"].textContent = "";
  ui["lock-message"].textContent = message;
  if (focus) ui.token.focus();
}

async function request(path, argumentsToSend, key) {
  const employee = session;
  if (!employee) return null;
  employee.task?.abort();
  const task = new AbortController();
  employee.task = task;
  const current = () => session === employee && employee.task === task && !task.signal.aborted;
  const headers = { Authorization: `Bearer ${employee.token}` };
  if (argumentsToSend) {
    headers["Content-Type"] = "application/json";
    headers["Idempotency-Key"] = key;
  }
  try {
    const response = await fetch(path, {
      method: argumentsToSend ? "POST" : "GET", headers, body: argumentsToSend ? JSON.stringify(argumentsToSend) : undefined,
      signal: task.signal, cache: "no-store", credentials: "omit", mode: "same-origin", redirect: "error",
      referrerPolicy: "no-referrer",
    });
    if (!current()) return null;
    if (response.status === 401) {
      lock("凭据无效或已过期，请重新载入。", true);
      return null;
    }
    const payload = response.ok ? await response.json() : null;
    return current() ? { status: response.status, payload } : null;
  } catch {
    return current() ? { status: 503, payload: null } : null;
  }
}

function choose(item) {
  if (!session) return;
  session.task?.abort();
  clearDetail();
  session.selected = item;
  ui["action-status"].textContent = "";
  ui.selection.textContent = `${item.feedback_id} · ${states[item.state]}`;
  ui.read.hidden = !item.has_citation;
  ui.assign.hidden = session.role !== "owner" || item.state !== "pending";
  const awaiting = item.state === "awaiting_retest";
  ui.process.hidden = session.role !== "assignee";
  ui.correction.required = !item.has_citation || awaiting;
  ui["correction-label"].textContent = item.has_citation ? "更正取证请求编号" : "补源取证请求编号";
  ui.corrected.textContent = item.has_citation ? (awaiting ? "更新更正依据" : "登记已修正")
    : (awaiting ? "更新补源依据" : "登记补源");
  ui["conclusion-fields"].hidden = ui.process.hidden || awaiting || !item.has_citation;
  ui.verify.hidden = session.role !== "owner" || item.state !== "awaiting_retest";
  ui.detail.hidden = false;
  ui["detail-title"].focus();
}

function workRow(item) {
  const row = text("li", "", "wiki-topic");
  const summary = text("div", "", "wiki-topic-header");
  summary.append(text("h3", item.feedback_id), text("span", item.assigned ? "已分派" : "未分派", "wiki-generation"));
  const open = text("button", "打开工单", "quiet-button");
  open.type = "button";
  open.addEventListener("click", () => choose(item));
  row.append(summary, text("span", states[item.state], "wiki-state"), text("span", categories[item.category], "wiki-generation"));
  const actions = text("div", "", "work-buttons");
  actions.append(open);
  row.append(actions);
  return row;
}

async function load(after = null, message = "") {
  if (!session) return;
  clearDetail();
  ui.items.replaceChildren();
  ui.items.setAttribute("aria-busy", "true");
  ui.next.hidden = true;
  ui["action-status"].textContent = message;
  ui["list-status"].textContent = "正在读取待办…";
  const suffix = after === null ? "" : `?after=${encodeURIComponent(after)}`;
  const response = await request(endpoint + suffix);
  if (!response) return;
  ui.items.setAttribute("aria-busy", "false");
  if (response.status === 403) return lock("当前凭据未获准查看纠错队列。", true);
  if (response.status !== 200) {
    ui["list-status"].textContent = "暂时无法读取待办，请刷新重试。";
    return;
  }
  const { role, items, next_cursor: cursor } = response.payload;
  session.role = role;
  session.after = after;
  session.next = cursor;
  ui.next.hidden = cursor === null;
  ui.items.replaceChildren(...items.map(workRow));
  ui["list-status"].textContent = items.length ? (role === "owner" ? "本空间待办" : "分派给我的待办") : "当前没有待办工单。";
}

async function readEvidence() {
  const selected = session?.selected;
  if (!selected || session.saving) return;
  session.basis = null;
  ui.conclusion.value = "";
  ui.conclusion.disabled = true;
  ui.explain.disabled = true;
  ui.quality.hidden = true;
  ui.evidence.replaceChildren();
  ui["action-status"].textContent = "正在核对原文权限…";
  const response = await request(`${endpoint}/${selected.feedback_id}/evidence`);
  if (!response || session.selected !== selected) return;
  if (response.status !== 200) {
    ui["action-status"].textContent = response.status === 503 ? "取证暂不可用，请重试。" : "无法查看这条原文，请确认工单分派和本人读权。";
    return;
  }
  const { request_id: requestId, passage } = response.payload;
  const location = passage.location;
  const column = location.columns?.[0];
  const position = passage.source_type === "docx" && Number.isInteger(location.table)
    ? [...location.heading_path, `第 ${location.table} 表`, `第 ${location.row_id} 行`].join(" / ")
      + ` · ${location.columns.length} 个单元格`
    : passage.source_type === "csv"
    ? `第 ${location.row_id} 行 / 第 ${column.column} 列（${column.header}）`
    : passage.source_type === "pdf"
      ? `第 ${location.page} 页（PDF 转录）`
      : [...location.heading_path, `第 ${location.paragraph} 段`].join(" / ");
  const article = text("article", "", "passage original work-original");
  article.append(
    text("h3", passage.title), text("p", `版本 ${passage.version_label} / 转录修订 ${passage.excerpt_revision}`, "version"),
    text("p", passage.source_type === "csv" ? passage.excerpt : passage.excerpt.trim(), "excerpt"),
    text("p", position, "meta"),
  );
  ui.evidence.replaceChildren(article);
  ui["action-status"].textContent = "已按本人权限核对。";
  session.basis = requestId;
  ui.conclusion.disabled = false;
  ui.quality.hidden = session.role !== "owner" || selected.state !== "pending";
}

async function transition(action, fields = {}) {
  const selected = session?.selected;
  if (!selected || session.saving) return;
  if (Object.entries(fields).some(([name, value]) => name !== "conclusion_code" && !opaqueRef.test(value))) {
    ui["action-status"].textContent = "请输入完整的编号。";
    return;
  }
  const quarantine = action === "quarantine";
  const command = { expected_generation: selected.generation, ...(quarantine ? {} : { action }), ...fields };
  const input = JSON.stringify([action, command]);
  if (session.write?.input !== input) session.write = { input, key: crypto.randomUUID() };
  ui.evidence.replaceChildren();
  session.saving = true;
  ui["action-status"].textContent = "正在保存处理决定…";
  const response = await request(`${endpoint}/${selected.feedback_id}/${quarantine ? "quarantine" : "transitions"}`,
                                 command, session.write.key);
  if (!response || session.selected !== selected) return;
  session.saving = false;
  if (response.status === 200) {
    ui["board-title"].focus();
    return load(session.after, confirmations[action]);
  }
  if (response.status === 409) {
    return load(session.after, "工单已变化或尚未满足条件，请重新核对。");
  }
  ui["action-status"].textContent = response.status === 403 ? "当前凭据无法执行此操作。" : "暂未确认保存结果，请重试。";
}

for (const [form, handler] of [
  [ui.assign, () => transition("assign", { assignee_ref: ui.assignee.value.trim() })],
  [ui.process, () => {
    const correction = ui.correction.value.trim();
    return transition("mark_corrected", correction ? { correction_request_id: correction } : {});
  }],
  [ui.verify, () => transition("verify_correction", { retest_request_id: ui.retest.value.trim() })],
]) {
  form.addEventListener("submit", event => { event.preventDefault(); handler(); });
}
ui.login.addEventListener("submit", event => {
  event.preventDefault();
  const token = ui.token.value.trim();
  lock();
  if (!/^[A-Za-z0-9_.-]{32,16384}$/.test(token)) return lock("请输入完整的本机办理测试凭据。", true);
  session = { token };
  ui.lock.hidden = true;
  ui.workspace.hidden = false;
  ui["board-title"].focus();
  load();
});
ui.refresh.addEventListener("click", () => load());
ui.next.addEventListener("click", () => { if (session?.next) load(session.next); });
ui.logout.addEventListener("click", () => lock("已清除凭据和工单。", true));
ui.read.addEventListener("click", readEvidence);
ui.conclusion.addEventListener("change", () => {
  ui.explain.disabled = !session?.basis || !ui.conclusion.value;
});
ui.explain.addEventListener("click", () => {
  if (session?.basis && ui.conclusion.value) {
    transition("explain", { basis_request_id: session.basis, conclusion_code: ui.conclusion.value });
  }
});
ui.quarantine.addEventListener("click", () => { if (session?.basis) transition("quarantine", { basis_request_id: session.basis }); });
window.addEventListener("pagehide", () => lock());
window.addEventListener("pageshow", event => { if (event.persisted) lock("此页面已重新锁定，请载入凭据。"); });
document.addEventListener("visibilitychange", () => { if (document.hidden) lock("页面已锁定，请重新载入凭据。"); });
lock();

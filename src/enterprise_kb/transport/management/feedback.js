const ui = Object.fromEntries([
  "lock", "login", "token", "lock-message", "workspace", "board-title", "refresh", "logout", "list-status",
  "items", "next", "action-status", "detail", "detail-title", "selection", "read", "evidence", "assign",
  "assignee", "process", "correction-label", "correction", "corrected", "explain", "conclusion-fields", "conclusion",
  "verify", "retest", "quality", "quarantine", "login-button",
].map(name => [name, document.getElementById(`work-${name}`)]));
const gapUi = Object.fromEntries([
  "workspace", "refresh", "logout", "list-status", "items", "previous", "next", "action-status", "board-title",
  "detail", "detail-title", "selection", "review", "classification", "save",
].map(name => [name, document.getElementById(`gap-${name}`)]));

const states = { pending: "待核对", awaiting_retest: "已修正待复测" };
const categories = { incorrect_evidence: "引用有疑点", missing_evidence: "缺少依据" };
const confirmations = {
  assign: "已保存分派。", mark_corrected: "已登记修正，等待提交人复测。",
  explain: "已记录解释决定。", verify_correction: "已复核并关闭工单。", quarantine: "已隔离转录批次。工单仍待处理。",
};
const opaqueRef = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const endpoint = "/internal/feedback";
const gapEndpoint = `${endpoint}/gaps`;
const gapClasses = { reported_missing: "员工报告缺少依据", no_visible_match: "搜索未找到可见依据" };
const reviewClasses = new Set(["conditions_missing", "permission_review"]);
const feedbackTab = document.getElementById("feedback-tab");
const gapTab = document.getElementById("gap-tab");
const pageTitle = document.getElementById("management-title");
const pageDescription = document.getElementById("management-description");
const pageSubnote = document.getElementById("page-subnote");
const feedbackCopy = [document.title, pageTitle.textContent, pageDescription.textContent, pageSubnote.textContent];
let session = null;
let gapView;

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

function clearGapDetail() {
  if (session) session.gapSelected = null;
  gapUi.detail.hidden = true;
  gapUi.selection.textContent = "";
  gapUi.classification.value = "";
}

function clearWorkspaces() {
  session?.task?.abort();
  clearDetail();
  clearGapDetail();
  setGapSaving(false);
  for (const board of [ui, gapUi]) {
    board.workspace.hidden = true;
    board.items.replaceChildren();
    board.items.setAttribute("aria-busy", "false");
    board.next.hidden = true;
    board["list-status"].textContent = "";
    board["action-status"].textContent = "";
  }
  gapUi.previous.hidden = true;
}

function lock(message = "", focus = false) {
  clearWorkspaces();
  if (session) session.token = "";
  session = null;
  ui.lock.hidden = false;
  ui.token.value = "";
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

function chooseGap(item) {
  if (!session || !gapView || session.gapSaving) return;
  clearGapDetail();
  session.gapSelected = item;
  gapUi["action-status"].textContent = "";
  gapUi.selection.textContent = `${item.gap_id} · ${gapClasses[item.classification] ?? "未识别分类"}`;
  gapUi.detail.hidden = false;
  gapUi["detail-title"].focus();
}

function gapRow(item) {
  const row = text("li", "", "wiki-topic");
  const summary = text("div", "", "wiki-topic-header");
  summary.append(text("h3", item.gap_id), text("span", `版本 ${item.generation}`, "wiki-generation"));
  row.append(summary, text("span", gapClasses[item.classification] ?? "未识别分类", "wiki-state"));
  const actions = text("div", "", "work-buttons");
  const open = text("button", "处理这条缺口", "quiet-button");
  open.type = "button";
  open.addEventListener("click", () => chooseGap(item));
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

async function loadGaps(cursors, message = "") {
  if (!session || !gapView || session.gapSaving) return;
  const after = cursors.at(-1);
  session.gapCursors = cursors;
  session.gapNext = null;
  clearGapDetail();
  gapUi.items.replaceChildren();
  gapUi.items.setAttribute("aria-busy", "true");
  gapUi.previous.hidden = true;
  gapUi.next.hidden = true;
  gapUi["action-status"].textContent = message;
  gapUi["list-status"].textContent = "正在读取缺口队列…";
  const suffix = after === null ? "" : `?after=${encodeURIComponent(after)}`;
  const response = await request(gapEndpoint + suffix);
  if (!response) return;
  gapUi.items.setAttribute("aria-busy", "false");
  if (response.status === 403) {
    session.gapCursors = [null];
    gapUi["list-status"].textContent = "当前凭据未获准查看缺口队列。";
    return;
  }
  gapUi.previous.hidden = cursors.length === 1;
  if (response.status !== 200) {
    gapUi["list-status"].textContent = "暂时无法读取缺口队列，请刷新重试。";
    return;
  }
  const { items, next_cursor: cursor } = response.payload;
  session.gapNext = cursor;
  gapUi.next.hidden = cursor === null;
  gapUi.items.replaceChildren(...items.map(gapRow));
  gapUi["list-status"].textContent = items.length ? `第 ${cursors.length} 页 · 本页 ${items.length} 条`
    : after === null ? "当前没有待处理的搜索缺口。" : "本页已无待处理缺口，可返回上一页。";
}

function setGapSaving(saving) {
  if (session) session.gapSaving = saving;
  for (const control of [gapUi.classification, gapUi.save, gapUi.refresh, gapUi.previous, gapUi.next,
    ...gapUi.items.querySelectorAll("button")]) {
    control.disabled = saving;
  }
}

async function reclassifyGap() {
  const selected = session?.gapSelected;
  const classification = gapUi.classification.value;
  if (!selected || session.gapSaving || !reviewClasses.has(classification)) return;
  const command = { expected_generation: selected.generation, classification };
  const input = JSON.stringify([selected.gap_id, command]);
  if (session.gapWrite?.input !== input) session.gapWrite = { input, key: crypto.randomUUID() };
  setGapSaving(true);
  gapUi["action-status"].textContent = "正在保存缺口归类…";
  const response = await request(`${gapEndpoint}/${encodeURIComponent(selected.gap_id)}/reclassify`, command, session.gapWrite.key);
  if (!response || session?.gapSelected !== selected) return;
  setGapSaving(false);
  if (response.status === 200 || response.status === 409) {
    session.gapWrite = null;
    gapUi["board-title"].focus();
    return loadGaps(session.gapCursors, response.status === 200 ? "已保存缺口归类。" : "缺口已变化，请重新核对后再保存。");
  }
  gapUi["action-status"].textContent = response.status === 403 ? "当前凭据无法办理这条缺口。" : "暂未确认保存结果，请重试。";
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

function openWorkspace() {
  const board = gapView ? gapUi : ui;
  ui.lock.hidden = true;
  board.workspace.hidden = false;
  board["board-title"].focus();
  if (gapView) loadGaps([null]);
  else load();
}

function selectView() {
  const showGaps = new URLSearchParams(location.search).get("view") === "gaps";
  if (showGaps === gapView) return;
  gapView = showGaps;
  clearWorkspaces();
  for (const [tab, active] of [[feedbackTab, !gapView], [gapTab, gapView]]) {
    tab.classList.toggle("active", active);
    if (active) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  }
  const [title, heading, description, subnote] = gapView ? [
    "搜索缺口队列 · 知识库管理后台", "管理搜索缺口队列",
    "查看本空间待核对的搜索缺口。队列不显示员工的原始搜索或反馈正文。", "核对并归类待处理缺口",
  ] : feedbackCopy;
  document.title = title;
  pageTitle.textContent = heading;
  pageDescription.textContent = description;
  pageSubnote.textContent = subnote;
  document.getElementById("feedback-notice").hidden = gapView;
  ui["login-button"].textContent = gapView ? "查看缺口队列" : "查看员工报错";
  ui["login-button"].setAttribute("aria-label", gapView ? "查看缺口队列" : "查看待办");
  ui["lock-message"].textContent = "";
  if (session) openWorkspace();
}

for (const tab of [feedbackTab, gapTab]) {
  tab.addEventListener("click", event => {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    if (tab.href !== location.href) history.pushState(null, "", tab.href);
    selectView();
  });
}
window.addEventListener("popstate", selectView);
ui.login.addEventListener("submit", event => {
  event.preventDefault();
  const token = ui.token.value.trim();
  lock();
  if (!/^[A-Za-z0-9_.-]{32,16384}$/.test(token)) return lock("请输入完整的本机办理测试凭据。", true);
  session = { token };
  openWorkspace();
});
ui.refresh.addEventListener("click", () => load());
ui.next.addEventListener("click", () => { if (session?.next) load(session.next); });
gapUi.refresh.addEventListener("click", () => { if (session) loadGaps(session.gapCursors); });
gapUi.previous.addEventListener("click", () => {
  if (session?.gapCursors.length > 1) {
    gapUi["board-title"].focus();
    loadGaps(session.gapCursors.slice(0, -1));
  }
});
gapUi.next.addEventListener("click", () => {
  if (session?.gapNext) {
    gapUi["board-title"].focus();
    loadGaps([...session.gapCursors, session.gapNext]);
  }
});
ui.logout.addEventListener("click", () => lock("已清除凭据和工单。", true));
gapUi.logout.addEventListener("click", () => lock("已清除凭据和缺口。", true));
gapUi.review.addEventListener("submit", event => { event.preventDefault(); reclassifyGap(); });
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
selectView();

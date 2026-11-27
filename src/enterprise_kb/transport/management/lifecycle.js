const ui = Object.fromEntries([
  "lock", "lock-message", "access", "token", "workspace", "logout",
  "retention-form", "retention-source", "retention-expected", "retention-days",
  "retention-action", "retention-basis", "retention-submit", "retention-status",
  "hold-form", "hold-version", "hold-action", "hold-generation",
  "hold-basis", "hold-submit", "hold-status",
  "plan-form", "plan-version", "plan-action", "plan-reason",
  "plan-btn", "submit-case-btn", "plan-status", "plan-summary", "plan-copies",
  "case-form", "case-id", "case-snapshot", "case-basis", "case-ttl", "case-approval-id",
  "case-approve-btn", "case-reject-btn", "case-verify-btn", "case-tombstone-btn", "case-status",
  "audit-form", "audit-source", "audit-request", "audit-load", "audit-more", "audit-status", "audit-list",
].map(name => [name, document.getElementById(`lifecycle-${name}`)]));

const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const sha256Hex = /^[0-9a-f]{64}$/;
const statusMessages = {
  400: "请求参数无效，请核对编号、代次、快照摘要或有效期。",
  401: "凭据无效或已过期，请更换凭据。",
  403: "当前身份无权执行该生命周期或审计操作（管理/审计权限不授予原文读权）。",
  409: "策略代次、保全状态、处置清点快照或幂等键冲突，请刷新核对。",
  503: "生命周期或审计服务暂不可用，请稍后重试。",
};
const unknownResult = "未收到服务结果，请保留表单原样重试。";
let session = null;

function clearList(element) {
  while (element.firstChild) element.removeChild(element.firstChild);
}

function appendItem(list, text) {
  const item = document.createElement("li");
  item.textContent = text;
  list.appendChild(item);
}

function clearWorkspace() {
  for (const formKey of ["retention-form", "hold-form", "plan-form", "case-form", "audit-form"]) {
    ui[formKey].reset();
    ui[formKey].inert = false;
  }
  for (const statusKey of ["retention-status", "hold-status", "plan-status", "plan-summary", "case-status", "audit-status"]) {
    ui[statusKey].textContent = "";
  }
  clearList(ui["plan-copies"]);
  clearList(ui["audit-list"]);
  ui["audit-more"].hidden = true;
}

function lock(message = "") {
  session?.pending?.abort();
  session = null;
  clearWorkspace();
  ui.token.value = "";
  ui.workspace.hidden = true;
  ui.lock.hidden = false;
  ui["lock-message"].textContent = message;
}

function idempotencyKey(activeSession, slot, path, body) {
  if (activeSession[slot]?.path !== path || activeSession[slot].body !== body) {
    activeSession[slot] = { path, body, key: crypto.randomUUID() };
  }
  return activeSession[slot].key;
}

async function callApi(activeSession, path, { method = "GET", body = null, key = null } = {}) {
  const pending = new AbortController();
  activeSession.pending = pending;
  const headers = { "Authorization": `Bearer ${activeSession.token}` };
  if (body !== null) headers["Content-Type"] = "application/json";
  if (key !== null) headers["Idempotency-Key"] = key;
  try {
    const response = await fetch(path, { method, headers, body, signal: pending.signal });
    if (session !== activeSession) return null;
    if (!response.ok) return { ok: false, status: response.status };
    const data = await response.json();
    if (session !== activeSession) return null;
    return { ok: true, data };
  } catch {
    if (session !== activeSession) return null;
    return { ok: false, status: 0 };
  } finally {
    if (session === activeSession) activeSession.pending = null;
  }
}

ui.access.addEventListener("submit", event => {
  event.preventDefault();
  if (session) return;
  const token = ui.token.value.trim();
  if (!token) {
    ui["lock-message"].textContent = "请输入管理测试凭据。";
    return;
  }
  session = { token, preview: null, auditAfter: null, auditSource: null };
  ui.token.value = "";
  ui["lock-message"].textContent = "";
  ui.lock.hidden = true;
  ui.workspace.hidden = false;
  ui["retention-source"].focus();
});

ui.logout.addEventListener("click", () => {
  lock();
  ui.token.focus();
});
window.addEventListener("pagehide", () => lock());
window.addEventListener("pageshow", event => {
  if (event.persisted) lock("页面已重新锁定，请载入管理凭据。");
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) lock("页面已锁定，请重新载入管理凭据。");
});

ui["retention-form"].addEventListener("submit", async event => {
  event.preventDefault();
  const activeSession = session;
  if (!activeSession || activeSession.pending) return;
  const sourceId = ui["retention-source"].value.trim();
  const basisId = ui["retention-basis"].value.trim();
  const expectedRevision = Number.parseInt(ui["retention-expected"].value, 10);
  const keepDays = Number.parseInt(ui["retention-days"].value, 10);
  const action = ui["retention-action"].value;
  if (!uuid.test(sourceId) || !uuid.test(basisId) || !Number.isInteger(expectedRevision) || expectedRevision < 0 ||
      !Number.isInteger(keepDays) || keepDays < 0) {
    ui["retention-status"].textContent = statusMessages[400];
    return;
  }
  const path = "/internal/lifecycle/retention-policy";
  const body = JSON.stringify({
    source_id: sourceId, expected_revision: expectedRevision, keep_days: keepDays, action, basis_id: basisId,
  });
  const key = idempotencyKey(activeSession, "retentionCmd", path, body);
  ui["retention-form"].inert = true;
  ui["retention-status"].textContent = "正在登记保留策略…";
  const result = await callApi(activeSession, path, { method: "POST", body, key });
  if (session !== activeSession || !result) return;
  ui["retention-form"].inert = false;
  if (!result.ok) {
    ui["retention-status"].textContent = statusMessages[result.status] || unknownResult;
    return;
  }
  ui["retention-status"].textContent = `已登记保留策略：${result.data.policy_id}（第 ${result.data.revision} 版）`;
  ui["retention-expected"].value = String(result.data.revision);
});

ui["hold-form"].addEventListener("submit", async event => {
  event.preventDefault();
  const activeSession = session;
  if (!activeSession || activeSession.pending) return;
  const versionId = ui["hold-version"].value.trim();
  const basisId = ui["hold-basis"].value.trim();
  const action = ui["hold-action"].value;
  const expectedGeneration = Number.parseInt(ui["hold-generation"].value, 10);
  if (!uuid.test(versionId) || !uuid.test(basisId) || !Number.isInteger(expectedGeneration) || expectedGeneration < 0) {
    ui["hold-status"].textContent = statusMessages[400];
    return;
  }
  const path = "/internal/lifecycle/holds";
  const body = JSON.stringify({
    version_id: versionId, action, expected_generation: expectedGeneration, basis_id: basisId,
  });
  const key = idempotencyKey(activeSession, "holdCmd", path, body);
  ui["hold-form"].inert = true;
  ui["hold-status"].textContent = "正在记录保全决定…";
  const result = await callApi(activeSession, path, { method: "POST", body, key });
  if (session !== activeSession || !result) return;
  ui["hold-form"].inert = false;
  if (!result.ok) {
    ui["hold-status"].textContent = statusMessages[result.status] || unknownResult;
    return;
  }
  ui["hold-status"].textContent = `已记录保全决定：${result.data.decision_id}（状态：${result.data.state}，代次：${result.data.generation}）`;
  ui["hold-generation"].value = String(result.data.generation);
});

ui["plan-form"].addEventListener("submit", async event => {
  event.preventDefault();
  const activeSession = session;
  if (!activeSession || activeSession.pending) return;
  clearList(ui["plan-copies"]);
  ui["plan-summary"].textContent = "";
  const versionId = ui["plan-version"].value.trim();
  const action = ui["plan-action"].value;
  const reason = ui["plan-reason"].value;
  if (!uuid.test(versionId)) {
    ui["plan-status"].textContent = "请输入有效的处置目标版本编号。";
    return;
  }
  const path = "/internal/lifecycle/disposition-preview";
  const body = JSON.stringify({ version_id: versionId, action, reason });
  ui["plan-form"].inert = true;
  ui["plan-status"].textContent = "正在生成处置清点预览…";
  const result = await callApi(activeSession, path, { method: "POST", body });
  if (session !== activeSession || !result) return;
  ui["plan-form"].inert = false;
  if (!result.ok) {
    ui["plan-status"].textContent = statusMessages[result.status] || unknownResult;
    return;
  }
  const data = result.data;
  activeSession.preview = {
    version_id: data.version_id,
    action: data.action,
    reason: data.reason,
    inventory_snapshot: data.inventory_snapshot,
  };
  ui["case-snapshot"].value = data.inventory_snapshot;
  const protections = data.protections && data.protections.length > 0 ? data.protections.join(", ") : "无阻断保护";
  ui["plan-summary"].textContent =
    `处置判定：${data.decision}｜保护关系：${protections}｜策略版本：${data.policy_revision}｜清点快照：${data.inventory_snapshot}`;
  for (const copy of data.copies || []) {
    appendItem(ui["plan-copies"], `本地副本：${copy.kind}（状态：${copy.state}，编号：${copy.ref}）`);
  }
  if (data.unverified_copy_kinds && data.unverified_copy_kinds.length > 0) {
    appendItem(ui["plan-copies"], `待核验副本类型：${data.unverified_copy_kinds.join(", ")}`);
  }
  ui["plan-status"].textContent = "已生成处置清点预览。";
});

ui["submit-case-btn"].addEventListener("click", async () => {
  const activeSession = session;
  if (!activeSession || activeSession.pending) return;
  if (!activeSession.preview) {
    ui["plan-status"].textContent = "请先执行“预览处置清点”获取当前清点快照。";
    return;
  }
  const path = "/internal/lifecycle/disposition-cases";
  const body = JSON.stringify(activeSession.preview);
  const key = idempotencyKey(activeSession, "submitCaseCmd", path, body);
  ui["plan-form"].inert = true;
  ui["plan-status"].textContent = "正在提交处置申请…";
  const result = await callApi(activeSession, path, { method: "POST", body, key });
  if (session !== activeSession || !result) return;
  ui["plan-form"].inert = false;
  if (!result.ok) {
    ui["plan-status"].textContent = statusMessages[result.status] || unknownResult;
    return;
  }
  ui["case-id"].value = result.data.case_id;
  ui["case-snapshot"].value = result.data.inventory_snapshot;
  ui["plan-status"].textContent = `已提交处置申请：${result.data.case_id}（状态：${result.data.state}）`;
});

async function runCaseAction(actionKind) {
  const activeSession = session;
  if (!activeSession || activeSession.pending) return;
  const caseId = ui["case-id"].value.trim();
  const snapshot = ui["case-snapshot"].value.trim();
  const basisId = ui["case-basis"].value.trim();
  const approvalId = ui["case-approval-id"].value.trim();
  if (!uuid.test(caseId) || !sha256Hex.test(snapshot)) {
    ui["case-status"].textContent = "请输入有效的处置案件编号和 64 位小写清点快照摘要。";
    return;
  }
  let path = "";
  let payload = null;
  if (actionKind === "approve") {
    const ttl = Number.parseInt(ui["case-ttl"].value, 10);
    if (!uuid.test(basisId) || !Number.isInteger(ttl) || ttl < 1 || ttl > 14) {
      ui["case-status"].textContent = "独立批准需要有效的依据编号和 1–14 分钟有效期。";
      return;
    }
    path = `/internal/lifecycle/disposition-cases/${caseId}/approval`;
    payload = {
      inventory_snapshot: snapshot,
      basis_id: basisId,
      expires_at: new Date(Date.now() + ttl * 60_000).toISOString(),
    };
  } else if (actionKind === "reject") {
    if (!uuid.test(basisId)) {
      ui["case-status"].textContent = "驳回处置申请需要有效的复核依据编号。";
      return;
    }
    path = `/internal/lifecycle/disposition-cases/${caseId}/rejection`;
    payload = { inventory_snapshot: snapshot, basis_id: basisId };
  } else if (actionKind === "verify") {
    path = `/internal/lifecycle/disposition-cases/${caseId}/original-verification`;
    payload = { inventory_snapshot: snapshot };
  } else if (actionKind === "tombstone") {
    if (!uuid.test(approvalId)) {
      ui["case-status"].textContent = "登记删除墓碑需要已批准决定编号。";
      return;
    }
    path = `/internal/lifecycle/disposition-cases/${caseId}/deletion-tombstone`;
    payload = { approval_id: approvalId, inventory_snapshot: snapshot };
  }
  const body = JSON.stringify(payload);
  const key = idempotencyKey(activeSession, `caseCmd_${actionKind}`, path, body);
  ui["case-form"].inert = true;
  ui["case-status"].textContent = "正在提交处置案件操作…";
  const result = await callApi(activeSession, path, { method: "POST", body, key });
  if (session !== activeSession || !result) return;
  ui["case-form"].inert = false;
  if (!result.ok) {
    ui["case-status"].textContent = statusMessages[result.status] || unknownResult;
    return;
  }
  if (actionKind === "approve") {
    ui["case-approval-id"].value = result.data.decision_id;
    ui["case-status"].textContent = `已独立批准处置：${result.data.decision_id}（状态：${result.data.state}）`;
  } else if (actionKind === "reject") {
    ui["case-status"].textContent = `已驳回处置申请：${result.data.decision_id}（状态：${result.data.state}）`;
  } else if (actionKind === "verify") {
    ui["case-status"].textContent = `原件摘要核验完成：${result.data.verification_id}（状态：${result.data.state}）`;
  } else if (actionKind === "tombstone") {
    ui["case-status"].textContent = `已登记删除墓碑：${result.data.tombstone_id}（状态：${result.data.state}）`;
  }
}

ui["case-approve-btn"].addEventListener("click", () => runCaseAction("approve"));
ui["case-reject-btn"].addEventListener("click", () => runCaseAction("reject"));
ui["case-verify-btn"].addEventListener("click", () => runCaseAction("verify"));
ui["case-tombstone-btn"].addEventListener("click", () => runCaseAction("tombstone"));

async function loadAuditPage(append) {
  const activeSession = session;
  if (!activeSession || activeSession.pending) return;
  const sourceId = ui["audit-source"].value.trim();
  const requestFilter = ui["audit-request"].value.trim();
  if (!uuid.test(sourceId) || (requestFilter && !uuid.test(requestFilter))) {
    ui["audit-status"].textContent = "请输入有效的审计来源编号（及可选请求编号）。";
    return;
  }
  if (!append) {
    clearList(ui["audit-list"]);
    activeSession.auditAfter = null;
    activeSession.auditSource = sourceId;
  }
  let query = "";
  if (requestFilter) {
    query = `?request_id=${encodeURIComponent(requestFilter)}`;
  } else if (append && activeSession.auditAfter) {
    query = `?after=${encodeURIComponent(activeSession.auditAfter)}`;
  }
  ui["audit-form"].inert = true;
  ui["audit-status"].textContent = "正在查询按来源审计记录…";
  const result = await callApi(activeSession, `/internal/sources/${sourceId}/audit${query}`);
  if (session !== activeSession || !result) return;
  ui["audit-form"].inert = false;
  if (!result.ok) {
    ui["audit-status"].textContent = statusMessages[result.status] || unknownResult;
    return;
  }
  const items = result.data.requests || [];
  if (!append && items.length === 0) {
    appendItem(ui["audit-list"], "当前来源暂无符合条件的审计请求记录。");
  }
  for (const row of items) {
    const elapsed = row.elapsed_ms === null || row.elapsed_ms === undefined ? "-" : `${row.elapsed_ms}ms`;
    appendItem(
      ui["audit-list"],
      `请求 ${row.request_id}｜操作：${row.operation}｜目标：${row.destination}｜结果：${row.outcome}｜耗时：${elapsed}｜开始：${row.started_at}`,
    );
  }
  activeSession.auditAfter = result.data.next_after || null;
  ui["audit-more"].hidden = !activeSession.auditAfter;
  ui["audit-status"].textContent = `已加载 ${items.length} 条审计元数据（不含原文内容）。`;
}

ui["audit-form"].addEventListener("submit", event => {
  event.preventDefault();
  loadAuditPage(false);
});
ui["audit-more"].addEventListener("click", () => loadAuditPage(true));

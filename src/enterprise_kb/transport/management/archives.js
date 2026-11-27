const ui = Object.fromEntries([
  "lock", "access", "token", "lock-message", "workspace", "request-panel", "request-title",
  "role-badge", "refresh", "logout", "request-form", "source-checks", "version-checks",
  "wiki-checks", "request-btn", "request-status", "status", "list",
].map(name => [name, document.getElementById(`archives-${name}`)]));

const stateLabels = {
  requested: "待独立审批",
  approved: "已批准待封存",
  approval_expired: "审批已过期",
  sealed: "已封存",
};
const utcTime = new Intl.DateTimeFormat("zh-CN", {
  timeZone: "UTC", year: "numeric", month: "2-digit", day: "2-digit",
  hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
});
let session = null;
let latestData = null;

function text(tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = String(value);
  if (className) node.className = className;
  return node;
}

function formatUtc(isoString) {
  if (!isoString) return "暂无";
  return `${utcTime.format(new Date(isoString))} UTC`;
}

function idempotencyKey(prefix) {
  const rand = typeof crypto !== "undefined" && crypto.randomUUID
    ? crypto.randomUUID().replace(/-/g, "")
    : `${Date.now()}_${Math.random().toString(16).slice(2, 12)}`;
  return `${prefix}_${rand}`.slice(0, 96);
}

function lock(message = "", focus = false) {
  session = null;
  latestData = null;
  ui.token.value = "";
  ui["request-status"].textContent = "";
  ui.status.textContent = "";
  ui["source-checks"].replaceChildren();
  ui["version-checks"].replaceChildren();
  ui["wiki-checks"].replaceChildren();
  ui.list.replaceChildren();
  ui.workspace.hidden = true;
  ui.lock.hidden = false;
  ui["lock-message"].textContent = message;
  if (focus) ui.token.focus();
}

async function apiJson(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (session?.token) headers.Authorization = `Bearer ${session.token}`;
  const response = await fetch(url, { ...options, headers, cache: "no-store", credentials: "same-origin" });
  const data = await response.json().catch(() => null);
  return { ok: response.ok, status: response.status, data };
}

function renderScopePickers(data) {
  const roles = data.caller_roles || {};
  const roleNames = [];
  if (roles.is_space_owner) roleNames.push("空间负责人");
  if (roles.is_source_approver) roleNames.push("来源独立审批人");
  ui["role-badge"].textContent = roleNames.join(" / ") || "只读";
  ui["request-form"].hidden = !roles.is_space_owner;

  ui["source-checks"].replaceChildren();
  for (const src of data.available_sources || []) {
    const label = document.createElement("label");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.name = "source_id";
    cb.value = src.source_id;
    cb.checked = Boolean(src.owned_by_caller);
    label.append(cb, text("span", `${src.source_key} (${src.source_id})`));
    ui["source-checks"].append(label);
  }
  if (!data.available_sources?.length) {
    ui["source-checks"].append(text("p", "当前空间暂无来源。", "wiki-generation"));
  }

  ui["version-checks"].replaceChildren();
  for (const ver of data.available_versions || []) {
    const label = document.createElement("label");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.name = "version_id";
    cb.value = ver.version_id;
    cb.checked = Boolean(ver.archive_eligible);
    const suffix = ver.archive_eligible ? "（可归档）" : "（待解析审批，暂不可归档）";
    label.append(cb, text("span", `${ver.display_name} · ${ver.version_label} (${ver.media_type}) ${suffix} [${ver.version_id}]`));
    ui["version-checks"].append(label);
  }
  if (!data.available_versions?.length) {
    ui["version-checks"].append(text("p", "当前空间暂无文档版本。", "wiki-generation"));
  }

  ui["wiki-checks"].replaceChildren();
  for (const wk of data.available_wikis || []) {
    const label = document.createElement("label");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.name = "wiki_revision_id";
    cb.value = wk.revision_id;
    label.append(cb, text("span", `${wk.topic_key} · 修订 ${wk.revision_id}`));
    ui["wiki-checks"].append(label);
  }
  if (!data.available_wikis?.length) {
    ui["wiki-checks"].append(text("p", "当前空间暂无可用已发布 Wiki。", "wiki-generation"));
  }
}

async function approveArchive(exportId, minutesInput, msgBox, button) {
  if (!session) return;
  const minutes = Number(minutesInput.value);
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 15) {
    msgBox.textContent = "批准有效分钟数必须为 1 至 15 的整数。";
    return;
  }
  button.disabled = true;
  msgBox.textContent = "正在提交独立审批...";
  const expiresAt = new Date(Date.now() + minutes * 60_000).toISOString();
  try {
    const res = await apiJson(`/internal/lifecycle/space-archives/${encodeURIComponent(exportId)}/approve`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey("arch_approve"),
      },
      body: JSON.stringify({ expires_at: expiresAt }),
    });
    if (res.status === 401) {
      lock("凭据已失效，请重新载入。", true);
      return;
    }
    if (!res.ok) {
      msgBox.textContent = res.data?.error?.message || `审批失败（HTTP ${res.status}）。`;
      return;
    }
    await loadArchives(`已独立批准归档申请 ${exportId}。`);
  } catch {
    msgBox.textContent = "提交审批时网络异常。";
  } finally {
    button.disabled = false;
  }
}

async function sealArchive(exportId, msgBox, button) {
  if (!session) return;
  button.disabled = true;
  msgBox.textContent = "正在执行实时权限复核与归档封存...";
  try {
    const res = await apiJson(`/internal/lifecycle/space-archives/${encodeURIComponent(exportId)}/seal`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey("arch_seal"),
      },
      body: JSON.stringify({}),
    });
    if (res.status === 401) {
      lock("凭据已失效，请重新载入。", true);
      return;
    }
    if (!res.ok) {
      msgBox.textContent = res.data?.error?.message || `封存失败（HTTP ${res.status}）。`;
      return;
    }
    await loadArchives(`已完成归档封存（包编号 ${res.data.package_id}）。`);
  } catch {
    msgBox.textContent = "执行封存时网络异常。";
  } finally {
    button.disabled = false;
  }
}

async function verifyArchive(exportId, verifyBox, button) {
  if (!session) return;
  button.disabled = true;
  verifyBox.replaceChildren(text("p", "正在执行离线压缩包完整性、清单签名与水印核验..."));
  verifyBox.hidden = false;
  try {
    const res = await apiJson(`/internal/lifecycle/space-archives/${encodeURIComponent(exportId)}/verify`, {
      method: "POST",
    });
    if (res.status === 401) {
      lock("凭据已失效，请重新载入。", true);
      return;
    }
    if (!res.ok) {
      verifyBox.replaceChildren(text("p", res.data?.error?.message || `离线核验未通过（HTTP ${res.status}）。`));
      return;
    }
    const v = res.data;
    verifyBox.replaceChildren(
      text("strong", "离线完整性核验通过（verified = true）"),
      text(
        "p",
        `格式：${v.format_version} · 来源 ${v.source_ids.length} 个 · 版本 ${v.version_ids.length} 个 · Wiki ${v.wiki_revision_ids.length} 篇 · 核验于 ${formatUtc(v.verified_at)}`,
      ),
      text("p", `归档包 SHA-256：${v.archive_sha256}`, "repair-meta"),
      text("pre", JSON.stringify({
        recovery_watermark: v.recovery_watermark,
        authorization_rules_keys: v.authorization_rules_keys,
        safety_decisions_keys: v.safety_decisions_keys,
      }, null, 2)),
    );
  } catch {
    verifyBox.replaceChildren(text("p", "执行离线核验时网络异常。"));
  } finally {
    button.disabled = false;
  }
}

function renderArchives(data) {
  ui.list.replaceChildren();
  const roles = data.caller_roles || {};
  const list = data.archives || [];
  if (!list.length) {
    ui.list.append(text("li", "当前空间暂无空间归档申请记录。", "wiki-topic"));
    return;
  }
  for (const item of list) {
    const li = text("li", "", "wiki-topic");
    li.dataset.exportId = item.export_id;
    const header = text("div", "", "wiki-topic-header");
    header.append(
      text("h3", `归档申请 ${item.export_id}`),
      text("span", `申请于 ${formatUtc(item.requested_at)}`, "wiki-generation"),
    );
    const pill = text("span", stateLabels[item.state] || item.state, "wiki-state");
    if (item.state !== "sealed") pill.dataset.state = "needs_rebuild";

    const counts = text("dl", "", "wiki-counts");
    counts.append(
      (() => { const d = document.createElement("div"); d.append(text("dt", "来源数"), text("dd", item.source_ids.length)); return d; })(),
      (() => { const d = document.createElement("div"); d.append(text("dt", "版本数"), text("dd", item.version_ids.length)); return d; })(),
      (() => { const d = document.createElement("div"); d.append(text("dt", "Wiki 篇数"), text("dd", item.wiki_publication_ids.length)); return d; })(),
      (() => { const d = document.createElement("div"); d.append(text("dt", "包大小"), text("dd", item.archive_bytes_length ? `${item.archive_bytes_length} B` : "未封存")); return d; })(),
    );

    const detail = text(
      "p",
      `审批编号：${item.approval_id || "未审批"} · 审批过期：${formatUtc(item.approval_expires_at)} · 封存包：${item.package_id || "未封存"} · 封存于：${formatUtc(item.sealed_at)}`,
      "wiki-generation repair-meta",
    );
    li.append(header, pill, counts, detail);
    if (item.archive_sha256) {
      li.append(text("p", `封存 SHA-256：${item.archive_sha256}`, "wiki-generation repair-meta"));
    }

    const actions = text("div", "", "workbench-inline");
    const msgBox = text("p", "", "wiki-generation repair-meta");
    msgBox.setAttribute("role", "status");
    const verifyBox = text("div", "", "verify-summary");
    verifyBox.hidden = true;

    if (item.state === "requested" && roles.is_source_approver && !item.requested_by_caller) {
      const minutesInput = document.createElement("input");
      minutesInput.type = "number";
      minutesInput.min = "1";
      minutesInput.max = "15";
      minutesInput.value = "10";
      minutesInput.setAttribute("aria-label", "批准有效分钟数");
      const approveBtn = text("button", "独立批准导出", "primary-button");
      approveBtn.type = "button";
      approveBtn.dataset.approveExport = item.export_id;
      approveBtn.addEventListener("click", () => approveArchive(item.export_id, minutesInput, msgBox, approveBtn));
      actions.append(text("span", "有效分钟数（1-15）：", "wiki-generation"), minutesInput, approveBtn);
    }
    if (item.state === "approved" && roles.is_space_owner) {
      const sealBtn = text("button", "执行归档封存", "primary-button");
      sealBtn.type = "button";
      sealBtn.dataset.sealExport = item.export_id;
      sealBtn.addEventListener("click", () => sealArchive(item.export_id, msgBox, sealBtn));
      actions.append(sealBtn);
    }
    if (item.state === "sealed") {
      const verifyBtn = text("button", "离线完整性核验", "primary-button");
      verifyBtn.type = "button";
      verifyBtn.dataset.verifyExport = item.export_id;
      verifyBtn.addEventListener("click", () => verifyArchive(item.export_id, verifyBox, verifyBtn));
      actions.append(verifyBtn);
    }
    if (actions.childNodes.length) li.append(actions);
    li.append(msgBox, verifyBox);
    ui.list.append(li);
  }
}

async function loadArchives(statusOverride = "") {
  if (!session) return false;
  ui.list.setAttribute("aria-busy", "true");
  try {
    const res = await apiJson("/internal/lifecycle/space-archives");
    if (res.status === 401) {
      lock("凭据无效或已过期，请重新输入。", true);
      return false;
    }
    if (res.status === 403) {
      lock("该凭据缺少空间归档台账权限（list_space_archives）或非空间负责人/来源审批人。", true);
      return false;
    }
    if (!res.ok) {
      const errText = res.data?.error?.message || `加载归档台账失败（HTTP ${res.status}）。`; if (ui.workspace.hidden) { lock(errText, true); } else { ui.status.textContent = errText; }
      return false;
    }
    latestData = res.data;
    ui.lock.hidden = true;
    ui.workspace.hidden = false;
    renderScopePickers(res.data);
    renderArchives(res.data);
    ui.status.textContent = statusOverride || `共载入 ${(res.data.archives || []).length} 条空间归档记录（观测于 ${formatUtc(res.data.observed_at)}）。`;
    return true;
  } catch {
    if (ui.workspace.hidden) {
      lock("连接服务失败，请稍后重试。", true);
    } else {
      ui.status.textContent = "刷新台账时网络异常。";
    }
    return false;
  } finally {
    ui.list.setAttribute("aria-busy", "false");
  }
}

ui.access.addEventListener("submit", async event => {
  event.preventDefault();
  const token = ui.token.value.trim();
  if (!token) return;
  ui["lock-message"].textContent = "正在验证凭据...";
  session = { token };
  const ok = await loadArchives();
  if (ok) ui["request-title"].focus();
});

ui["request-form"].addEventListener("submit", async event => {
  event.preventDefault();
  if (!session) return;
  const sourceIds = Array.from(ui["source-checks"].querySelectorAll('input[name="source_id"]:checked')).map(el => el.value);
  const versionIds = Array.from(ui["version-checks"].querySelectorAll('input[name="version_id"]:checked')).map(el => el.value);
  const wikiIds = Array.from(ui["wiki-checks"].querySelectorAll('input[name="wiki_revision_id"]:checked')).map(el => el.value);
  if (!sourceIds.length || !versionIds.length) {
    ui["request-status"].textContent = "请至少选择 1 个来源和 1 个文档版本。";
    return;
  }
  ui["request-btn"].disabled = true;
  ui["request-status"].textContent = "正在发起空间归档申请...";
  try {
    const payload = { source_ids: sourceIds, version_ids: versionIds };
    if (wikiIds.length) payload.wiki_revision_ids = wikiIds;
    const res = await apiJson("/internal/lifecycle/space-archives", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey("arch_req"),
      },
      body: JSON.stringify(payload),
    });
    if (res.status === 401) {
      lock("凭据已失效，请重新载入。", true);
      return;
    }
    if (!res.ok) {
      ui["request-status"].textContent = res.data?.error?.message || `发起申请失败（HTTP ${res.status}）。`;
      return;
    }
    ui["request-status"].textContent = `已发起归档申请：${res.data.export_id}，等待来源独立审批人批准。`;
    await loadArchives();
  } catch {
    ui["request-status"].textContent = "发起归档申请时网络异常。";
  } finally {
    ui["request-btn"].disabled = false;
  }
});

ui.refresh.addEventListener("click", () => loadArchives());
ui.logout.addEventListener("click", () => lock("已退出空间归档管理。", true));

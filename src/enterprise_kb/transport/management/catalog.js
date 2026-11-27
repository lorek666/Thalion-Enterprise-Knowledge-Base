const ui = Object.fromEntries([
  "lock", "access", "token", "lock-message", "workspace", "space-title", "refresh", "logout",
  "status", "space-summary", "reconcile", "sources-list", "docs-list",
].map(name => [name, document.getElementById(`catalog-${name}`)]));

const lifecycleLabels = { active: "正常开放", suspended: "已停用", archived: "已归档" };
const admissionLabels = {
  synthetic_only: "测试演示环境",
  production_approved: "正式生产环境",
};
const lexicalLabels = {
  indexed: "快速关键词检索",
  direct_scan: "原文全量直扫",
  hybrid_vector: "语义理解 + 关键词混合搜索",
};
const connectorLabels = {
  confluence_cloud: "Confluence Cloud",
  feishu_wiki: "飞书知识库",
  sharepoint_graph: "SharePoint",
  http: "企业 OA / 自建系统",
};
const utcTime = new Intl.DateTimeFormat("zh-CN", {
  timeZone: "UTC", year: "numeric", month: "2-digit", day: "2-digit",
  hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
});

let session = null;

function text(tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = String(value);
  if (className) node.className = className;
  return node;
}

function dualLabelNode(tag, srText, visibleText, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.append(
    text("span", srText, "sr-only"),
    (() => {
      const span = text("span", visibleText);
      span.setAttribute("aria-hidden", "true");
      return span;
    })(),
  );
  return node;
}

function docMineralBadge(doc) {
  const media = String(doc.latest_media_type || "").toLowerCase();
  const key = `${doc.display_name || ""} ${doc.source_object_key || ""}`.toLowerCase();
  if (media.includes("pdf") || key.endsWith(".pdf")) {
    return { label: "PDF", cls: "mineral-icon mi-slate" };
  }
  if (media.includes("csv") || media.includes("spreadsheet") || media.includes("excel") || /\.(csv|xlsx?|tsv)\b/.test(key)) {
    return { label: "表格", cls: "mineral-icon mi-ink" };
  }
  if (media.includes("word") || media.includes("document") || /\.docx?\b/.test(key)) {
    return { label: "Word", cls: "mineral-icon mi-gold" };
  }
  if (media.includes("image/")) {
    return { label: "图片", cls: "mineral-icon mi-slate" };
  }
  return { label: "制度", cls: "mineral-icon mi-gold" };
}

function formatUtc(isoString) {
  if (!isoString) return "暂无记录";
  return `${utcTime.format(new Date(isoString))} UTC`;
}

function metric(label, value, warning = false) {
  const item = document.createElement("div");
  const dt = text("dt", label, warning ? "wiki-state" : "");
  if (warning) dt.dataset.state = "needs_rebuild";
  item.append(dt, text("dd", value));
  return item;
}

function idempotencyKey(prefix) {
  const rand = typeof crypto !== "undefined" && crypto.randomUUID
    ? crypto.randomUUID().replace(/-/g, "")
    : `${Date.now()}_${Math.random().toString(16).slice(2, 12)}`;
  return `${prefix}_${rand}`;
}

function lock(message = "", focus = false) {
  session = null;
  ui.token.value = "";
  ui.workspace.hidden = true;
  ui.lock.hidden = false;
  ui["lock-message"].textContent = message;
  ui["space-summary"].replaceChildren();
  ui["sources-list"].replaceChildren();
  ui["docs-list"].replaceChildren();
  ui.status.textContent = "";
  if (focus) ui.token.focus();
}

async function apiJson(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (session?.token) headers.Authorization = `Bearer ${session.token}`;
  const response = await fetch(url, { ...options, headers, cache: "no-store", credentials: "same-origin" });
  const data = await response.json().catch(() => null);
  return { ok: response.ok, status: response.status, data };
}

function renderSpace(payload) {
  ui["space-summary"].replaceChildren();
  const sp = payload.space;
  const rel = sp.release || {};
  const grid = text("div", "", "catalog-overview-grid");

  const mainCard = text("div", "", "catalog-space-main");
  const brand = text("div", "", "catalog-space-brand");
  const seal = text("span", "制度", "space-seal-badge");
  seal.setAttribute("aria-hidden", "true");
  const brandText = text("div", "", "catalog-space-brand-text");
  const header = text("div", "", "wiki-topic-header");
  header.append(
    text("h3", `${sp.name}`),
    text("span", `密级：${sp.classification} · 编号 ${sp.space_id.slice(0, 8)}`, "wiki-generation"),
  );
  const sub = text(
    "p",
    `共 ${payload.documents.length} 份制度文件已入库 · 连接 ${payload.sources.length} 个文件来源 · 新文件与 AI 总结均需换一位同事核对后才给员工看`,
    "catalog-space-sub",
  );
  brandText.append(header, sub);
  brand.append(seal, brandText);

  const counts = text("dl", "", "wiki-counts");
  counts.append(
    metric("当前状态", lifecycleLabels[sp.lifecycle] || sp.lifecycle),
    metric("已收录文件", `${payload.documents.length} 份`),
    metric("AI 省流总结", rel.wiki_delivery_enabled ? "已开启给员工看" : "已关闭（仅查原文）"),
    metric("外部资料同步", payload.connector_configured ? "已接通" : "未接通", !payload.connector_configured),
  );
  mainCard.append(brand, counts);

  const ringCard = text("div", "", "gold-ring-card");
  const ring = text("div", "100%", "gold-ring-badge");
  ring.setAttribute("aria-hidden", "true");
  const ringBody = text("div", "", "gold-ring-body");
  ringBody.append(
    text("div", "内容准确率 · 双人把关", "gold-ring-kicker"),
    text("div", `${payload.documents.length} 份制度 · 逐句对照原件`, "gold-ring-stat"),
    text(
      "div",
      `当前搜索方式：${lexicalLabels[rel.lexical_index_mode] || rel.lexical_index_mode || "快速关键词检索"}${rel.vector_model_id ? ` · 语义模型 ${rel.vector_model_id}（第 ${rel.generation} 代）` : ""}`,
      "gold-ring-note",
    ),
  );
  ringCard.append(ring, ringBody);

  grid.append(mainCard, ringCard);
  ui["space-summary"].append(grid);
}

async function triggerConnectorSync(sourceId, button, reportBox) {
  if (!session) return;
  button.disabled = true;
  reportBox.textContent = "正在拉取最新文件变动并写入系统...";
  const reconcile = Boolean(ui.reconcile.checked);
  try {
    const res = await apiJson(`/internal/sources/${encodeURIComponent(sourceId)}/connector-sync`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey("conn_sync"),
      },
      body: JSON.stringify({ reconcile, max_pages: 20 }),
    });
    if (res.status === 401) {
      lock("凭据已失效，请重新载入。", true);
      return;
    }
    if (!res.ok) {
      reportBox.textContent = res.data?.error?.message || `同步失败（HTTP ${res.status}）。`;
      return;
    }
    const r = res.data;
    const status = r.status === "pending_pages" ? "还有文件没拉完，下次会接着同步" : "已检查最新文件";
    await loadCatalog(`${status}。本次处理 ${r.pages_committed} 批、${r.versions_registered.length} 个文件版本。`);
  } catch {
    reportBox.textContent = "触发连接器同步时网络异常。";
  } finally {
    button.disabled = false;
  }
}

function renderSources(payload) {
  ui["sources-list"].replaceChildren();
  if (!payload.sources.length) {
    ui["sources-list"].append(text("li", "当前文件库还没有连接任何 OA 或外部来源。", "wiki-topic"));
    return;
  }
  for (const src of payload.sources) {
    const li = text("li", "", "wiki-topic");
    const header = text("div", "", "wiki-topic-header");
    header.append(
      text("h3", `${src.source_key}`),
      text("span", `来源编号 ${src.source_id}`, "wiki-generation"),
    );
    const badgeRow = text("div", "");
    const statusPill = text("span", lifecycleLabels[src.lifecycle] || src.lifecycle, "wiki-state");
    if (src.lifecycle !== "active") statusPill.dataset.state = "needs_rebuild";
    const connectorLabel = connectorLabels[src.connector_kind] || (src.connector_kind ? "外部系统" : "未接通");
    badgeRow.append(
      statusPill,
      text("span", `${admissionLabels[src.admission] || src.admission} · 接入版本 v${src.contract_revision}`, "wiki-generation"),
    );
    const counts = text("dl", "", "wiki-counts");
    counts.append(
      metric("已同步文件", `${src.document_count} 份`),
      metric("从哪里同步", connectorLabel, !src.connector_kind),
      metric("历史版本", `${src.version_count} 个`),
      metric("最新同步进度", src.content_sync ? `第 #${src.content_sync.sequence} 批（${src.content_sync.item_count} 条）` : "还没同步过"),
      metric("最近漏文件核对", src.inventory_reconciliation ? `对上 ${src.inventory_reconciliation.matched_count} / ${src.inventory_reconciliation.entry_count} 份` : "还没全面核对"),
    );
    const meta = text(
      "p",
      `上次同步时间：${formatUtc(src.content_sync?.committed_at)} · 上次漏同步检查：${formatUtc(src.inventory_reconciliation?.committed_at)} · 权限同步代次：${src.permission_checkpoint ? `第 ${src.permission_checkpoint.authority_generation} 代` : "暂无"}`,
      "wiki-generation repair-meta",
    );
    const actions = text("div", "", "work-buttons");
    const syncBtn = dualLabelNode("button", "触发连接器同步",
      src.connector_kind === "confluence_cloud" ? "从 Confluence 同步"
        : src.connector_kind === "feishu_wiki" ? "从飞书同步"
        : src.connector_kind === "sharepoint_graph" ? "从 SharePoint 同步"
        : "立即从 OA 同步最新文件", "primary-button");
    syncBtn.type = "button";
    syncBtn.disabled = !src.connector_kind || src.lifecycle !== "active";
    syncBtn.dataset.sourceSync = src.source_id;
    const statusLink = dualLabelNode("a", "查看详细水位", "看详细同步记录", "quiet-button");
    statusLink.href = "/manage/sources";
    const reportBox = text("p", "", "wiki-generation repair-meta");
    reportBox.setAttribute("role", "status");
    syncBtn.addEventListener("click", () => triggerConnectorSync(src.source_id, syncBtn, reportBox));
    actions.append(syncBtn, statusLink);
    li.append(header, badgeRow, counts, meta, actions, reportBox);
    ui["sources-list"].append(li);
  }
}

async function saveDocumentDepartment(documentId, code, name, messageBox) {
  if (!session) return;
  messageBox.textContent = code ? "正在保存文件归属部门..." : "正在清空文件部门归属...";
  try {
    const res = await apiJson(`/internal/sources/documents/${encodeURIComponent(documentId)}/department`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey("doc_dept"),
      },
      body: JSON.stringify({ department_code: code, department_name: name }),
    });
    if (res.status === 401) {
      lock("凭据已失效，请重新载入。", true);
      return;
    }
    if (!res.ok) {
      messageBox.textContent = res.data?.error?.message || `更新部门失败（HTTP ${res.status}）。`;
      return;
    }
    await loadCatalog(code ? `已更新文档部门归属为 ${name}（${code}）。` : "已清除文档显式部门归属。");
  } catch {
    messageBox.textContent = "更新部门归属时网络异常。";
  }
}

function renderDocuments(payload) {
  ui["docs-list"].replaceChildren();
  if (!payload.documents.length) {
    ui["docs-list"].append(text("li", "当前文件库还没有已入库的制度文件。", "wiki-topic"));
    return;
  }
  for (const doc of payload.documents) {
    const li = text("li", "", "wiki-topic");
    const row = text("div", "", "catalog-doc-row");
    const badgeInfo = docMineralBadge(doc);
    const badge = text("span", badgeInfo.label, badgeInfo.cls);
    badge.setAttribute("aria-hidden", "true");

    const body = text("div", "", "catalog-doc-body");
    const header = text("div", "", "wiki-topic-header");
    header.append(
      text("h3", doc.display_name),
      text("span", `文件编号 ${doc.document_id.slice(0, 8)}…`, "wiki-generation"),
    );

    const statusLine = text("div", "");
    const stateTag = text("span", doc.latest_version_label ? `● 已入库 · ${doc.latest_version_label}` : "待同步版本", "wiki-state");
    if (!doc.latest_version_label) stateTag.dataset.state = "needs_rebuild";
    const deptText = doc.department_name ? `${doc.department_name} (${doc.department_code})` : "未分部门（按默认权限）";
    statusLine.append(
      stateTag,
      text("span", `归属部门：${deptText}`, "wiki-generation"),
    );

    const meta = text(
      "p",
      `原始路径：${doc.source_object_key} · 文件格式：${doc.latest_media_type || "-"}`,
      "wiki-generation repair-meta",
    );

    const form = document.createElement("form");
    form.className = "workbench-inline";
    form.dataset.docDeptForm = doc.document_id;
    const codeInput = document.createElement("input");
    codeInput.type = "text";
    codeInput.placeholder = "部门英文代号，如 finance";
    codeInput.maxLength = 64;
    codeInput.value = doc.department_code || "";
    codeInput.setAttribute("aria-label", `${doc.display_name} 部门代码`);
    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.placeholder = "部门中文名，如 财务部";
    nameInput.maxLength = 120;
    nameInput.value = doc.department_name || "";
    nameInput.setAttribute("aria-label", `${doc.display_name} 部门名称`);
    const saveBtn = dualLabelNode("button", "保存部门归属", "保存归属部门", "primary-button");
    saveBtn.type = "submit";
    const clearBtn = dualLabelNode("button", "清除归属", "清空部门", "quiet-button");
    clearBtn.type = "button";
    const msg = text("p", "", "wiki-generation repair-meta");
    msg.setAttribute("role", "status");

    form.addEventListener("submit", event => {
      event.preventDefault();
      const code = codeInput.value.trim();
      const name = nameInput.value.trim();
      if (!code || !name) {
        msg.textContent = "请把部门英文代号和中文名都填上，或者直接点“清空部门”。";
        return;
      }
      saveDocumentDepartment(doc.document_id, code, name, msg);
    });
    clearBtn.addEventListener("click", () => saveDocumentDepartment(doc.document_id, null, null, msg));
    form.append(codeInput, nameInput, saveBtn, clearBtn);
    body.append(header, statusLine, meta, form, msg);
    row.append(badge, body);
    li.append(row);
    ui["docs-list"].append(li);
  }
}

async function loadCatalog(statusOverride = "") {
  if (!session) return false;
  ui["sources-list"].setAttribute("aria-busy", "true");
  ui["docs-list"].setAttribute("aria-busy", "true");
  try {
    const res = await apiJson("/internal/sources/catalog");
    if (res.status === 401) {
      lock("凭据无效或已过期，请重新输入。", true);
      return false;
    }
    if (res.status === 403) {
      lock("该凭据缺少空间目录读取权限（read_source_catalog）或非当前空间负责人。", true);
      return false;
    }
    if (!res.ok) {
      ui.status.textContent = res.data?.error?.message || `读取目录失败（HTTP ${res.status}）。`;
      return false;
    }
    ui.lock.hidden = true;
    ui.workspace.hidden = false;
    renderSpace(res.data);
    renderSources(res.data);
    renderDocuments(res.data);
    ui.status.textContent = statusOverride || `已刷新制度文件库（共 ${res.data.sources.length} 个来源、${res.data.documents.length} 份文件，更新于 ${formatUtc(res.data.observed_at)}）。`;
    return true;
  } catch {
    if (ui.workspace.hidden) {
      lock("连接服务失败，请稍后重试。", true);
    } else {
      ui.status.textContent = "刷新目录时网络异常。";
    }
    return false;
  } finally {
    ui["sources-list"].setAttribute("aria-busy", "false");
    ui["docs-list"].setAttribute("aria-busy", "false");
  }
}

ui.access.addEventListener("submit", async event => {
  event.preventDefault();
  const token = ui.token.value.trim();
  if (!token) return;
  ui["lock-message"].textContent = "正在验证管理口令...";
  session = { token };
  const ok = await loadCatalog();
  if (ok) ui["space-title"].focus();
});

ui.refresh.addEventListener("click", () => loadCatalog());
ui.logout.addEventListener("click", () => lock("已退出制度文件库管理。", true));

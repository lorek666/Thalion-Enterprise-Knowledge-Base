const ui = Object.fromEntries([
  "lock", "access", "token", "lock-message", "workspace", "editor-title", "refresh", "logout",
  "editor", "editing-id", "term", "synonyms", "definition", "save-btn", "cancel-edit", "form-status",
  "filter", "query", "include-inactive", "status", "list",
].map(name => [name, document.getElementById(`glossary-${name}`)]));

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

function parseSynonyms(raw) {
  return raw
    .split(/[,，\n;；]+/)
    .map(item => item.trim())
    .filter(Boolean);
}

function resetEditor() {
  ui["editing-id"].value = "";
  ui.term.value = "";
  ui.synonyms.value = "";
  ui.definition.value = "";
  ui["save-btn"].textContent = "保存新词条";
  ui["cancel-edit"].hidden = true;
}

function lock(message = "", focus = false) {
  session = null;
  ui.token.value = "";
  resetEditor();
  ui["form-status"].textContent = "";
  ui.status.textContent = "";
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

function startEdit(entry) {
  ui["editing-id"].value = entry.entry_id;
  ui.term.value = entry.term;
  ui.synonyms.value = (entry.synonyms || []).join(", ");
  ui.definition.value = entry.definition;
  ui["save-btn"].textContent = "更新词条";
  ui["cancel-edit"].hidden = false;
  ui["form-status"].textContent = `正在编辑词条「${entry.term}」（当前修订 v${entry.revision}）。`;
  ui.term.focus();
}

async function toggleStatus(entry) {
  if (!session) return;
  const nextStatus = entry.status === "active" ? "inactive" : "active";
  ui.status.textContent = `正在将「${entry.term}」切换为${nextStatus === "active" ? "启用中" : "已停用"}...`;
  try {
    const res = await apiJson(`/internal/glossary/${encodeURIComponent(entry.entry_id)}/status`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey("gloss_status"),
      },
      body: JSON.stringify({ status: nextStatus }),
    });
    if (res.status === 401) {
      lock("凭据已失效，请重新载入。", true);
      return;
    }
    if (!res.ok) {
      ui.status.textContent = res.data?.error?.message || `状态切换失败（HTTP ${res.status}）。`;
      return;
    }
    await loadEntries(`已将词条「${entry.term}」设为${nextStatus === "active" ? "启用中" : "已停用"}。`);
  } catch {
    ui.status.textContent = "切换词条状态时网络异常。";
  }
}

function renderEntries(entries) {
  ui.list.replaceChildren();
  if (!entries.length) {
    ui.list.append(text("li", "当前条件下暂无业务词条。", "wiki-topic"));
    return;
  }
  for (const entry of entries) {
    const li = text("li", "", "wiki-topic");
    li.dataset.glossaryEntry = entry.entry_id;
    const header = text("div", "", "wiki-topic-header");
    header.append(
      text("h3", entry.term),
      text("span", `v${entry.revision} · 更新于 ${formatUtc(entry.updated_at)}`, "wiki-generation"),
    );
    const pill = text("span", entry.status === "active" ? "启用中" : "已停用", "wiki-state");
    if (entry.status !== "active") pill.dataset.state = "needs_rebuild";
    const synLine = text(
      "p",
      `同义词：${entry.synonyms && entry.synonyms.length ? entry.synonyms.join("、") : "（无）"}`,
      "wiki-generation repair-meta",
    );
    const defLine = text("p", entry.definition, "repair-meta");
    const buttons = text("div", "", "work-buttons");
    const editBtn = text("button", "编辑", "quiet-button");
    editBtn.type = "button";
    editBtn.addEventListener("click", () => startEdit(entry));
    const toggleBtn = text("button", entry.status === "active" ? "停用" : "重新启用", "quiet-button");
    toggleBtn.type = "button";
    toggleBtn.addEventListener("click", () => toggleStatus(entry));
    buttons.append(editBtn, toggleBtn);
    li.append(header, pill, synLine, defLine, buttons);
    ui.list.append(li);
  }
}

async function loadEntries(statusOverride = "") {
  if (!session) return false;
  ui.list.setAttribute("aria-busy", "true");
  const params = new URLSearchParams();
  params.set("include_inactive", ui["include-inactive"].checked ? "true" : "false");
  const q = ui.query.value.trim();
  if (q) params.set("q", q);
  try {
    const res = await apiJson(`/internal/glossary?${params.toString()}`);
    if (res.status === 401) {
      lock("凭据无效或已过期，请重新输入。", true);
      return false;
    }
    if (res.status === 403) {
      lock("该凭据缺少业务词典读取权限（read_glossary）。", true);
      return false;
    }
    if (!res.ok) {
      ui.status.textContent = res.data?.error?.message || `加载词典失败（HTTP ${res.status}）。`;
      return false;
    }
    ui.lock.hidden = true;
    ui.workspace.hidden = false;
    const entries = res.data.entries || [];
    renderEntries(entries);
    ui.status.textContent = statusOverride || `共载入 ${entries.length} 条业务词条。`;
    return true;
  } catch {
    if (ui.workspace.hidden) {
      lock("连接服务失败，请稍后重试。", true);
    } else {
      ui.status.textContent = "刷新词典时网络异常。";
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
  ui["lock-message"].textContent = "正在验证管理凭据...";
  session = { token };
  const ok = await loadEntries();
  if (ok) ui["editor-title"].focus();
});

ui.editor.addEventListener("submit", async event => {
  event.preventDefault();
  if (!session) return;
  const term = ui.term.value.trim();
  const synonyms = parseSynonyms(ui.synonyms.value);
  const definition = ui.definition.value.trim();
  if (!term || !definition) {
    ui["form-status"].textContent = "请填写标准术语和业务释义。";
    return;
  }
  const editingId = ui["editing-id"].value.trim();
  const url = editingId ? `/internal/glossary/${encodeURIComponent(editingId)}` : "/internal/glossary";
  ui["save-btn"].disabled = true;
  ui["form-status"].textContent = editingId ? "正在保存词条修改..." : "正在创建业务词条...";
  try {
    const res = await apiJson(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey(editingId ? "gloss_upd" : "gloss_add"),
      },
      body: JSON.stringify({ term, synonyms, definition }),
    });
    if (res.status === 401) {
      lock("凭据已失效，请重新载入。", true);
      return;
    }
    if (!res.ok) {
      ui["form-status"].textContent = res.data?.error?.message || `保存失败（HTTP ${res.status}）。`;
      return;
    }
    resetEditor();
    ui["form-status"].textContent = editingId ? `已更新词条「${res.data.entry.term}」。` : `已创建词条「${res.data.entry.term}」。`;
    await loadEntries();
  } catch {
    ui["form-status"].textContent = "保存词条时网络异常。";
  } finally {
    ui["save-btn"].disabled = false;
  }
});

ui["cancel-edit"].addEventListener("click", () => {
  resetEditor();
  ui["form-status"].textContent = "已取消编辑。";
});
ui.filter.addEventListener("submit", event => {
  event.preventDefault();
  loadEntries();
});
ui.refresh.addEventListener("click", () => loadEntries());
ui.logout.addEventListener("click", () => lock("已退出业务词典管理。", true));

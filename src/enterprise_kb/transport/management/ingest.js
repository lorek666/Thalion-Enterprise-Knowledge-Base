const ui = Object.fromEntries([
  "lock", "access", "token", "lock-message", "workspace", "logout", "form", "source", "files",
  "rows", "submit", "status", "results", "results-meta", "result-list",
  "history-load", "history-message", "history-list", "history-pages", "history-next",
  "processing-form", "processing-version", "processing-message",
].map(name => [name, document.getElementById(`ingest-${name}`)]));
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const identifier = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const statusLabels = {
  registered: "已登记，待解析",
  duplicate: "已存在，指向原版本",
  needs_confirmation: "需确认新版本",
  rejected: "未登记",
};
const processingLabels = {
  not_scheduled: "未排入解析",
  queued: "等待解析",
  processing: "正在解析",
  pending_review: "待质量审核",
  quality_approved: "质量已批准",
  quarantined: "已隔离",
  blocked: "处理或使用已阻断",
};
const reasonLabels = {
  unsupported_media: "格式不受支持或扩展名与内容不符",
  empty: "文件为空",
  too_large: "文件超过大小限制",
  invalid_metadata: "标题、版本或资料标识无效",
  version_label_changed_content: "同一版本号已有不同内容，请更换版本号并确认新版本",
  version_key_changed_content: "同一版本键已有不同内容，请更换版本号并确认新版本",
  new_version_confirmation_required: "内容有变，请勾选确认新版本",
  not_admitted: "当前来源未接收此文件",
  dependency_unavailable: "入库服务暂不可用，请稍后重试",
};
const batchTime = new Intl.DateTimeFormat("zh-CN", { dateStyle: "short", timeStyle: "medium", hour12: false });
let session = null;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function fnv1a(text) {
  let value = 0x811c9dc5;
  for (const character of text) {
    value ^= character.codePointAt(0);
    value = Math.imul(value, 0x01000193) >>> 0;
  }
  return value.toString(16).padStart(8, "0");
}

function defaultIdentifier(name) {
  const stem = name.replace(/\.[^.]+$/, "").toLowerCase()
    .replace(/[^a-z0-9_.:-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 100);
  return identifier.test(stem) ? stem : `doc-${fnv1a(name)}`;
}

function defaultTitle(name) {
  return name.replace(/\.[^.]+$/, "").slice(0, 300) || "未命名资料";
}

function clearResults() {
  if (session) session.batch = null;
  ui.results.hidden = true;
  ui["results-meta"].textContent = "";
  ui["result-list"].replaceChildren();
}

function clearProcessing() {
  session?.lookup?.abort();
  if (session) session.lookup = null;
  ui["processing-message"].textContent = "";
}

function clearHistory() {
  session?.history?.abort();
  if (session) {
    session.history = null;
    session.nextBatch = null;
  }
  ui["history-message"].textContent = "";
  ui["history-list"].replaceChildren();
  ui["history-list"].setAttribute("aria-busy", "false");
  ui["history-pages"].hidden = true;
}

function metadataInputs(container, prefix, entry) {
  const fields = [
    ["title", "标题", entry.title, 300],
    ["version", "版本", entry.version, 128],
    ["identifier", "资料标识", entry.identifier, 128],
  ];
  const inputs = {};
  for (const [name, label, value, max] of fields) {
    const id = `${prefix}-${name}`;
    const input = element("input");
    input.id = id;
    input.maxLength = max;
    input.required = true;
    input.value = value;
    input.spellcheck = false;
    const wrapper = element("div");
    const text = element("label", label);
    text.htmlFor = id;
    wrapper.append(text, input);
    container.append(wrapper);
    inputs[name] = input;
  }
  inputs.version.placeholder = "如 A、2026.1";
  const confirmLabel = element("label", "内容有变，确认按新版本登记");
  const confirm = element("input");
  confirm.type = "checkbox";
  confirm.id = `${prefix}-confirm`;
  confirm.checked = entry.confirm_new_version;
  confirmLabel.prepend(confirm);
  container.append(confirmLabel);
  return { inputs, confirm };
}

function rowFor(file, index) {
  const fieldset = element("fieldset", undefined, "repair-change");
  fieldset.append(element("h3", `${index + 1}. ${file.name}`));
  const fields = metadataInputs(fieldset, `ingest-row-${index}`, {
    title: defaultTitle(file.name), version: "", identifier: defaultIdentifier(file.name), confirm_new_version: false,
  });
  return { file, fieldset, ...fields };
}

function readEntry(file, { inputs, confirm }) {
  return {
    file, title: inputs.title.value.trim(), version: inputs.version.value.trim(),
    identifier: inputs.identifier.value.trim(), confirm_new_version: confirm.checked,
  };
}

function updateUploadControls() {
  const pending = Boolean(session?.upload);
  ui.files.disabled = pending;
  ui.source.disabled = pending;
  const count = session?.rows.length ?? 0;
  ui.submit.disabled = pending || count === 0 || count > 20;
  for (const controls of ui["result-list"].querySelectorAll("fieldset")) controls.disabled = pending;
}

function rebuildRows() {
  if (!session) return;
  session.rows = Array.from(ui.files.files).map((file, index) => rowFor(file, index));
  ui.rows.replaceChildren(...session.rows.map(row => row.fieldset));
  const tooMany = session.rows.length > 20;
  updateUploadControls();
  ui.status.textContent = tooMany
    ? "单批最多 20 个文件，请减少选择。"
    : session.rows.length ? `已选择 ${session.rows.length} 个文件。` : "请选择要登记的文件。";
  clearResults();
}

async function base64(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function processingButton(version, label) {
  const button = element("button", `查看处理状态：${label}`, "quiet-button");
  button.type = "button";
  button.addEventListener("click", () => {
    ui["processing-version"].value = version;
    ui["processing-version"].focus();
    ui["processing-form"].requestSubmit();
  });
  return button;
}

function historyRow(batch) {
  const row = element("li", undefined, "repair-change");
  const details = element("details");
  const state = batch.completed_at === null ? "回执未齐" : "回执已齐";
  const time = batchTime.format(new Date(batch.created_at));
  details.append(element("summary", `${time} · ${state} · ${batch.files.length}/${batch.item_count} 件`));
  details.append(element("p", `批次 ${batch.batch_id}`, "repair-meta"));
  const files = element("ul", undefined, "result-list");
  for (const file of batch.files) {
    const item = element("li", undefined, "repair-change");
    const status = file.status === "registered" ? "已登记" : statusLabels[file.status];
    item.append(element("h3", `${file.position + 1}. ${file.title}`), element("p", status));
    if (file.reason) item.append(element("p", reasonLabels[file.reason] ?? "原因待核对"));
    if (file.version_id && ["registered", "duplicate"].includes(file.status)) {
      item.append(processingButton(file.version_id, file.title));
    }
    files.append(item);
  }
  details.append(files);
  row.append(details);
  return row;
}

async function loadHistory(after = null) {
  const activeSession = session;
  if (!activeSession) return;
  clearHistory();
  const source = ui.source.value.trim().toLowerCase();
  const message = ui["history-message"];
  const list = ui["history-list"];
  if (!uuid.test(source)) {
    message.textContent = "请输入有效的来源编号。";
    return;
  }
  const controller = new AbortController();
  activeSession.history = controller;
  const current = () => session === activeSession && activeSession.history === controller;
  list.setAttribute("aria-busy", "true");
  message.textContent = "正在查询入库台账…";
  try {
    const cursor = after === null ? "" : `?after=${encodeURIComponent(after)}`;
    const response = await fetch(`/internal/sources/${source}/ingest-batches${cursor}`, {
      headers: { Authorization: `Bearer ${activeSession.token}` }, signal: controller.signal,
      cache: "no-store", credentials: "omit", mode: "same-origin", redirect: "error", referrerPolicy: "no-referrer",
    });
    if (!current()) return;
    if (response.status === 401) {
      lock("凭据无效或已过期，请更换凭据。");
      ui.token.focus();
      return;
    }
    if (response.status === 403) {
      message.textContent = "当前凭据不可查看该来源的入库台账。";
      return;
    }
    if (!response.ok) throw new Error("Ingest history unavailable");
    const body = await response.json();
    if (!current()) return;
    if (body.source_id !== source || !Array.isArray(body.batches) ||
        (body.next_cursor !== null && !uuid.test(body.next_cursor))) {
      throw new Error("Invalid ingest history");
    }
    list.replaceChildren(...body.batches.map(historyRow));
    message.textContent = body.batches.length ? `本页 ${body.batches.length} 个批次。` : "未找到入库批次。";
    activeSession.nextBatch = body.next_cursor;
    ui["history-pages"].hidden = activeSession.nextBatch === null;
  } catch {
    if (current()) message.textContent = "暂时无法查询入库台账，请重试。";
  } finally {
    if (current()) {
      list.setAttribute("aria-busy", "false");
      activeSession.history = null;
    }
  }
}

function resultRow(batch, item, receipt = null) {
  const card = element("li", undefined, "repair-change");
  const number = item.position + 1;
  const heading = element("h3", `${number}. ${statusLabels[item.status] || item.status}`);
  heading.tabIndex = -1;
  card.append(heading);
  if (item.version_id) card.append(element("p", `版本 ${item.version_id}`));
  if (item.document_id) card.append(element("p", `资料 ${item.document_id}`));
  if (item.media_type) card.append(element("p", `格式 ${item.media_type}`));
  if (item.reason) card.append(element("p", reasonLabels[item.reason] || item.reason, "status-message"));
  if (receipt) {
    card.append(element("p", `重试回执 ${receipt.ingestion_request_id}`), element("p", `请求 ${receipt.request_id}`));
  }
  if (item.version_id && (item.status === "registered" || item.status === "duplicate")) {
    const actions = element("div", undefined, "work-buttons");
    actions.append(processingButton(item.version_id, `第 ${number} 项`));
    card.append(actions);
  } else if (item.status === "rejected" || item.status === "needs_confirmation") {
    const entry = batch.entries[item.position];
    const form = element("form");
    form.autocomplete = "off";
    form.setAttribute("aria-label", `第 ${number} 项单独重试`);
    const controls = element("fieldset", undefined, "wiki-access-form");
    const currentFile = element("p", `重试文件：${entry.file.name}`);
    const label = element("label", `第 ${number} 项替换文件`);
    const replacement = element("input");
    replacement.id = `ingest-replacement-${item.position}`;
    replacement.type = "file";
    replacement.accept = ui.files.accept;
    label.htmlFor = replacement.id;
    replacement.addEventListener("change", () => {
      currentFile.textContent = `重试文件：${(replacement.files[0] ?? entry.file).name}`;
    });
    controls.append(currentFile, label, replacement);
    const fields = metadataInputs(controls, `ingest-retry-${item.position}`, entry);
    const retry = element("button", `重试第 ${number} 项`, "quiet-button");
    retry.type = "submit";
    form.addEventListener("submit", event => {
      event.preventDefault();
      if (session?.batch !== batch) return;
      const chosenEntry = readEntry(replacement.files[0] ?? entry.file, fields);
      void submitFiles(batch.source, [chosenEntry], `正在登记第 ${number} 项…`, response => {
        if (session?.batch !== batch) return;
        batch.entries[item.position] = chosenEntry;
        const updated = { ...response.files[0], position: item.position };
        const next = resultRow(batch, updated, response);
        card.replaceWith(next);
        next.querySelector("h3").focus();
        ui.status.textContent = `第 ${number} 项：${statusLabels[updated.status]}。`;
      });
    });
    controls.append(retry);
    form.append(controls);
    card.append(form);
  }
  return card;
}

function renderResults(source, entries, body) {
  const batch = { source, entries };
  const cards = body.files.map(item => resultRow(batch, item));
  session.batch = batch;
  ui.results.hidden = false;
  ui["results-meta"].textContent = `请求 ${body.request_id} · 入库任务 ${body.ingestion_request_id}`;
  ui["result-list"].replaceChildren(...cards);
  const pending = body.files.some(item => item.status === "needs_confirmation");
  ui.status.textContent = pending
    ? "有文件需要确认新版本。"
    : "本批已处理。";
}

ui.access.addEventListener("submit", event => {
  event.preventDefault();
  const token = ui.token.value.trim();
  if (!token) {
    ui["lock-message"].textContent = "请输入管理测试凭据。";
    return;
  }
  session = { token, rows: [] };
  ui.token.value = "";
  ui["lock-message"].textContent = "";
  ui.lock.hidden = true;
  ui.workspace.hidden = false;
  ui.source.focus();
});

function lock(message = "") {
  session?.upload?.abort();
  clearProcessing();
  clearHistory();
  session = null;
  ui.token.value = "";
  ui.workspace.hidden = true;
  ui.lock.hidden = false;
  ui.form.reset();
  ui["processing-form"].reset();
  ui.rows.replaceChildren();
  ui.status.textContent = "";
  clearResults();
  updateUploadControls();
  ui["lock-message"].textContent = message;
}

ui.logout.addEventListener("click", () => {
  lock();
  ui.token.focus();
});

window.addEventListener("pagehide", () => lock());
window.addEventListener("pageshow", event => {
  if (event.persisted) lock("页面已重新锁定，请载入凭据。");
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) lock("页面已锁定，请重新载入凭据。");
});
ui.files.addEventListener("change", rebuildRows);
ui.source.addEventListener("input", () => {
  clearResults();
  clearHistory();
  clearProcessing();
  ui["processing-form"].reset();
});
ui["history-load"].addEventListener("click", () => void loadHistory());
ui["history-next"].addEventListener("click", () => {
  if (session?.nextBatch) void loadHistory(session.nextBatch);
});
ui["processing-version"].addEventListener("input", clearProcessing);

ui["processing-form"].addEventListener("submit", async event => {
  event.preventDefault();
  const activeSession = session;
  if (!activeSession) return;
  clearProcessing();
  const message = ui["processing-message"];
  const version = ui["processing-version"].value.trim();
  if (!uuid.test(version)) {
    message.textContent = "请输入有效的资料版本编号。";
    return;
  }
  const lookup = new AbortController();
  activeSession.lookup = lookup;
  message.textContent = "正在查询处理状态…";
  try {
    const response = await fetch(`/internal/sources/versions/${version}/processing-status`, {
      headers: { "Authorization": `Bearer ${activeSession.token}` },
      signal: lookup.signal,
    });
    const body = response.ok ? await response.json() : null;
    if (session !== activeSession || activeSession.lookup !== lookup) return;
    if (body?.version_id === version.toLowerCase() && Object.hasOwn(processingLabels, body.state)) {
      message.textContent = processingLabels[body.state];
    } else {
      message.textContent = {
        401: "凭据无效或已过期，请更换凭据。",
        403: "该版本的处理状态不可查看。",
      }[response.status] || "暂时无法查询处理状态，请重试。";
    }
  } catch {
    if (session === activeSession && activeSession.lookup === lookup) {
      message.textContent = "暂时无法查询处理状态，请重试。";
    }
  } finally {
    if (session === activeSession && activeSession.lookup === lookup) activeSession.lookup = null;
  }
});

async function submitFiles(source, entries, message, onSuccess) {
  const activeSession = session;
  if (!activeSession || activeSession.upload) return;
  if (!uuid.test(source)) {
    ui.status.textContent = "请输入有效的来源编号。";
    return;
  }
  if (!entries.length) {
    ui.status.textContent = "请选择要登记的文件。";
    return;
  }
  const total = entries.reduce((sum, entry) => sum + entry.file.size, 0);
  if (entries.length > 20 || total > 32 * 1024 * 1024 || entries.some(entry => entry.file.size > 16 * 1024 * 1024)) {
    ui.status.textContent = "批次超过 20 个文件、合计 32 MiB 或单文件 16 MiB 的限制。";
    return;
  }
  for (const entry of entries) {
    if (!entry.title || !entry.version || !identifier.test(entry.identifier)) {
      ui.status.textContent = `请补全 ${entry.file.name} 的标题、版本和资料标识；资料标识只能使用字母、数字、点、冒号、下划线或连字符。`;
      return;
    }
  }
  const upload = new AbortController();
  activeSession.upload = upload;
  updateUploadControls();
  ui.status.textContent = message;
  try {
    const files = [];
    for (const { file, ...metadata } of entries) {
      files.push({ ...metadata, name: file.name, content: await base64(file) });
      if (session !== activeSession) return;
    }
    const response = await fetch(`/internal/sources/${source}/ingest-batches`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${activeSession.token}`,
        "Content-Type": "application/json",
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({ files }),
      signal: upload.signal,
    });
    const body = await response.json().catch(() => ({}));
    if (session !== activeSession) return;
    if (!response.ok) {
      ui.status.textContent = {
        400: "请求参数无效，请检查文件和元数据。",
        401: "凭据无效或已过期。",
        403: "需要来源负责人身份和上传能力，或来源已停用。",
        409: "该次上传与已有批次冲突，请重新发起。",
        413: "批次超过大小限制。",
        503: "入库服务暂不可用，请稍后重试。",
      }[response.status] || "上传失败，请稍后重试。";
      return;
    }
    if (!uuid.test(body.request_id) || !uuid.test(body.ingestion_request_id) ||
        !Array.isArray(body.files) || body.files.length !== entries.length ||
        body.files.some((item, index) => item?.position !== index || !Object.hasOwn(statusLabels, item.status))) {
      throw new Error("Invalid upload receipt");
    }
    onSuccess(body);
  } catch {
    if (session === activeSession) ui.status.textContent = "无法完成上传，请检查本机服务后重试。";
  } finally {
    if (session === activeSession) {
      activeSession.upload = null;
      updateUploadControls();
    }
  }
}

ui.form.addEventListener("submit", event => {
  event.preventDefault();
  if (!session) return;
  const source = ui.source.value.trim();
  const entries = session.rows.map(row => readEntry(row.file, row));
  void submitFiles(source, entries, "正在读取并登记本批文件…", body => renderResults(source, entries, body));
});

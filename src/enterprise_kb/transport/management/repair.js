const ui = Object.fromEntries([
  "lock", "access", "token", "lock-message", "workspace", "logout", "search", "run", "status",
  "difference", "meta", "changes", "decision", "basis",
  "mode-markdown", "run-field", "run-label", "approve-decision", "correction-field", "correction", "page-field", "page", "show",
  "pdf", "pdf-meta", "pdf-image", "full-size", "pdf-details", "propose", "transcript",
  "proposal-basis", "review-correction", "correction-basis",
  "approve-batch", "batch-meta", "batch-progress", "batch-basis", "approve",
  "rule-section", "rule-refresh", "rule-catalog-status", "rule-catalog",
  "rule-impact-form", "rule-revision", "rule-source", "rule-status", "rule-impact-list",
  "rule-rollback-form", "rule-reason", "rule-basis", "rule-rollback-status", "rule-rollback-items",
].map(name => [name, document.getElementById(`repair-${name}`)]));
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const pageNumber = /^(?:[1-9]|1[0-6])$/;
const evidencePath = "/internal/evidence";
const correctionWindow = 5 * 60_000;
const batchWindow = 30 * 60_000;
const previewLabels = {
  markdown: "查看差异", pdf: "查看原页", proposal: "查看提交原页",
  correction: "查看候选对照", batch: "核对批次原页", docx: "查看待审批次",
};
const ocrReasons = { empty: "未识别到文字", unsupported_structure: "无法识别页面结构", size_limit: "超出处理上限" };
const docxRowReasons = { missing_column: "缺少声明列", missing_value: "缺少必需值", invalid_amount: "金额格式不受支持" };
const docxRoles = { amount: "金额", unit: "单位", condition: "适用条件", exception: "例外" };
const rollbackReasons = {
  not_latest_run: "已有更新批次覆盖",
  source_deleted: "来源已删除隔离",
  version_stopped: "版本已撤回或停用",
  custody_hold: "版本处于保全中",
  scope_or_contract_changed: "来源停用或契约已变更",
  unsupported_media_type: "格式需人工校订",
  no_approved_baseline: "无已批准历史基线",
  requires_reviewer_quarantine: "需由来源质控审核人先隔离",
};
const qualityStates = {
  approved: "已批准",
  quarantined: "已隔离",
  pending_review: "待审核",
  parse_quarantined: "解析隔离",
};
let session = null;

function mode() {
  return ui.search.elements["repair-mode"].value;
}

function clearDifference() {
  if (session !== null) {
    clearTimeout(session.timer);
    session.preview = null;
  }
  ui.difference.hidden = true;
  ui.meta.textContent = "";
  ui.changes.replaceChildren();
  ui.basis.value = "";
}

function clearPdf() {
  if (session) {
    if (session.imageUrl) URL.revokeObjectURL(session.imageUrl);
    session.imageUrl = null;
    session.pdfReceipt = null;
    clearTimeout(session.pdfTimer);
  }
  ui.pdf.hidden = true;
  ui["pdf-meta"].textContent = "";
  ui["pdf-image"].replaceChildren();
  ui["pdf-image"].scrollTo(0, 0);
  ui["pdf-details"].hidden = true;
  ui["pdf-details"].replaceChildren();
  for (const form of [ui.propose, ui["review-correction"]]) {
    form.hidden = true;
    form.reset();
  }
}

function updateBatchProgress() {
  if (session) clearTimeout(session.batchTimer);
  const batch = session?.batch;
  const now = Date.now();
  let nextExpiry = Infinity;
  if (batch) {
    for (const [number, receipt] of batch.pages) {
      if (receipt.expiry <= now) batch.pages.delete(number);
      else nextExpiry = Math.min(nextExpiry, receipt.expiry);
    }
  }
  const count = batch?.pages.size ?? 0;
  ui["approve-batch"].hidden = count === 0;
  ui["batch-progress"].textContent = count ? `已核对 ${count} / ${batch.count} 页` : "";
  ui["batch-meta"].textContent = count ? `前批次 ${batch.replaces}` : "";
  ui.approve.disabled = !count || count !== batch.count || session.pending !== null;
  if (Number.isFinite(nextExpiry)) session.batchTimer = setTimeout(updateBatchProgress, nextExpiry - now);
}

function clearBatch() {
  if (session) session.batch = null;
  ui["approve-batch"].reset();
  updateBatchProgress();
}

function clearSelection(keepBatch = false) {
  if (session) {
    session.pending?.abort();
    session.pending = null;
  }
  clearDifference();
  clearPdf();
  if (keepBatch) {
    ui["batch-basis"].value = "";
    updateBatchProgress();
  } else clearBatch();
  ui.status.textContent = "";
}

function updateMode() {
  const selected = mode();
  const hasPage = ["pdf", "proposal", "batch"].includes(selected);
  const hasCorrection = selected === "correction";
  ui["page-field"].hidden = ui.page.disabled = !hasPage;
  ui["run-field"].hidden = ui.run.disabled = hasCorrection;
  ui["correction-field"].hidden = ui.correction.disabled = !hasCorrection;
  ui["run-label"].textContent = selected === "docx" ? "待审批次编号" : "校订批次编号";
  ui["approve-decision"].textContent = selected === "docx" ? "批准 DOCX 批次" : "批准校订";
  ui.show.textContent = previewLabels[selected];
}

function lock(message = "", focus = false) {
  clearSelection();
  if (session) {
    session.rulePending?.abort();
    session.rulePending = null;
    session.activeRule = null;
  }
  if (session) session.token = "";
  session = null;
  ui.token.value = "";
  ui.run.value = "";
  ui.correction.value = "";
  ui.page.value = "1";
  ui["mode-markdown"].checked = true;
  ui["full-size"].checked = false;
  ui["pdf-image"].classList.remove("repair-pdf-full");
  ui["rule-catalog-status"].textContent = "";
  ui["rule-catalog"].replaceChildren();
  ui["rule-impact-form"].reset();
  ui["rule-status"].textContent = "";
  ui["rule-impact-list"].replaceChildren();
  ui["rule-rollback-form"].reset();
  ui["rule-rollback-form"].hidden = true;
  ui["rule-rollback-status"].textContent = "";
  ui["rule-rollback-items"].replaceChildren();
  updateMode();
  ui.workspace.hidden = true;
  ui.lock.hidden = false;
  ui["lock-message"].textContent = message;
  if (focus) ui.token.focus();
}

function element(tag, text, style) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (style) node.className = style;
  return node;
}

function side(label, part) {
  const panel = element("div", undefined, "repair-side");
  panel.append(element("h4", label));
  if (part === null) panel.append(element("p", "此批次未收录"));
  else {
    const position = part.document_paragraph === undefined
      ? `字节 ${part.byte_start}–${part.byte_end}`
      : [...part.heading_path, `文档第 ${part.document_paragraph} 段`].join(" / ");
    panel.append(
      element("p", `第 ${part.paragraph} 段 · 转录 ${part.revision} · ${position}`),
      element("pre", part.excerpt),
    );
  }
  return panel;
}

function retainPreview(payload, run, kind) {
  const expiry = Date.parse(payload.expires_at);
  if (!Number.isFinite(expiry) || expiry <= Date.now()) {
    ui.status.textContent = "预览已失效，请重新核对。";
    return false;
  }
  session.preview = { id: payload.preview_id, run, expiry, kind };
  const owner = session;
  session.timer = setTimeout(() => {
    if (session !== owner) return;
    clearDifference();
    ui.status.textContent = "预览已失效，请重新核对。";
  }, expiry - Date.now());
  return true;
}

function render(payload) {
  const diff = payload.difference;
  if (!retainPreview(payload, diff.run_id, "markdown")) return;
  ui.meta.textContent = `前批次 ${diff.replaces_run_id} · 校订批次 ${diff.run_id}`
    + (diff.rollback_run_id ? ` · 回退基准 ${diff.rollback_run_id}` : "");
  ui.changes.replaceChildren(...diff.changes.map(change => {
    const row = element("li", undefined, "repair-change");
    const columns = element("div", undefined, "repair-columns");
    columns.append(side("校订前", change.before), side("校订后", change.after));
    row.append(element("h3", change.passage_id), columns);
    return row;
  }));
  ui.difference.hidden = false;
  ui.status.textContent = `${diff.changes.length} 处差异`;
}

function renderDocx(payload) {
  const batch = payload.batch;
  if (!retainPreview(payload, batch.run_id, "docx")) return;
  ui.meta.textContent = `待审批次 ${batch.run_id} · 版本 ${batch.version_id}`;
  if (batch.repair) {
    ui.meta.textContent += ` · 隔离批次 ${batch.repair.replaces_run_id} · 校订依据 ${batch.repair.repair_basis_id}`;
    if (batch.repair.rollback_run_id) ui.meta.textContent += ` · 回退基准 ${batch.repair.rollback_run_id}`;
  }
  const tables = batch.tables ?? [];
  const paragraphs = batch.paragraphs.map(part => {
    const item = element("li", undefined, "repair-change");
    const location = [...part.location.heading_path, `第 ${part.location.paragraph} 段`].join(" / ");
    item.append(transcriptPanel(
      `${location} · 主文档第 ${part.document_paragraph} 段 · 转录 ${part.excerpt_revision}`, part.excerpt,
    ));
    return item;
  });
  const changes = batch.repair?.changes.map(renderDocxChange) ?? [];
  ui.changes.replaceChildren(...changes, ...paragraphs, ...tables.map(renderDocxTable));
  ui.difference.hidden = false;
  ui.status.textContent = tables.length ? `已载入 ${paragraphs.length} 段、${tables.length} 张表待审核`
    : `已载入 ${paragraphs.length} 段待审核材料`;
}

function renderDocxChange(change) {
  const location = change.after ?? change.before;
  const label = location.table === undefined ? `主文档第 ${location.document_paragraph} 段`
    : `第 ${location.table} 表 / 第 ${location.row} 行 / 第 ${location.column} 列`;
  const status = side => {
    if (side === null) return "无记录";
    const role = docxRowReasons[side.reason] ?? docxRoles[side.role];
    return [role, `修订 ${side.revision}`].filter(Boolean).join(" · ");
  };
  const item = element("li", undefined, "repair-change");
  item.append(element("h3", label), element("p", `校订前 ${status(change.before)}`),
    element("p", `校订后 ${status(change.after)}`));
  if (change.before && change.after) {
    if (change.before.excerpt_sha256 !== change.after.excerpt_sha256) item.append(element("p", "原值摘要有变化"));
    if (change.before.header_sha256 !== change.after.header_sha256) item.append(element("p", "表头摘要有变化"));
  }
  return item;
}

function tableHeader(text, scope) {
  const header = element("th", text);
  header.scope = scope;
  return header;
}

function renderDocxTable(source) {
  const item = element("li", undefined, "repair-change");
  const label = [...source.heading_path, `第 ${source.table_number} 表`].join(" / ");
  const wrapper = element("div", undefined, "repair-table-scroll");
  wrapper.tabIndex = 0;
  wrapper.setAttribute("role", "region");
  wrapper.setAttribute("aria-label", label);
  const table = element("table", undefined, "repair-table");
  const heading = element("tr");
  heading.append(...["原件行号", ...source.headers, "证据组"].map(text => tableHeader(text, "col")));
  const head = element("thead");
  head.append(heading);
  const body = element("tbody");
  for (const row of source.rows) {
    const line = element("tr");
    line.append(tableHeader(String(row.row_number), "row"));
    for (const cell of row.cells) {
      const field = element("td");
      field.append(element("pre", cell.excerpt), element("small",
        `${cell.role ? `${docxRoles[cell.role]} · ` : ""}修订 ${cell.excerpt_revision}`));
      line.append(field);
    }
    line.append(element("td", row.reason === null ? "完整" : docxRowReasons[row.reason] ?? "不组成证据组"));
    body.append(line);
  }
  table.append(element("caption", label), head, body);
  wrapper.append(table);
  item.append(wrapper);
  return item;
}

function transcriptPanel(label, text) {
  const panel = element("div", undefined, "repair-side");
  panel.append(element("h4", label), element("pre", text));
  return panel;
}

async function renderPdf(body, selected, target, number, owner, current, started) {
  const page = body.page_number;
  if (!Number.isInteger(page) || !pageNumber.test(page) || !uuid.test(body.run_id)
      || !uuid.test(body.version_id) || !uuid.test(body.request_id)
      || typeof body.png_base64 !== "string" || body.png_base64.length > 17_000_000
      || !body.png_base64.startsWith("iVBORw0KGgo")) {
    throw new Error("Unexpected PDF page response");
  }
  if (selected === "correction") {
    if (body.correction_id !== target || typeof body.proposed_transcript !== "string"
        || (body.previous_transcript !== null && typeof body.previous_transcript !== "string")) {
      throw new Error("Unexpected OCR comparison response");
    }
  } else if (body.run_id !== target || page !== number) {
    throw new Error("Unexpected PDF page selection");
  }
  if (selected === "batch" && (!Number.isInteger(body.page_count) || !pageNumber.test(body.page_count)
      || page > body.page_count || !uuid.test(body.replaces_run_id) || !/^[a-f0-9]{64}$/.test(body.manifest_sha256)
      || typeof body.transcript !== "string" || typeof body.corrected !== "boolean")) {
    throw new Error("Unexpected PDF repair manifest");
  }
  const expires = started + (selected === "batch" ? batchWindow : correctionWindow);
  if (selected !== "pdf" && expires <= Date.now()) throw new Error("Expired PDF preview");
  const binary = atob(body.png_base64);
  const pixels = new Uint8Array(binary.length);
  for (let offset = 0; offset < binary.length; offset += 1) pixels[offset] = binary.charCodeAt(offset);
  const image = element("img");
  image.alt = `PDF 原页，第 ${page} 页`;
  image.draggable = false;
  owner.imageUrl = URL.createObjectURL(new Blob([pixels], { type: "image/png" }));
  image.src = owner.imageUrl;
  await image.decode();
  if (!current()) return;
  if (selected !== "pdf" && expires <= Date.now()) throw new Error("Expired PDF preview");
  ui["pdf-meta"].textContent = `第 ${page} 页 · 版本 ${body.version_id}`;
  ui["pdf-image"].replaceChildren(image);
  ui.pdf.hidden = false;
  ui.status.textContent = "";
  if (selected === "proposal" || selected === "correction") {
    owner.pdfReceipt = { id: body.request_id, target, page, expires };
    owner.pdfTimer = setTimeout(() => {
      if (session !== owner) return;
      clearPdf();
      ui.status.textContent = "原页回执已过期，请重新核对。";
    }, expires - Date.now());
  }
  if (selected === "proposal") {
    ui.propose.hidden = false;
  } else if (selected === "correction") {
    const previous = body.previous_transcript === null
      ? `原转录失败：${Object.hasOwn(ocrReasons, body.previous_reason) ? ocrReasons[body.previous_reason] : "无可用转录"}`
      : body.previous_transcript;
    ui["pdf-details"].replaceChildren(
      transcriptPanel("原转录", previous), transcriptPanel("候选转录", body.proposed_transcript),
    );
    ui["pdf-details"].hidden = false;
    ui["review-correction"].hidden = false;
  } else if (selected === "batch") {
    const batch = owner.batch;
    if (!batch || batch.run !== target || batch.version !== body.version_id || batch.manifest !== body.manifest_sha256
        || batch.count !== body.page_count || batch.replaces !== body.replaces_run_id) {
      clearBatch();
      owner.batch = {
        run: target, version: body.version_id, manifest: body.manifest_sha256,
        count: body.page_count, replaces: body.replaces_run_id, pages: new Map(),
      };
    }
    owner.batch.pages.set(page, { id: body.request_id, expiry: expires });
    ui["pdf-details"].replaceChildren(
      transcriptPanel(body.corrected ? "人工校订转录" : "未修改转录", body.transcript),
    );
    ui["pdf-details"].hidden = false;
  }
}

async function request(path, { payload = null, busy, failure, onSuccess, keepBatch = false }) {
  const owner = session;
  if (!owner) return;
  clearSelection(keepBatch);
  const controller = new AbortController();
  owner.pending = controller;
  if (keepBatch) updateBatchProgress();
  const current = () => session === owner && owner.pending === controller && !controller.signal.aborted;
  const started = Date.now();
  ui.status.textContent = busy;
  try {
    const headers = { Authorization: `Bearer ${owner.token}` };
    if (payload) Object.assign(headers, {
      "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID(),
    });
    const result = await fetch(`${evidencePath}${path}`, {
      method: payload ? "POST" : "GET", headers, body: payload ? JSON.stringify(payload) : undefined,
      signal: controller.signal, cache: "no-store", credentials: "omit", mode: "same-origin",
      redirect: "error", referrerPolicy: "no-referrer",
    });
    if (!current()) return;
    if (result.status === 401) return lock("凭据无效或已过期，请重新载入。", true);
    const body = await result.json();
    if (!current()) return;
    if (!result.ok) {
      clearBatch();
      ui.status.textContent = body.error?.message ?? failure;
    } else {
      await onSuccess(body, owner, current, started);
    }
  } catch {
    if (current()) {
      clearDifference();
      clearPdf();
      clearBatch();
      ui.status.textContent = failure;
    }
  } finally {
    if (current()) {
      owner.pending = null;
      if (keepBatch) updateBatchProgress();
    }
  }
}

function identifier(input) {
  return input.value.trim().toLowerCase();
}

function submit(path, payload, renderResult) {
  request(path, {
    payload, busy: "正在提交…", failure: "未确认提交结果，请核实后再试。",
    onSuccess: body => { ui.status.textContent = renderResult(body); },
  });
}

ui.access.addEventListener("submit", event => {
  event.preventDefault();
  const token = ui.token.value.trim();
  lock();
  if (!/^[A-Za-z0-9_.-]{32,16384}$/.test(token)) return lock("请输入完整的本机管理测试凭据。", true);
  session = { token, pending: null, rulePending: null, activeRule: null, preview: null, imageUrl: null, pdfReceipt: null, batch: null };
  ui.lock.hidden = true;
  ui.workspace.hidden = false;
  ui.run.focus();
});

for (const input of [ui.run, ui.correction]) input.addEventListener("input", () => clearSelection());
ui.page.addEventListener("input", () => clearSelection(mode() === "batch"));
for (const radio of ui.search.elements["repair-mode"]) {
  radio.addEventListener("change", () => {
    clearSelection();
    ui.correction.value = "";
    updateMode();
  });
}
ui["full-size"].addEventListener("change", () => {
  ui["pdf-image"].classList.toggle("repair-pdf-full", ui["full-size"].checked);
});
ui.search.addEventListener("submit", event => {
  event.preventDefault();
  const selected = mode();
  const target = identifier(selected === "correction" ? ui.correction : ui.run);
  if (!uuid.test(target)) {
    ui.status.textContent = selected === "correction" ? "请输入有效的候选编号。" : `请输入有效的${ui["run-label"].textContent}。`;
    return;
  }
  if (selected === "markdown") {
    request(`/repairs/${target}/preview`, {
      busy: "正在读取差异…", failure: "暂时无法完成校订审核。", onSuccess: render,
    });
    return;
  }
  if (selected === "docx") {
    request(`/repairs/${target}/docx-preview?format=table-batch-v1`, {
      busy: "正在读取 DOCX 批次…", failure: "暂时无法查看待审批次。", onSuccess: renderDocx,
    });
    return;
  }
  const page = ui.page.value.trim();
  if (selected !== "correction" && !pageNumber.test(page)) {
    ui.status.textContent = "请输入 1 至 16 的物理页码。";
    return;
  }
  const keepBatch = selected === "batch";
  const path = selected === "correction" ? `/pdf-corrections/${target}/preview`
    : `/repairs/${target}/pdf-pages/${page}${keepBatch ? "/review" : ""}`;
  request(path, {
    busy: "正在读取原页…", failure: "暂时无法查看原页。", keepBatch,
    onSuccess: (body, owner, current, started) => renderPdf(body, selected, target, Number(page), owner, current, started),
  });
});
ui.decision.addEventListener("submit", event => {
  event.preventDefault();
  const selected = session?.preview;
  if (!selected || selected.expiry <= Date.now()) return;
  const basis = identifier(ui.basis);
  const outcome = event.submitter?.value;
  if (!uuid.test(basis) || !["approved", "quarantined"].includes(outcome)) {
    ui.status.textContent = "请输入有效的审核依据编号。";
    return;
  }
  const docx = selected.kind === "docx";
  const subject = docx ? "DOCX 批次" : "校订";
  submit(`/repairs/${selected.run}/${docx ? "docx-decision" : "decision"}`,
    { preview_id: selected.id, outcome, basis_id: basis },
    body => body.outcome === "approved" ? `${subject}已批准。` : `${subject}已拒绝并隔离。`);
});
ui.propose.addEventListener("submit", event => {
  event.preventDefault();
  const receipt = session?.pdfReceipt;
  if (mode() !== "proposal" || !receipt || receipt.expires <= Date.now()) return;
  const basis = identifier(ui["proposal-basis"]);
  const transcript = ui.transcript.value;
  if (!uuid.test(basis) || !transcript.trim() || new TextEncoder().encode(transcript).length > 32_768) {
    ui.status.textContent = "请输入有效的依据编号及不超过 32 KiB 的非空转录。";
    return;
  }
  submit(`/repairs/${receipt.target}/pdf-pages/${receipt.page}/corrections`, {
    preview_request_id: receipt.id, basis_id: basis, transcript,
  }, body => `候选已提交：${body.correction_id}`);
});
ui["review-correction"].addEventListener("submit", event => {
  event.preventDefault();
  const receipt = session?.pdfReceipt;
  if (mode() !== "correction" || !receipt || receipt.expires <= Date.now()) return;
  const basis = identifier(ui["correction-basis"]);
  const outcome = event.submitter?.value;
  if (!uuid.test(basis) || !["approved", "rejected"].includes(outcome)) {
    ui.status.textContent = "请输入有效的复核依据编号。";
    return;
  }
  submit(`/pdf-corrections/${receipt.target}/decision`, { preview_request_id: receipt.id, outcome, basis_id: basis },
    body => body.outcome === "approved" ? "候选已批准。" : "候选已拒绝。");
});
ui["approve-batch"].addEventListener("submit", event => {
  event.preventDefault();
  if (!session?.batch || session.pending || mode() !== "batch") return;
  updateBatchProgress();
  if (ui.approve.disabled) return;
  const basis = identifier(ui["batch-basis"]);
  if (!uuid.test(basis)) {
    ui.status.textContent = "请输入有效的整批审定依据编号。";
    return;
  }
  const { run, count, pages } = session.batch;
  submit(`/repairs/${run}/pdf-approval`, {
    basis_id: basis, preview_request_ids: Array.from({ length: count }, (_, index) => pages.get(index + 1).id),
  }, () => "修订批次已批准。");
});
function ruleNode(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function ruleRandomKey() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return `rule_rb_${crypto.randomUUID().replace(/-/g, "")}`;
  }
  return `rule_rb_${Date.now()}_${Math.random().toString(36).slice(2, 12)}`;
}

async function ruleApi(path, { method = "GET", body = null, idempotencyKey = null } = {}) {
  const owner = session;
  if (owner === null) throw new Error("locked");
  owner.rulePending?.abort();
  const controller = new AbortController();
  owner.rulePending = controller;
  const headers = { Authorization: `Bearer ${owner.token}` };
  if (body !== null) headers["Content-Type"] = "application/json";
  if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
  const response = await fetch(`${evidencePath}${path}`, {
    method, headers, body: body !== null ? JSON.stringify(body) : undefined, signal: controller.signal,
    cache: "no-store", credentials: "omit", mode: "same-origin", redirect: "error", referrerPolicy: "no-referrer",
  });
  if (session !== owner || owner.rulePending !== controller || controller.signal.aborted) return null;
  owner.rulePending = null;
  return response;
}

async function loadRuleCatalog() {
  if (!session) return;
  ui["rule-catalog-status"].textContent = "正在读取空间规则目录…";
  ui["rule-catalog"].replaceChildren();
  try {
    const response = await ruleApi("/rules");
    if (!response) return;
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      ui["rule-catalog-status"].textContent = payload.error?.message ?? `读取规则目录失败（HTTP ${response.status}）。`;
      return;
    }
    const rows = payload.revisions ?? [];
    ui["rule-catalog-status"].textContent = rows.length
      ? `已载入 ${rows.length} 个清洗规则修订，历史回退 ${payload.rollbacks?.length ?? 0} 次。`
      : "当前范围没有清洗规则记录。";
    ui["rule-catalog"].replaceChildren(...rows.map(item => {
      const li = ruleNode("li", undefined, "wiki-topic");
      const header = ruleNode("div", undefined, "wiki-topic-header");
      header.append(
        ruleNode("strong", `规则修订 #${item.configuration_revision}`),
        ruleNode("span", `${item.profile} · v${item.parser_version}`, "wiki-generation"),
      );
      const meta = ruleNode(
        "p",
        `涉及批次 ${item.run_count} · 当前最新 ${item.latest_run_count} · 已隔离 ${item.quarantined_count}`,
        "repair-meta",
      );
      const btn = ruleNode("button", "查此规则影响", "quiet-button");
      btn.type = "button";
      btn.addEventListener("click", () => {
        ui["rule-revision"].value = String(item.configuration_revision);
        loadRuleImpact(item.configuration_revision, ui["rule-source"].value.trim());
      });
      li.append(header, meta, btn);
      return li;
    }));
  } catch {
    if (session) ui["rule-catalog-status"].textContent = "读取规则目录失败，请重试。";
  }
}

async function loadRuleImpact(revision, sourceId = "") {
  if (!session) return;
  ui["rule-status"].textContent = `正在查询规则 #${revision} 受影响批次…`;
  ui["rule-impact-list"].replaceChildren();
  ui["rule-rollback-form"].hidden = true;
  ui["rule-rollback-status"].textContent = "";
  ui["rule-rollback-items"].replaceChildren();
  const query = sourceId ? `?source_id=${encodeURIComponent(sourceId)}` : "";
  try {
    const response = await ruleApi(`/rules/${encodeURIComponent(String(revision))}/impact${query}`);
    if (!response) return;
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      ui["rule-status"].textContent = payload.error?.message ?? `影响清单查询失败（HTTP ${response.status}）。`;
      return;
    }
    const summary = payload.summary;
    session.activeRule = { revision, sourceId: sourceId || null };
    ui["rule-status"].textContent =
      `规则 #${revision}（${payload.rule.profile}）：共 ${summary.total_runs} 个批次，`
      + `最新 ${summary.latest_runs}，可自动回退 ${summary.rollback_eligible}，`
      + `已停用/删除 ${summary.stopped_or_deleted}，保全 ${summary.held}，关联 Wiki ${summary.affected_wikis.length} 个。`;
    ui["rule-impact-list"].replaceChildren(...payload.items.map(item => {
      const li = ruleNode("li", undefined, "wiki-topic");
      const header = ruleNode("div", undefined, "wiki-topic-header");
      const title = ruleNode("h3");
      title.append(ruleNode("code", item.run_id));
      const state = ruleNode("span", qualityStates[item.quality_status] ?? item.quality_status, "wiki-state");
      state.dataset.state = item.rollback_eligible ? "published" : "needs_rebuild";
      header.append(title, state);
      const reasonsText = item.ineligible_reasons.map(code => rollbackReasons[code] ?? code).join("、");
      const summaryLine = item.rollback_eligible
        ? `可回退至基线 ${item.baseline_run_id}（规则 #${item.baseline_configuration_revision}）`
        : `不可自动回退：${reasonsText}`;
      const meta = ruleNode(
        "p",
        `版本 ${item.version_id} · ${item.media_type} · ${summaryLine}`
        + (item.affected_wiki_ids.length ? ` · 影响 Wiki：${item.affected_wiki_ids.join(", ")}` : ""),
        "repair-meta",
      );
      li.append(header, meta);
      if (item.rollback_run_id) {
        const openBtn = ruleNode("button", "载入回退差异核对", "quiet-button");
        openBtn.type = "button";
        openBtn.addEventListener("click", () => {
          ui["mode-markdown"].checked = true;
          updateMode();
          ui.run.value = item.rollback_run_id;
          ui.run.focus();
        });
        li.append(openBtn);
      }
      return li;
    }));
    ui["rule-rollback-form"].hidden = payload.items.length === 0;
  } catch {
    if (session) ui["rule-status"].textContent = "影响清单查询失败，请重试。";
  }
}

ui["rule-refresh"].addEventListener("click", () => loadRuleCatalog());

ui["rule-impact-form"].addEventListener("submit", event => {
  event.preventDefault();
  const revText = ui["rule-revision"].value.trim();
  const sourceId = ui["rule-source"].value.trim();
  if (!/^[1-9][0-9]*$/.test(revText)) {
    ui["rule-status"].textContent = "请输入正整数规则配置修订号。";
    return;
  }
  if (sourceId && !uuid.test(sourceId)) {
    ui["rule-status"].textContent = "来源编号须为有效 UUID。";
    return;
  }
  loadRuleImpact(Number.parseInt(revText, 10), sourceId);
});

ui["rule-rollback-form"].addEventListener("submit", async event => {
  event.preventDefault();
  if (!session?.activeRule) return;
  const reasonCode = ui["rule-reason"].value.trim();
  const basisId = identifier(ui["rule-basis"]);
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(reasonCode) || !uuid.test(basisId)) {
    ui["rule-rollback-status"].textContent = "请输入小写原因码与有效依据 UUID。";
    return;
  }
  ui["rule-rollback-status"].textContent = "正在隔离受影响批次并排入跨批次回退…";
  const body = { reason_code: reasonCode, basis_id: basisId };
  if (session.activeRule.sourceId) body.source_id = session.activeRule.sourceId;
  try {
    const response = await ruleApi(`/rules/${encodeURIComponent(String(session.activeRule.revision))}/rollback`, {
      method: "POST",
      idempotencyKey: ruleRandomKey(),
      body,
    });
    if (!response) return;
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      ui["rule-rollback-status"].textContent = payload.error?.message ?? `跨批次回退失败（HTTP ${response.status}）。`;
      return;
    }
    ui["rule-rollback-status"].textContent =
      `已登记规则回退 ${payload.rollback_id}：当场隔离 ${payload.quarantined_count}，`
      + `已排入回退 ${payload.queued_count}（目标规则 #${payload.target_configuration_revision ?? "无"}），`
      + `跳过 ${payload.skipped_count}。`;
    ui["rule-rollback-items"].replaceChildren(...(payload.items ?? []).map(entry => {
      const label = entry.action === "queued_rollback"
        ? `已入队回退（任务 ${entry.queued_job_id} -> 基线 ${entry.baseline_run_id}）`
        : `已跳过（${rollbackReasons[entry.skip_reason] ?? entry.skip_reason}）`;
      return ruleNode("li", `批次 ${entry.faulty_run_id}：${label}`, "wiki-input-item");
    }));
  } catch {
    if (session) ui["rule-rollback-status"].textContent = "跨批次回退请求失败，请重试。";
  }
});

ui.logout.addEventListener("click", () => lock("已清除凭据与预览。", true));
window.addEventListener("pagehide", () => lock());
window.addEventListener("pageshow", event => {
  if (event.persisted) lock("页面已重新锁定，请载入凭据。");
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) lock("页面已锁定，请重新载入凭据。");
});
lock();

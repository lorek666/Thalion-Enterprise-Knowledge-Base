const wikiHeading = /^ {0,3}(#{1,6})[ \t]+(.+?)\s*$/;
const wikiListItem = /^( {0,3})([-+*]|\d{1,9}[.)])[ \t]+(.+)$/;
const wikiQuote = /^ {0,3}>[ \t]?/;
const wikiFence = /^ {0,3}(`{3,}(?!`)(?=[^`]*$)|~{3,})(.*)$/;
const wikiInlineLink = String.raw`\[([^\[\]\\]*(?:\\.[^\[\]\\]*)*)\]\((?:<([^<>\s]+)>|([^()<>\s]+))\)`;

function parseTableRow(line) {
  const value = line.trim().replace(/^\|/, "");
  const cells = [];
  let cell = "";
  let escaped = false;
  for (const character of value) {
    if (character === "|" && !escaped) {
      cells.push(cell.trim());
      cell = "";
      continue;
    }
    if (character === "\\" && !escaped) {
      escaped = true;
      cell += character;
      continue;
    }
    escaped = false;
    cell += character;
  }
  if (cell || !value.endsWith("|") || escaped) cells.push(cell.trim());
  return cells.map(cellValue => cellValue.replace(/\\\|/g, "|"));
}

function tableDivider(lines, index) {
  if (!lines[index]?.includes("|") || !lines[index + 1]?.includes("|")) return null;
  const divider = parseTableRow(lines[index + 1]);
  return divider.length === parseTableRow(lines[index]).length && divider.every(cell => /^:?-{3,}:?$/.test(cell))
    ? divider : null;
}

function parseMarkdown(markdown) {
  const lines = markdown.split("\n");
  const offsets = [0];
  for (const line of lines) offsets.push(offsets.at(-1) + line.length + 1);
  const blocks = [];
  let index = 0;
  function add(block, start) {
    blocks.push({ ...block, from: offsets[start], to: offsets[index] - 1 });
  }
  while (index < lines.length) {
    if (!lines[index].trim()) {
      index += 1;
      continue;
    }
    const start = index;
    const fence = lines[index].match(wikiFence);
    if (fence) {
      const close = new RegExp(`^ {0,3}${fence[1][0]}{${fence[1].length},}\\s*$`);
      const language = fence[2].trim();
      index += 1;
      while (index < lines.length && !close.test(lines[index])) index += 1;
      const value = lines.slice(start + 1, index).join("\n");
      if (index < lines.length) index += 1;
      add({ type: "code", language, value }, start);
      continue;
    }
    const heading = lines[index].match(wikiHeading);
    if (heading) {
      index += 1;
      add({ type: "heading", level: heading[1].length, text: heading[2].replace(/\s+#+$/, "") }, start);
      continue;
    }
    const divider = tableDivider(lines, index);
    if (divider) {
      const headers = parseTableRow(lines[index]);
      const rows = [];
      index += 2;
      while (lines[index]?.includes("|") && !lines[index].match(wikiHeading) && !lines[index].match(wikiFence)) {
        rows.push(parseTableRow(lines[index]));
        index += 1;
      }
      add({ type: "table", headers, divider, rows }, start);
      continue;
    }
    const list = lines[index].match(wikiListItem);
    if (list) {
      const marker = list[2].at(-1);
      const ordered = /^\d/.test(list[2]);
      const items = [];
      let simple = true;
      while (lines[index]?.trim()) {
        const item = lines[index].match(wikiListItem);
        if (item && item[1] === list[1] && item[2].at(-1) === marker) items.push(item[3]);
        else if (/^[ \t]/.test(lines[index])) simple = false;
        else break;
        index += 1;
      }
      add(simple ? { type: "list", ordered, start: ordered ? parseInt(list[2], 10) : 1, items }
        : { type: "source", text: lines.slice(start, index).join("\n") }, start);
      continue;
    }
    if (wikiQuote.test(lines[index])) {
      const linesInQuote = [];
      while (wikiQuote.test(lines[index] ?? "")) {
        linesInQuote.push(lines[index].replace(wikiQuote, ""));
        index += 1;
      }
      add({ type: "quote", text: linesInQuote.join("\n") }, start);
      continue;
    }
    index += 1;
    while (lines[index]?.trim()) {
      if ([wikiHeading, wikiListItem, wikiQuote, wikiFence].some(pattern => pattern.test(lines[index])) || tableDivider(lines, index)) break;
      index += 1;
    }
    const paragraph = lines.slice(start, index).join("\n");
    const link = paragraph.match(new RegExp(`^${wikiInlineLink}$`));
    if (link && safeLinkUrl(link[2] ?? link[3])) {
      add({ type: "link", text: unescapeMarkdown(link[1]), url: link[2] ?? link[3] }, start);
    } else {
      add({ type: "paragraph", text: paragraph }, start);
    }
  }
  return blocks;
}

function escapeTableCell(value) {
  return String(value ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function codeFenceFor(value, language) {
  const marker = language.includes("`") ? "~" : "`";
  let length = 3;
  for (const run of value.match(new RegExp(`${marker}+`, "g")) ?? []) length = Math.max(length, run.length + 1);
  return marker.repeat(length);
}

function serializeBlock(block) {
  if (block.type === "heading") return `${"#".repeat(block.level)} ${block.text}`;
  if (block.type === "list") {
    return block.items.map((item, index) => block.ordered ? `${block.start + index}. ${item}` : `- ${item}`).join("\n");
  }
  if (block.type === "table") {
    const divider = block.headers.map((_, index) => block.divider?.[index] ?? "---");
    const rows = block.rows.map(row => block.headers.map((_, index) => row[index] ?? ""));
    return [block.headers.map(escapeTableCell), divider, ...rows.map(row => row.map(escapeTableCell))]
      .map(row => `| ${row.join(" | ")} |`).join("\n");
  }
  if (block.type === "quote") return block.text.split("\n").map(line => `> ${line}`).join("\n");
  if (block.type === "code") {
    const fence = codeFenceFor(block.value, block.language);
    return `${fence}${block.language}\n${block.value}\n${fence}`;
  }
  if (block.type === "link") return `[${block.text.replace(/[\\[\]]/g, "\\$&")}](<${block.url}>)`;
  return block.text;
}

function safeLinkUrl(url) {
  if (!url || /[\s\\<>\u0000-\u001f\u007f]/.test(url)) return null;
  if (/^\/(?!\/)|^#/.test(url)) return url;
  if (!/^https?:\/\//i.test(url)) return null;
  try {
    const parsed = new URL(url);
    return parsed.username || parsed.password ? null : url;
  } catch {
    return null;
  }
}

function unescapeMarkdown(text) {
  return text.replace(/\\([!-/:-@\[-`{-~])/g, "$1");
}

function wikiLink(label, url) {
  const link = element("a", label);
  link.setAttribute("href", url);
  if (!url.startsWith("#")) {
    link.target = "_blank";
    link.rel = "noopener noreferrer";
  }
  return link;
}

function appendInlineSafe(root, value) {
  const pattern = new RegExp(String.raw`(\\[!-/:-@\[-\x60{-~])|(!?)${wikiInlineLink}|\*\*([^*\n]+)\*\*|\x60([^\x60\n]+)\x60|\*([^*\n]+)\*`, "g");
  let offset = 0;
  for (const match of value.matchAll(pattern)) {
    if (match.index > offset) root.append(value.slice(offset, match.index));
    const [, escaped, image, label, bracketUrl, bareUrl, strong, code, emphasis] = match;
    if (escaped) root.append(escaped.slice(1));
    else if (label !== undefined) {
      const url = safeLinkUrl(bracketUrl ?? bareUrl);
      root.append(!image && url ? wikiLink(unescapeMarkdown(label), url) : match[0]);
    } else if (strong) root.append(element("strong", strong));
    else if (code) root.append(element("code", code));
    else root.append(element("em", emphasis));
    offset = match.index + match[0].length;
  }
  root.append(value.slice(offset));
}

function renderBlockSafe(block, root) {
  if (block.type === "heading") {
    const heading = document.createElement(`h${Math.min(6, Math.max(1, block.level || 1))}`);
    appendInlineSafe(heading, block.text);
    root.append(heading);
  } else if (block.type === "list") {
    const list = document.createElement(block.ordered ? "ol" : "ul");
    if (block.ordered && block.start !== 1) list.start = block.start;
    for (const item of block.items) {
      const li = document.createElement("li");
      appendInlineSafe(li, item);
      list.append(li);
    }
    root.append(list);
  } else if (block.type === "table") {
    const scroll = element("div", undefined, "wiki-table-scroll");
    const table = document.createElement("table");
    const head = document.createElement("thead");
    const headRow = document.createElement("tr");
    for (const cell of block.headers) {
      const th = document.createElement("th");
      th.scope = "col";
      appendInlineSafe(th, cell);
      headRow.append(th);
    }
    head.append(headRow);
    const body = document.createElement("tbody");
    for (const row of block.rows) {
      const tr = document.createElement("tr");
      for (const [index] of block.headers.entries()) {
        const td = document.createElement("td");
        appendInlineSafe(td, row[index] ?? "");
        tr.append(td);
      }
      body.append(tr);
    }
    table.append(head, body);
    scroll.append(table);
    root.append(scroll);
  } else if (block.type === "quote") {
    const quote = document.createElement("blockquote");
    appendInlineSafe(quote, block.text);
    root.append(quote);
  } else if (block.type === "code") {
    const pre = document.createElement("pre");
    const code = document.createElement("code");
    code.textContent = block.value;
    pre.append(code);
    root.append(pre);
  } else if (block.type === "link") {
    root.append(wikiLink(block.text, block.url));
  } else if (block.type === "source") {
    root.append(element("pre", block.text));
  } else {
    const paragraph = document.createElement("p");
    appendInlineSafe(paragraph, block.text ?? "");
    root.append(paragraph);
  }
}

function renderMarkdownSafe(markdown, root) {
  const fragment = document.createDocumentFragment();
  for (const block of parseMarkdown(markdown.replace(/\r\n?/g, "\n"))) renderBlockSafe(block, fragment);
  root.replaceChildren(fragment);
}

const ui = Object.fromEntries([
  "lock", "access-form", "token", "lock-message", "workspace", "register-title", "status", "topics",
  "refresh", "logout", "next",
  "ledger-section", "rebuilds-section", "rebuilds-status", "rebuilds",
  "author-section", "inputs-form", "business-date", "direct-inputs", "parent-manifests", "rebuild-event",
  "clear-rebuild", "inputs-status", "candidate-form", "manifest-id", "topic-key", "draft-title",
  "draft-markdown", "draft-source", "editor-mode", "structured-editor", "block-type", "add-block", "draft-blocks",
  "block-editor", "block-editor-fields", "apply-block", "cancel-block", "block-editor-status", "editor-status",
  "reviewer-ref", "citations", "statements", "ai-instructions", "ai-budget", "ai-generate-btn", "submit-candidate", "candidate-status",
  "queue-section", "queue-status", "revisions", "preview-panel", "preview-title", "preview-meta",
  "preview-markdown", "preview-source-toggle", "preview-source", "preview-inputs", "citation-empty", "citation-detail", "citation-text", "comparison-box", "comparison-meta",
  "review-form", "review-reason", "approve-btn", "reject-btn", "publish-btn", "review-status", "publish-diagnosis",
  "release-section", "release-summary", "release-switch-form", "release-action", "release-wiki-enabled",
  "release-lexical-mode", "release-target", "release-trigger", "release-reason", "release-switch-status",
  "topic-rollback-form", "rollback-topic", "rollback-revision", "rollback-date", "rollback-reason",
  "topic-rollback-status", "release-history",
].map(name => [name, document.getElementById(`wiki-${name}`)]));

const states = { needs_rebuild: "待重编", published: "已发布", not_published: "未发布" };
const reasons = {
  withdrawn: "来源撤回", suspended: "来源停用", quarantined: "质量隔离", reprocessed: "证据重处理",
  policy_changed: "来源策略变更", rule_replaced: "制度换版",
  custody_hold: "输入版本已保全", deletion_blocked: "来源删除隔离",
};
const review = {
  awaiting_review: "待审核", approved: "已记录批准", rejected: "已驳回", stale: "需重新审核", published: "已发布",
};
const unavailable = "暂时无法读取台账，请稍后重试。";
let session = null;
let activePreview = null;
let releaseOverview = null;
let editingBlock = null;
let previewLoad = null;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function dualButton(srText, visibleText, className) {
  const btn = element("button", undefined, className);
  btn.type = "button";
  const sr = element("span", srText, "sr-only");
  const vis = element("span", visibleText);
  vis.setAttribute("aria-hidden", "true");
  btn.append(sr, vis);
  return btn;
}

function randomUuid() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function randomKey(prefix) {
  return `${prefix}_${randomUuid().replace(/-/g, "")}`;
}

function parsePairs(raw) {
  const lines = raw.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  return lines.map(line => {
    const [ref, rev] = line.split(":").map(part => part.trim());
    const parsed = Number.parseInt(rev, 10);
    if (!ref || !Number.isInteger(parsed) || parsed < 1) throw new Error("invalid_pair");
    return [ref, parsed];
  });
}

function editorField(labelText, type, value) {
  const label = element("label", labelText);
  const field = document.createElement(type === "textarea" ? "textarea" : "input");
  field.value = value;
  if (type !== "textarea") field.type = type;
  if (type === "textarea") field.rows = 3;
  label.append(field);
  return { label, field };
}

function renderDraftBlocks() {
  const blocks = parseMarkdown(ui["draft-markdown"].value);
  const fragment = document.createDocumentFragment();
  for (const block of blocks) {
    const item = element("li", undefined, "wiki-draft-block");
    const body = element("div", undefined, "wiki-draft-block-body wiki-markdown-content");
    renderBlockSafe(block, body);
    const actions = element("div", undefined, "wiki-block-actions");
    const edit = dualButton("编辑此块", "编辑", "quiet-button");
    edit.addEventListener("click", () => openBlockEditor(block));
    const remove = dualButton("删除此块", "删除", "quiet-button");
    remove.addEventListener("click", () => {
      replaceDraftBlock(block, "");
      ui["add-block"].focus();
    });
    actions.append(edit, remove);
    item.append(body, actions);
    fragment.append(item);
  }
  ui["draft-blocks"].replaceChildren(fragment);
  ui["editor-status"].textContent = blocks.length ? `${blocks.length} 个内容块。` : "暂无正文，请选择类型添加内容块。";
}

function makeBlock(type) {
  if (type === "heading") return { type, level: 2, text: "" };
  if (type === "list") return { type, ordered: false, start: 1, items: [""] };
  if (type === "table") return { type, headers: ["", ""], rows: [["", ""]] };
  if (type === "quote") return { type, text: "" };
  if (type === "code") return { type, language: "", value: "" };
  return { type: "link", text: "", url: "" };
}

function openBlockEditor(existing = null) {
  if (editingBlock) return;
  const block = existing ?? makeBlock(ui["block-type"].value);
  const fields = ui["block-editor-fields"];
  fields.replaceChildren();
  function addField(labelText, type, value, container = fields) {
    const control = editorField(labelText, type, value);
    container.append(control.label);
    return control.field;
  }
  let read;
  if (block.type === "heading") {
    const text = addField("标题文字", "text", block.text);
    const level = addField("标题级别", "number", block.level);
    level.min = "1";
    level.max = "6";
    read = () => ({ type: block.type, text: text.value.trim(), level: level.valueAsNumber });
  } else if (block.type === "list") {
    const items = addField("列表项（每行一项）", "textarea", block.items.join("\n"));
    const label = element("label", "列表样式");
    const select = document.createElement("select");
    select.add(new Option("无序列表", "false"));
    select.add(new Option("有序列表", "true"));
    select.value = String(block.ordered);
    label.append(select);
    fields.append(label);
    const start = addField("有序列表起始编号", "number", block.start);
    start.min = "0";
    start.max = "999999999";
    const updateNumber = () => { start.parentElement.hidden = select.value === "false"; };
    select.addEventListener("change", updateNumber);
    updateNumber();
    read = () => ({ type: block.type, ordered: select.value === "true", start: start.valueAsNumber,
      items: items.value.split("\n").map(item => item.trim()).filter(Boolean) });
  } else if (block.type === "table") {
    read = editWikiTable(block, fields, addField);
  } else if (block.type === "quote") {
    const text = addField("引用文字", "textarea", block.text);
    read = () => ({ type: block.type, text: text.value.trim() });
  } else if (block.type === "code") {
    const language = addField("代码语言（选填）", "text", block.language);
    const value = addField("代码内容", "textarea", block.value);
    read = () => ({ type: block.type, language: language.value.trim(), value: value.value });
  } else if (block.type === "link") {
    const text = addField("链接文字", "text", block.text);
    const url = addField("链接地址", "text", block.url);
    read = () => ({ type: block.type, text: text.value.trim(), url: url.value.trim() });
  } else {
    const text = addField("此块 Markdown 源码", "textarea", block.text);
    read = () => ({ type: block.type, text: text.value });
  }
  editingBlock = { existing, read, focusReturn: document.activeElement };
  setBlockEditing(true);
  fields.querySelector("input, textarea, select")?.focus();
}

function editWikiTable(block, fields, addField) {
  const grid = element("div", undefined, "wiki-table-fields");
  fields.append(grid);
  const headers = [];
  const rows = [];
  const addColumn = (value = "") => {
    headers.push(addField(`第 ${headers.length + 1} 列表头`, "text", value, grid.firstElementChild));
    for (const [index, row] of rows.entries()) {
      row.push(addField(`第 ${index + 1} 行第 ${headers.length} 列`, "text", "", grid.children[index + 1]));
    }
    return headers.at(-1);
  };
  const addRow = (values = []) => {
    const row = element("div", undefined, "wiki-table-field-row");
    grid.append(row);
    const cells = headers.map((_, index) => addField(`第 ${rows.length + 1} 行第 ${index + 1} 列`, "text", values[index] ?? "", row));
    rows.push(cells);
    return cells[0];
  };
  grid.append(element("div", undefined, "wiki-table-field-row"));
  for (const header of block.headers) addColumn(header);
  for (const row of block.rows) addRow(row);
  const buttons = element("div", undefined, "work-buttons");
  const rowButton = dualButton("添加表格行", "添加行", "quiet-button");
  const columnButton = dualButton("添加表格列", "添加列", "quiet-button");
  rowButton.addEventListener("click", () => addRow().focus());
  columnButton.addEventListener("click", () => addColumn().focus());
  buttons.append(rowButton, columnButton);
  fields.append(buttons);
  const valuesOf = controls => controls.map(control => control.value.trim());
  return () => ({ ...block, headers: valuesOf(headers), rows: rows.map(valuesOf) });
}

function setBlockEditing(editing) {
  ui["block-editor"].hidden = !editing;
  ui["draft-blocks"].inert = editing;
  for (const name of ["editor-mode", "add-block", "block-type", "submit-candidate", "ai-generate-btn"]) {
    ui[name].disabled = editing;
  }
  ui["block-editor-status"].textContent = "";
}

function closeBlockEditor() {
  editingBlock = null;
  setBlockEditing(false);
  ui["block-editor-fields"].replaceChildren();
}

function setEditorMode(label, expanded) {
  ui["editor-mode"].textContent = label;
  ui["editor-mode"].setAttribute("aria-expanded", String(expanded));
}

function replaceDraftBlock(block, replacement) {
  const current = ui["draft-markdown"].value;
  ui["draft-markdown"].value = current.slice(0, block.from) + replacement + current.slice(block.to);
  renderDraftBlocks();
}

function appendDraftBlock(markdown) {
  const current = ui["draft-markdown"].value;
  const separator = !current || current.endsWith("\n\n") ? "" : current.endsWith("\n") ? "\n" : "\n\n";
  ui["draft-markdown"].value = current + separator + markdown;
  renderDraftBlocks();
}

function applyBlockEditor() {
  if (!editingBlock) return;
  const { existing, read } = editingBlock;
  const block = read();
  const invalidNumber = [...ui["block-editor-fields"].querySelectorAll('input[type="number"]')]
    .some(field => !field.parentElement.hidden && (!field.validity.valid || !Number.isInteger(field.valueAsNumber)));
  if (invalidNumber || block.text !== undefined && !block.text.trim() || block.type === "list" && !block.items.length
      || block.type === "table" && !block.headers.some(Boolean)) {
    ui["block-editor-status"].textContent = "请补全内容块并检查编号范围。";
    return;
  }
  if (block.type === "link" && !safeLinkUrl(block.url)) {
    ui["block-editor-status"].textContent = "请输入 HTTP(S) 地址、以单个 / 开头的站内路径或 # 锚点。";
    return;
  }
  const markdown = serializeBlock(block);
  closeBlockEditor();
  if (existing) replaceDraftBlock(existing, markdown);
  else appendDraftBlock(markdown);
  ui["add-block"].focus();
}

function enterStructuredEditor() {
  ui["draft-source"].hidden = true;
  ui["draft-markdown"].required = false;
  ui["structured-editor"].hidden = false;
  setEditorMode("Markdown 源码", true);
  renderDraftBlocks();
}

function showMarkdownSource() {
  ui["draft-source"].hidden = false;
  ui["draft-markdown"].required = true;
  ui["structured-editor"].hidden = true;
  ui["draft-blocks"].replaceChildren();
  setEditorMode("结构化编辑", false);
}

function clearPreview() {
  previewLoad?.abort();
  previewLoad = null;
  activePreview = null;
  ui["preview-panel"].hidden = true;
  ui["preview-title"].textContent = "";
  ui["preview-meta"].textContent = "";
  ui["preview-markdown"].replaceChildren();
  ui["preview-source"].textContent = "";
  ui["preview-source"].hidden = true;
  ui["preview-source-toggle"].hidden = true;
  ui["preview-source-toggle"].textContent = "查看 Markdown 源码";
  ui["preview-source-toggle"].setAttribute("aria-expanded", "false");
  ui["preview-inputs"].replaceChildren();
  if (ui["citation-empty"]) ui["citation-empty"].hidden = false;
  ui["citation-detail"].hidden = true;
  ui["citation-text"].textContent = "";
  ui["comparison-box"].hidden = true;
  ui["comparison-meta"].textContent = "";
  ui["publish-btn"].hidden = true;
  ui["review-status"].textContent = "";
  ui["publish-diagnosis"].replaceChildren();
}

function lock(message = "", focus = false) {
  if (session !== null) {
    session.pending?.abort();
    session.token = "";
  }
  session = null;
  ui.token.value = "";
  ui.topics.replaceChildren();
  ui.topics.setAttribute("aria-busy", "false");
  ui.status.textContent = "";
  ui.next.hidden = true;
  ui["ledger-section"].hidden = false;
  ui["rebuilds-section"].hidden = true;
  ui["rebuilds"].replaceChildren();
  ui["rebuilds-status"].textContent = "";
  ui["author-section"].hidden = true;
  ui["inputs-form"].reset();
  ui["candidate-form"].reset();
  closeBlockEditor();
  showMarkdownSource();
  ui["editor-status"].textContent = "";
  ui["inputs-status"].textContent = "";
  ui["candidate-status"].textContent = "";
  ui["queue-section"].hidden = true;
  ui["queue-status"].textContent = "";
  ui["revisions"].replaceChildren();
  clearPreview();
  releaseOverview = null;
  ui["release-section"].hidden = true;
  ui["release-summary"].textContent = "";
  ui["release-switch-form"].reset();
  ui["release-switch-status"].textContent = "";
  ui["topic-rollback-form"].reset();
  ui["topic-rollback-status"].textContent = "";
  ui["release-target"].replaceChildren(element("option", "不适用"));
  ui["release-target"].firstChild.value = "";
  ui["rollback-topic"].replaceChildren(element("option", "暂无已发布主题"));
  ui["rollback-topic"].firstChild.value = "";
  ui["rollback-revision"].replaceChildren(element("option", "暂无可回退修订"));
  ui["rollback-revision"].firstChild.value = "";
  ui["release-history"].replaceChildren();
  ui.workspace.hidden = true;
  ui.lock.hidden = false;
  ui["lock-message"].textContent = message;
  if (focus) ui.token.focus();
}

async function apiRequest(path, { method = "GET", body = null, idempotencyKey = null, signal = undefined } = {}) {
  const owner = session;
  if (owner === null) throw new Error("locked");
  const headers = { Authorization: `Bearer ${owner.token}` };
  if (body !== null) headers["Content-Type"] = "application/json";
  if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
  return fetch(path, {
    method, headers, body: body !== null ? JSON.stringify(body) : undefined, signal,
    cache: "no-store", credentials: "omit", mode: "same-origin", redirect: "error", referrerPolicy: "no-referrer",
  });
}

function topicRow(topic) {
  const row = element("li", undefined, "wiki-topic");
  const header = element("div", undefined, "wiki-topic-header");
  const reference = element("h3");
  reference.append(element("code", topic.wiki_id));
  header.append(reference, element("span", topic.generation === null ? "无发布代次" : `发布代次 ${topic.generation}`, "wiki-generation"));
  const state = element("span", states[topic.state] ?? "状态未知", "wiki-state");
  state.dataset.state = topic.state;
  const causes = element("ul", undefined, "wiki-reasons");
  causes.setAttribute("aria-label", "停用原因");
  causes.append(...topic.reasons.map(reason => element("li", reasons[reason] ?? "原因待核对")));
  const counters = element("dl", undefined, "wiki-counts");
  for (const key of ["awaiting_review", "approved", "rejected", "stale"]) {
    const label = review[key];
    const item = element("div");
    item.append(element("dt", label), element("dd", topic.review[key]));
    counters.append(item);
  }
  row.append(header, state);
  if (causes.childElementCount > 0) row.append(causes);
  row.append(counters);
  return row;
}

function rebuildRow(item) {
  const row = element("li", undefined, "wiki-topic");
  const header = element("div", undefined, "wiki-topic-header");
  const code = element("h3");
  code.append(element("code", item.event_id));
  header.append(code, element("span", `主题 ${item.wiki_id} · 代次 ${item.generation}`, "wiki-generation"));
  const reasonText = reasons[item.reason] ?? item.reason;
  const action = dualButton("发起干净重编", "重新整理这版总结", "quiet-button");
  action.addEventListener("click", () => {
    ui["rebuild-event"].value = item.event_id;
    ui["parent-manifests"].value = "";
    ui["inputs-status"].textContent = `已填入停用事件 ${item.event_id}，请仅填写未受影响的直接依据进行干净重编。`;
    ui["direct-inputs"].focus();
  });
  row.append(header, element("p", `停用原因：${reasonText}`, "repair-meta"), action);
  return row;
}

function revisionRow(item) {
  const row = element("li", undefined, "wiki-topic");
  const header = element("div", undefined, "wiki-topic-header");
  const heading = element("h3");
  heading.append(element("code", item.revision_id));
  const tag = element("span", review[item.stage] ?? item.stage, "wiki-state");
  tag.dataset.state = item.stage === "stale" ? "needs_rebuild" : item.stage;
  header.append(heading, tag);
  const meta = element(
    "p",
    `主题 ${item.wiki_id} · 业务日 ${item.business_date}${item.is_rebuild ? " · 干净重编" : ""}`
    + (item.published_generation !== null ? ` · 已发布代次 ${item.published_generation}` : ""),
    "repair-meta",
  );
  const buttons = element("div", undefined, "work-buttons");
  if (item.assigned_to_me && item.stage !== "published") {
    const previewBtn = dualButton("载入预览", "打开左右对照核对", "primary-button");
    previewBtn.addEventListener("click", () => loadPreview(item));
    buttons.append(previewBtn);
  }
  if (item.assigned_to_me && item.stage === "approved" && item.review_id) {
    const pubBtn = dualButton("直接发布", "正式发给员工看", "quiet-button");
    pubBtn.addEventListener("click", () => publishRevision(item.revision_id, item.review_id, item.business_date));
    buttons.append(pubBtn);
  }
  row.append(header, meta);
  if (buttons.childElementCount > 0) row.append(buttons);
  return row;
}

async function inspectCitation(passageId) {
  const current = previewLoad;
  if (ui["citation-empty"]) ui["citation-empty"].hidden = true;
  ui["citation-detail"].hidden = false;
  ui["citation-text"].textContent = "正在按你的当前权限实时调取正式原文…";
  try {
    const response = await apiRequest(`/v1/passages/${encodeURIComponent(passageId)}`, { signal: current?.signal });
    if (previewLoad !== current) return;
    if (!response.ok) {
      ui["citation-text"].textContent = `无法读取依据（HTTP ${response.status}）。`;
      return;
    }
    const data = await response.json();
    if (previewLoad !== current) return;
    const p = data.passage ?? data;
    ui["citation-text"].textContent = `${p.title ?? ""}\n${p.excerpt ?? JSON.stringify(data)}`;
  } catch {
    if (previewLoad !== current) return;
    ui["citation-text"].textContent = "原文核对失败，请重试。";
  }
}

async function loadPreview(item) {
  clearPreview();
  const controller = new AbortController();
  previewLoad = controller;
  ui["preview-panel"].hidden = false;
  ui["review-status"].textContent = "正在通过实时授权载入修订预览…";
  try {
    const response = await apiRequest(`/internal/wiki/revisions/${encodeURIComponent(item.revision_id)}/preview`, {
      method: "POST",
      body: { business_date: item.business_date },
      signal: controller.signal,
    });
    const payload = await response.json().catch(() => ({}));
    if (previewLoad !== controller) return;
    if (!response.ok) {
      ui["review-status"].textContent = payload.error?.message ?? `预览被拒绝（HTTP ${response.status}）。`;
      return;
    }
    activePreview = {
      revision_id: item.revision_id,
      business_date: item.business_date,
      content_digest: payload.content_digest,
      input_digest: payload.input_digest,
      review_material_id: payload.review_material_id,
      review_id: item.review_id,
    };
    ui["preview-title"].textContent = payload.content.title;
    ui["preview-meta"].textContent = `修订 ${item.revision_id} · 预期前代次 ${payload.expected_generation ?? 0} · 有效至 ${payload.valid_until}`;
    renderMarkdownSafe(payload.content.markdown, ui["preview-markdown"]);
    ui["preview-source"].textContent = payload.content.markdown;
    ui["preview-source-toggle"].hidden = false;
    ui["preview-inputs"].replaceChildren(...payload.manifest_inputs.map(entry => {
      const li = element("li", undefined, "wiki-input-item");
      const label = entry.cited ? "正文已引用" : "背景参考（受权限联动）";
      const meta = element("span", undefined, "wiki-input-meta");
      meta.append(element("code", `${entry.passage_id}:r${entry.excerpt_revision}`), element("span", ` · ${label}`));
      const btn = dualButton("核对原文", "看右边原文 ▸", "quiet-button");
      btn.addEventListener("click", () => inspectCitation(entry.passage_id));
      li.append(meta, btn);
      return li;
    }));
    if (payload.comparison && payload.comparison.previous_generation > 0) {
      ui["comparison-box"].hidden = false;
      ui["comparison-meta"].textContent = payload.comparison.previous_content_available
        ? `前代代次 ${payload.comparison.previous_generation}（标题：${payload.comparison.previous_title}），新增引用 ${payload.comparison.added_citations.length} 条，移除引用 ${payload.comparison.removed_citations.length} 条。`
        : `前代代次 ${payload.comparison.previous_generation} 已停用或当前无权读取，不展示旧正文。`;
    }
    ui["publish-btn"].hidden = !activePreview.review_id;
    ui["review-status"].textContent = "预览已载入，请逐条核对全部输入依据后决定批准或驳回。";
  } catch {
    if (previewLoad !== controller) return;
    ui["review-status"].textContent = "预览加载失败，请重试。";
  }
}

async function submitDecision(decision) {
  if (!activePreview) return;
  const reasonCode = ui["review-reason"].value.trim();
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(reasonCode)) {
    ui["review-status"].textContent = "审核原因码须为小写字母开头的下划线标识。";
    return;
  }
  ui["review-status"].textContent = "正在提交审核决定…";
  try {
    const response = await apiRequest(`/internal/wiki/revisions/${encodeURIComponent(activePreview.revision_id)}/review`, {
      method: "POST",
      idempotencyKey: randomKey("wiki_review"),
      body: {
        business_date: activePreview.business_date,
        content_digest: activePreview.content_digest,
        input_digest: activePreview.input_digest,
        review_material_id: activePreview.review_material_id,
        decision,
        reason_code: reasonCode,
        basis_id: randomUuid(),
      },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      ui["review-status"].textContent = payload.error?.message ?? `审核提交失败（HTTP ${response.status}）。`;
      return;
    }
    activePreview.review_id = payload.review_id;
    ui["publish-btn"].hidden = decision !== "approved";
    ui["review-status"].textContent = `已记录审核决定：${payload.decision}（${payload.review_id}）`;
    await loadWorkflow();
  } catch {
    ui["review-status"].textContent = "审核提交失败，请重试。";
  }
}

async function publishRevision(revisionId, reviewId, businessDate) {
  ui["publish-diagnosis"].replaceChildren();
  ui["review-status"].textContent = "正在执行发布前实时依赖与授权终检…";
  try {
    const response = await apiRequest(`/internal/wiki/revisions/${encodeURIComponent(revisionId)}/publish`, {
      method: "POST",
      idempotencyKey: randomKey("wiki_pub"),
      body: { business_date: businessDate, review_id: reviewId },
    });
    const payload = await response.json().catch(() => ({}));
    if (response.ok) {
      ui["review-status"].textContent = `已发布主题修订（${payload.publication_id}）`;
      await load(session?.after ?? null);
      return;
    }
    if (response.status === 409 && payload.error?.code === "wiki_input_changed") {
      const notes = [];
      if (payload.topic_generation_changed) {
        notes.push(element("li", `主题发布代次已由 ${payload.expected_generation} 变更为 ${payload.current_generation}，需重新审核。`));
      }
      for (const item of payload.changed_passages ?? []) {
        const labels = item.reasons.map(r => reasons[r] ?? r).join("、");
        notes.push(element("li", `依据 ${item.passage_id}:r${item.excerpt_revision} 已变化（${labels}），需重审或干净重编。`));
      }
      ui["publish-diagnosis"].replaceChildren(...notes);
      ui["review-status"].textContent = payload.error.message;
      return;
    }
    ui["review-status"].textContent = payload.error?.message ?? `发布失败（HTTP ${response.status}）。`;
  } catch {
    ui["review-status"].textContent = "发布请求失败，请重试。";
  }
}

async function loadWorkflow(signal) {
  const response = await apiRequest("/internal/wiki/revisions", { signal });
  if (!response.ok) return response.status;
  const payload = await response.json();
  ui["queue-section"].hidden = false;
  ui["revisions"].replaceChildren(...payload.revisions.map(revisionRow));
  ui["queue-status"].textContent = payload.revisions.length
    ? `当前可见 ${payload.revisions.length} 条修订记录`
    : "当前没有待办修订记录。";
  if (payload.role === "owner") {
    ui["author-section"].hidden = false;
    ui["rebuilds-section"].hidden = payload.pending_rebuilds.length === 0;
    ui["rebuilds"].replaceChildren(...payload.pending_rebuilds.map(rebuildRow));
    ui["rebuilds-status"].textContent = payload.pending_rebuilds.length
      ? `${payload.pending_rebuilds.length} 个停用主题等待干净重编`
      : "";
  } else {
    ui["author-section"].hidden = true;
    ui["rebuilds-section"].hidden = true;
  }
  return 200;
}

function populateRollbackRevisions(wikiId) {
  ui["rollback-revision"].replaceChildren();
  const topic = releaseOverview?.wiki_topics?.find(item => item.wiki_id === wikiId);
  if (!topic || !topic.publications.length) {
    const empty = element("option", "暂无可回退修订");
    empty.value = "";
    ui["rollback-revision"].append(empty);
    return;
  }
  for (const pub of topic.publications) {
    const opt = element(
      "option",
      `代次 ${pub.generation} · ${pub.revision_id.slice(0, 8)}${pub.rollback_eligible ? "" : `（已阻断：${pub.stop_reasons.join("/")}）`}`,
    );
    opt.value = pub.revision_id;
    ui["rollback-revision"].append(opt);
  }
}

async function loadReleaseControl(signal) {
  const response = await apiRequest("/internal/release/spaces", { signal });
  if (!response.ok) {
    ui["release-section"].hidden = true;
    return response.status;
  }
  const payload = await response.json();
  releaseOverview = payload;
  ui["release-section"].hidden = false;
  const cur = payload.current;
  ui["release-summary"].textContent =
    `当前发布代次 ${cur.generation} · Wiki 交付：${cur.wiki_delivery_enabled ? "启用" : "已关闭（纯 RAG）"} · 词项模式：${cur.lexical_index_mode}`;
  ui["release-wiki-enabled"].value = cur.wiki_delivery_enabled ? "true" : "false";
  ui["release-lexical-mode"].value = cur.lexical_index_mode;
  ui["release-target"].replaceChildren();
  const noneOpt = element("option", "选择历史发布代次");
  noneOpt.value = "";
  ui["release-target"].append(noneOpt);
  for (const item of payload.releases) {
    const opt = element(
      "option",
      `代次 ${item.generation} · ${item.action} · Wiki:${item.wiki_delivery_enabled ? "开" : "关"} · ${item.lexical_index_mode}`,
    );
    opt.value = item.release_id;
    ui["release-target"].append(opt);
  }
  ui["rollback-topic"].replaceChildren();
  if (!payload.wiki_topics.length) {
    const empty = element("option", "暂无已发布主题");
    empty.value = "";
    ui["rollback-topic"].append(empty);
    populateRollbackRevisions("");
  } else {
    for (const topic of payload.wiki_topics) {
      const opt = element(
        "option",
        `${topic.wiki_id.slice(0, 8)} · 当前生效代次 ${topic.effective_generation}${topic.rolled_back ? "（已回退）" : ""}`,
      );
      opt.value = topic.wiki_id;
      ui["rollback-topic"].append(opt);
    }
    populateRollbackRevisions(payload.wiki_topics[0].wiki_id);
  }
  ui["release-history"].replaceChildren(...payload.releases.map(item => {
    const li = element("li", undefined, "wiki-topic");
    const h = element("div", undefined, "wiki-topic-header");
    const code = element("h3");
    code.append(element("code", `代次 ${item.generation} · ${item.action}`));
    h.append(code, element("span", item.wiki_delivery_enabled ? "Wiki 开启" : "纯 RAG 回退", "wiki-state"));
    li.append(
      h,
      element("p", `词项模式：${item.lexical_index_mode} · 原因码：${item.reason_code} · 触发说明：${item.rollback_trigger_summary}`, "repair-meta"),
    );
    return li;
  }));
  return 200;
}

async function load(after = null) {
  const owner = session;
  if (owner === null) return;
  owner.pending?.abort();
  const controller = new AbortController();
  owner.pending = controller;
  const current = () => session === owner && owner.pending === controller && !controller.signal.aborted;
  ui.topics.replaceChildren();
  ui.topics.setAttribute("aria-busy", "true");
  ui.status.textContent = "正在读取当前台账…";
  ui.next.hidden = true;
  try {
    const cursor = after === null ? "" : `?after=${encodeURIComponent(after)}`;
    const response = await fetch(`/internal/wiki/status${cursor}`, {
      headers: { Authorization: `Bearer ${owner.token}` }, signal: controller.signal, cache: "no-store",
      credentials: "omit", mode: "same-origin", redirect: "error", referrerPolicy: "no-referrer",
    });
    if (!current()) return;
    if (response.status === 401) return lock("凭据无效或已过期，请重新载入。", true);
    if (response.status === 403) {
      const wfStatus = await loadWorkflow(controller.signal);
      if (!current()) return;
      if (wfStatus === 200) {
        ui["ledger-section"].hidden = true;
        return;
      }
      if (wfStatus === 401) return lock("凭据无效或已过期，请重新载入。", true);
      const relStatus = await loadReleaseControl(controller.signal);
      if (!current()) return;
      if (relStatus === 200) {
        ui["ledger-section"].hidden = true;
        return;
      }
      if (relStatus === 401) return lock("凭据无效或已过期，请重新载入。", true);
      return lock("当前凭据没有此空间的管理权限。", true);
    }
    if (!response.ok) throw new Error("Management status is unavailable");
    const payload = await response.json();
    if (!current()) return;
    ui["ledger-section"].hidden = false;
    ui.topics.replaceChildren(...payload.topics.map(topicRow));
    ui.status.textContent = payload.topics.length ? `本页 ${payload.topics.length} 个主题` : "当前页没有主题。";
    owner.after = after;
    owner.next = payload.next_cursor;
    ui.next.hidden = owner.next === null;
    await loadWorkflow(controller.signal);
    if (!current()) return;
    await loadReleaseControl(controller.signal);
  } catch {
    if (current()) lock(unavailable, true);
  } finally {
    if (current()) {
      ui.topics.setAttribute("aria-busy", "false");
      owner.pending = null;
    }
  }
}

ui["clear-rebuild"].addEventListener("click", () => {
  ui["rebuild-event"].value = "";
  ui["inputs-status"].textContent = "";
});

ui["editor-mode"].addEventListener("click", () => {
  if (ui["structured-editor"].hidden) enterStructuredEditor();
  else showMarkdownSource();
});
ui["add-block"].addEventListener("click", () => openBlockEditor());
ui["apply-block"].addEventListener("click", applyBlockEditor);
ui["cancel-block"].addEventListener("click", () => {
  const focus = editingBlock?.focusReturn;
  closeBlockEditor();
  focus?.focus();
});
ui["preview-source-toggle"].addEventListener("click", () => {
  const hidden = ui["preview-source"].hidden;
  ui["preview-source"].hidden = !hidden;
  ui["preview-source-toggle"].setAttribute("aria-expanded", String(hidden));
  ui["preview-source-toggle"].textContent = hidden ? "隐藏 Markdown 源码" : "查看 Markdown 源码";
});

ui["inputs-form"].addEventListener("submit", async event => {
  event.preventDefault();
  ui["inputs-status"].textContent = "正在按实时权限封存输入清单…";
  try {
    const direct = parsePairs(ui["direct-inputs"].value);
    const parents = ui["parent-manifests"].value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const rebuild = ui["rebuild-event"].value.trim();
    const body = { business_date: ui["business-date"].value, direct };
    if (parents.length) body.parents = parents;
    if (rebuild) body.rebuild_event_id = rebuild;
    const response = await apiRequest("/internal/wiki/inputs", { method: "POST", body });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      ui["inputs-status"].textContent = payload.error?.message ?? `输入组装失败（HTTP ${response.status}）。`;
      return;
    }
    ui["manifest-id"].value = payload.manifest_id;
    ui["inputs-status"].textContent = `已封存输入清单 ${payload.manifest_id}（共 ${payload.excerpts.length} 条输入）。`;
  } catch {
    ui["inputs-status"].textContent = "请检查直接依据格式（passage_id:revision）。";
  }
});

ui["candidate-form"].addEventListener("submit", async event => {
  event.preventDefault();
  if (editingBlock) {
    ui["block-editor-status"].textContent = "请先应用或取消当前内容块。";
    return;
  }
  if (!ui["draft-markdown"].value.trim()) {
    ui["candidate-status"].textContent = "请填写正文后再提交。";
    return;
  }
  ui["candidate-status"].textContent = "正在提交候选草稿…";
  try {
    const citations = parsePairs(ui["citations"].value);
    const statementLines = ui["statements"].value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const body = {
      business_date: ui["business-date"].value,
      topic_key: ui["topic-key"].value.trim(),
      title: ui["draft-title"].value.trim(),
      markdown: ui["draft-markdown"].value,
      manifest_id: ui["manifest-id"].value.trim(),
      reviewer_ref: ui["reviewer-ref"].value.trim(),
      basis_id: randomUuid(),
      citations,
    };
    if (statementLines.length) {
      body.statements = statementLines.map(text => ({ text, support_groups: [citations] }));
    }
    const response = await apiRequest("/internal/wiki/revisions", {
      method: "POST",
      idempotencyKey: randomKey("wiki_draft"),
      body,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      ui["candidate-status"].textContent = payload.error?.message ?? `草稿提交失败（HTTP ${response.status}）。`;
      return;
    }
    ui["candidate-status"].textContent = `已提交候选修订 ${payload.revision_id}，等待独立审核人审核。`;
    await load(session?.after ?? null);
  } catch {
    ui["candidate-status"].textContent = "请检查引用格式与必填字段。";
  }
});

ui["ai-generate-btn"].addEventListener("click", async () => {
  const owner = session;
  const manifestId = ui["manifest-id"].value.trim();
  const topicKey = ui["topic-key"].value.trim();
  const reviewerRef = ui["reviewer-ref"].value.trim();
  const businessDate = ui["business-date"].value;
  if (!manifestId || !topicKey || !reviewerRef || !businessDate) {
    ui["candidate-status"].textContent = "请先填写业务日期、已封存输入清单、主题键和独立审核人标识。";
    return;
  }
  const budget = Number.parseInt(ui["ai-budget"].value, 10) || 100000;
  ui["candidate-status"].textContent = "正在经获准模型网关与外发授权校验生成待审草稿…";
  try {
    const response = await apiRequest("/internal/wiki/revisions/generate", {
      method: "POST",
      idempotencyKey: randomKey("wiki_ai_draft"),
      body: {
        business_date: businessDate,
        topic_key: topicKey,
        manifest_id: manifestId,
        reviewer_ref: reviewerRef,
        basis_id: randomUuid(),
        title_hint: ui["draft-title"].value.trim(),
        instructions: ui["ai-instructions"].value.trim(),
        max_microunits: budget,
      },
    });
    const payload = await response.json().catch(() => ({}));
    if (session !== owner) return;
    if (!response.ok) {
      ui["candidate-status"].textContent = payload.error?.message ?? `AI 生成草稿失败（HTTP ${response.status}）。`;
      return;
    }
    if (payload.title) ui["draft-title"].value = payload.title;
    if (payload.markdown) {
      closeBlockEditor();
      ui["draft-markdown"].value = payload.markdown;
      if (!ui["structured-editor"].hidden) renderDraftBlocks();
    }
    if (Array.isArray(payload.citations)) {
      ui["citations"].value = payload.citations.map(([ref, rev]) => `${ref}:${rev}`).join("\n");
    }
    ui["candidate-status"].textContent = `AI 已生成待审修订 ${payload.revision_id}（调用回执 ${payload.provider_call_id}），等待独立审核人审核后发布。`;
    await load(session?.after ?? null);
  } catch {
    if (session !== owner) return;
    ui["candidate-status"].textContent = "AI 草稿生成请求失败，请检查模型网关与授权配置。";
  }
});

ui["approve-btn"].addEventListener("click", () => submitDecision("approved"));
ui["reject-btn"].addEventListener("click", () => submitDecision("rejected"));
ui["publish-btn"].addEventListener("click", () => {
  if (activePreview?.review_id) {
    publishRevision(activePreview.revision_id, activePreview.review_id, activePreview.business_date);
  }
});

ui["rollback-topic"].addEventListener("change", () => {
  populateRollbackRevisions(ui["rollback-topic"].value);
});

ui["release-switch-form"].addEventListener("submit", async event => {
  event.preventDefault();
  ui["release-switch-status"].textContent = "正在写入空间发布配置…";
  try {
    const action = ui["release-action"].value;
    const body = {
      action,
      rollback_trigger_summary: ui["release-trigger"].value.trim(),
      reason_code: ui["release-reason"].value.trim(),
      basis_ref: randomUuid(),
    };
    if (action === "rollback") {
      const target = ui["release-target"].value;
      if (!target) {
        ui["release-switch-status"].textContent = "请先选择历史发布代次作为回退目标。";
        return;
      }
      body.target_release_id = target;
    } else if (action === "disable_wiki") {
      body.wiki_delivery_enabled = false;
      body.lexical_index_mode = ui["release-lexical-mode"].value;
    } else {
      body.wiki_delivery_enabled = ui["release-wiki-enabled"].value === "true";
      body.lexical_index_mode = ui["release-lexical-mode"].value;
    }
    const response = await apiRequest("/internal/release/spaces/switch", {
      method: "POST",
      idempotencyKey: randomKey("space_release"),
      body,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      ui["release-switch-status"].textContent = payload.error?.message ?? `空间发布切换失败（HTTP ${response.status}）。`;
      return;
    }
    ui["release-switch-status"].textContent = `已切换至发布代次 ${payload.generation}（${payload.action}）。`;
    await load(session?.after ?? null);
  } catch {
    ui["release-switch-status"].textContent = "空间发布切换请求失败，请检查参数。";
  }
});

ui["topic-rollback-form"].addEventListener("submit", async event => {
  event.preventDefault();
  const wikiId = ui["rollback-topic"].value;
  const targetRev = ui["rollback-revision"].value;
  if (!wikiId || !targetRev) {
    ui["topic-rollback-status"].textContent = "请先选择主题与目标历史修订。";
    return;
  }
  ui["topic-rollback-status"].textContent = "正在按实时权限与现行撤权/删除记录核验回退目标…";
  try {
    const response = await apiRequest(`/internal/release/wiki/${encodeURIComponent(wikiId)}/rollback`, {
      method: "POST",
      idempotencyKey: randomKey("wiki_rollback"),
      body: {
        target_revision_id: targetRev,
        business_date: ui["rollback-date"].value,
        reason_code: ui["rollback-reason"].value.trim(),
        basis_ref: randomUuid(),
      },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const extra = Array.isArray(payload.stop_reasons) && payload.stop_reasons.length
        ? `（阻断原因：${payload.stop_reasons.join("、")}；建议关闭本空间 Wiki 交付退回纯 RAG）`
        : "";
      ui["topic-rollback-status"].textContent = (payload.error?.message ?? `主题回退失败（HTTP ${response.status}）。`) + extra;
      return;
    }
    ui["topic-rollback-status"].textContent = `已完成安全回退（${payload.rollback_id}），当前生效修订 ${payload.target_revision_id}。`;
    await load(session?.after ?? null);
  } catch {
    ui["topic-rollback-status"].textContent = "单主题回退请求失败，请重试。";
  }
});

ui["access-form"].addEventListener("submit", event => {
  event.preventDefault();
  const token = ui.token.value.trim();
  lock();
  if (!/^[A-Za-z0-9_.-]{32,16384}$/.test(token)) return lock("请输入完整的本机管理测试凭据。", true);
  session = { token, after: null, next: null, pending: null };
  ui.lock.hidden = true;
  ui.workspace.hidden = false;
  ui["register-title"].focus();
  load();
});

ui.refresh.addEventListener("click", () => load(session?.after ?? null));
ui.next.addEventListener("click", () => {
  if (session?.next) load(session.next);
});
ui.logout.addEventListener("click", () => lock("已退出，凭据与台账已清除。", true));
window.addEventListener("pagehide", () => lock());
window.addEventListener("pageshow", event => {
  if (event.persisted) lock("页面已重新锁定，请载入凭据。");
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) lock("页面已锁定，请重新载入凭据。");
});
lock();

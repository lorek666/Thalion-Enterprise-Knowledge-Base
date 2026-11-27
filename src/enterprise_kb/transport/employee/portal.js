const elements = Object.fromEntries([
  "locked-panel", "workspace", "session-actions", "access-form", "access-token", "access-message",
  "oidc-sso-box", "oidc-login-button",
  "switch-employee", "logout", "search-form", "query", "business-day", "passage-count", "source-ref", "include-wiki",
  "load-source-options", "source-options-panel", "source-options", "source-options-status",
  "department-code", "load-department-options", "department-options-panel", "department-options", "department-options-status",
  "load-search-suggestions", "search-suggestion-status", "search-suggestion-list",
  "source-facets", "source-facet-list", "department-facets", "department-facet-list",
  "result-status", "result-day", "result-request", "results", "wiki-results", "wiki-result-list",
  "reference-form", "reference-id", "direct-reference", "reference-status", "reference-content",
  "report-gap", "feedback-form", "feedback-context", "feedback-note", "submit-feedback",
  "feedback-lookup", "feedback-id", "feedback-status", "feedback-conclusion", "feedback-notices",
  "feedback-notice-status", "feedback-notice-list", "feedback-notice-next",
].map(id => [id, document.getElementById(id)]));

const credentialFormat = /^[A-Za-z0-9_.-]{32,16384}$/;
const departmentCodeFormat = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const referenceFormat = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const initialResults = "输入关键词开始查找。";
const initialReference = "选择一条依据，查看获准摘录和对应位置。";
const retryMessage = "暂时无法取证，未保留上次结果。请稍后重试。";
const feedbackStates = new Map([
  ["pending", "待核对"], ["awaiting_retest", "已修正待复测"], ["explained", "已有依据，已解释"], ["closed", "复核通过，已关闭"],
]);
const feedbackConclusions = new Map([
  ["basis_reviewed", "办理人已核对原依据，并记录了解释决定。"],
  ["source_text_confirmed", "办理人已核对所反馈的原文表述，未认定需要修订。"],
  ["applicability_confirmed", "办理人已核对所反馈条款的适用条件，未认定需要修订。"],
  ["correction_recorded", "已登记修正，请按原条件重新取证。"],
  ["correction_verified", "负责人已确认复测通过。"],
]);
const feedbackNoticeLabels = new Map([
  ["awaiting_retest", "已登记修正，等待你复测。"],
  ["explained", "办理人已记录解释。"],
  ["closed", "负责人已复核并关闭工单。"],
]);

let session = null;
let pendingSharedReference = null;

function textElement(tag, text, className) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  return element;
}

function cancel(kind) {
  if (session === null) return;
  session[kind]?.controller.abort();
  session[kind] = null;
}

function start(kind) {
  if (session === null) return null;
  cancel(kind);
  const task = { owner: session, kind, controller: new AbortController() };
  session[kind] = task;
  return task;
}

function isCurrent(task) {
  return session === task.owner && session[task.kind] === task && !task.controller.signal.aborted;
}

function clearResults(message = initialResults) {
  elements.results.replaceChildren();
  elements["report-gap"].hidden = true;
  if (session !== null) session.originSearch = null;
  clearWiki();
  elements["source-facet-list"].replaceChildren();
  elements["source-facets"].hidden = true;
  elements["department-facet-list"].replaceChildren();
  elements["department-facets"].hidden = true;
  elements.results.setAttribute("aria-busy", "false");
  elements["result-day"].textContent = "";
  elements["result-day"].hidden = true;
  elements["result-request"].querySelector("code").textContent = "";
  elements["result-request"].hidden = true;
  elements["result-status"].textContent = message;
}

function clearWiki() {
  elements["wiki-result-list"].replaceChildren();
  elements["wiki-results"].hidden = true;
}

function clearSourceOptions() {
  cancel("sourceOptions");
  elements["source-options"].replaceChildren();
  elements["source-options-panel"].hidden = true;
  elements["source-options-status"].textContent = "";
}

function clearDepartmentOptions() {
  cancel("departmentOptions");
  elements["department-options"].replaceChildren();
  elements["department-options-panel"].hidden = true;
  elements["department-options-status"].textContent = "";
}

function clearSearchSuggestions() {
  cancel("suggestions");
  elements["search-suggestion-list"].replaceChildren();
  elements["search-suggestion-list"].hidden = true;
  elements["search-suggestion-status"].textContent = "";
}

function clearReference(message = initialReference) {
  cancel("download");
  elements["reference-content"].replaceChildren();
  elements["reference-content"].setAttribute("aria-busy", "false");
  elements["reference-status"].textContent = message;
  elements.results.querySelector('[aria-pressed="true"]')?.setAttribute("aria-pressed", "false");
  elements["wiki-result-list"].querySelector('[aria-pressed="true"]')?.setAttribute("aria-pressed", "false");
}

function clearFeedbackDraft() {
  if (session !== null) session.draft = null;
  elements["feedback-form"].hidden = true;
  elements["feedback-context"].textContent = "";
  elements["feedback-note"].value = "";
  elements["submit-feedback"].disabled = false;
}

function clearFeedbackConclusion() {
  elements["feedback-conclusion"].textContent = "";
  elements["feedback-conclusion"].hidden = true;
}

function clearFeedbackNotices() {
  if (session !== null) session.nextNotice = null;
  elements["feedback-notice-list"].replaceChildren();
  elements["feedback-notice-list"].setAttribute("aria-busy", "false");
  elements["feedback-notice-status"].textContent = "";
  elements["feedback-notice-next"].hidden = true;
}

function accessMessage(message) {
  elements["access-message"].textContent = message;
  elements["access-message"].hidden = !message;
}

function lock(message = "", focus = false) {
  cancel("search");
  cancel("reference");
  cancel("download");
  cancel("feedback");
  cancel("notices");
  clearSourceOptions();
  clearDepartmentOptions();
  clearSearchSuggestions();
  clearFeedbackDraft();
  if (session !== null) session.token = "";
  session = null;
  pendingSharedReference = null;
  elements["access-token"].value = "";
  elements.query.value = "";
  elements["business-day"].value = "";
  elements["passage-count"].value = elements["passage-count"].defaultValue;
  elements["source-ref"].value = "";
  elements["department-code"].value = "";
  elements["include-wiki"].checked = false;
  elements["reference-id"].value = "";
  elements["direct-reference"].open = false;
  elements["feedback-id"].value = "";
  elements["feedback-status"].textContent = "";
  clearFeedbackConclusion();
  clearFeedbackNotices();
  clearResults();
  clearReference();
  elements.workspace.hidden = true;
  elements["session-actions"].hidden = true;
  elements["locked-panel"].hidden = false;
  accessMessage(message);
  if (focus) elements["access-token"].focus();
}

function loadSharedReference() {
  if (!location.hash.startsWith("#ref=")) return;
  const ref = location.hash.slice("#ref=".length);
  history.replaceState(null, "", location.pathname + location.search);
  const valid = referenceFormat.test(ref);
  lock(valid ? "载入凭据后核验共享引用。" : "该共享引用链接无效。", true);
  if (valid) pendingSharedReference = ref.toLowerCase();
}

async function authorizedFetch(task, path, data, key) {
  const headers = { Authorization: `Bearer ${task.owner.token}` };
  if (data !== undefined) headers["Content-Type"] = "application/json";
  if (key !== undefined) headers["Idempotency-Key"] = key;
  const response = await fetch(path, {
    method: data === undefined ? "GET" : "POST",
    headers,
    body: data === undefined ? undefined : JSON.stringify(data),
    signal: task.controller.signal,
    cache: "no-store",
    credentials: "omit",
    mode: "same-origin",
    redirect: "error",
    referrerPolicy: "no-referrer",
  });
  if (!isCurrent(task)) return null;
  if (response.status === 401) {
    lock("凭据无效或已过期，请重新载入。", true);
    return null;
  }
  return response;
}

async function request(task, path, data, key) {
  const response = await authorizedFetch(task, path, data, key);
  if (response === null) return null;
  const body = await response.json();
  return isCurrent(task) ? { status: response.status, body } : null;
}

function errorMessage(status, body, isReference = false) {
  if (isReference && status === 404) return "该引用不可用。请重新查找依据。";
  if (status === 403) return "当前凭据不允许此操作。";
  if (status === 400 && body.error?.code === "invalid_arguments") return "请检查关键词、日期或引用编号后重试。";
  return retryMessage;
}

function locationText(location) {
  if (Number.isInteger(location.page) && location.page > 0) return `第 ${location.page} 页（PDF 转录）`;
  if (typeof location.locator === "string" && Array.isArray(location.heading_path)) {
    return [...location.heading_path, location.locator].join(" / ");
  }
  if (Array.isArray(location.heading_path) && Number.isInteger(location.paragraph)) {
    return [...location.heading_path, `第 ${location.paragraph} 段`].join(" / ");
  }
  const column = location.columns?.[0];
  if (Number.isInteger(location.row_id) && Number.isInteger(column?.column) && typeof column.header === "string") {
    if (Array.isArray(location.heading_path) && Number.isInteger(location.table)) {
      const row = [...location.heading_path, `第 ${location.table} 表`, `第 ${location.row_id} 行`].join(" / ");
      return location.columns.length === 1 ? `${row} / 第 ${column.column} 列（${column.header}）`
        : `${row} · ${location.columns.length} 个单元格`;
    }
    return `第 ${location.row_id} 行 / 第 ${column.column} 列（${column.header}）`;
  }
  return "无可显示的定位信息";
}

function detectMineralBadge(location) {
  if (Number.isInteger(location?.page) && location.page > 0) {
    return { label: "PDF", cls: "mineral-icon mi-slate" };
  }
  if (Number.isInteger(location?.row_id) || Number.isInteger(location?.table)) {
    return { label: "表格", cls: "mineral-icon mi-ink" };
  }
  return { label: "制度", cls: "mineral-icon mi-gold" };
}

function openFeedback(origin, passage) {
  if (session === null || !referenceFormat.test(origin)) return;
  cancel("feedback");
  clearFeedbackDraft();
  session.draft = { origin, passageId: passage?.passage_id, note: null, key: null };
  elements["feedback-context"].textContent = passage ? `报错对应的规定：${passage.title}` : "反馈：没有搜到要找的规定";
  elements["feedback-status"].textContent = "";
  elements["feedback-form"].hidden = false;
  elements["feedback-note"].focus();
}

async function copyReferenceLink(button, ref) {
  const owner = session;
  if (owner === null || !referenceFormat.test(ref)) return;
  const link = new URL("/", location.origin);
  link.hash = `ref=${ref}`;
  let message;
  try {
    await navigator.clipboard.writeText(link.href);
    message = "已复制引用链接。";
  } catch {
    message = "未能复制链接，可转发引用编号。";
  }
  if (session === owner && button.isConnected) elements["reference-status"].textContent = message;
}

async function downloadOriginal(button, version) {
  if (!referenceFormat.test(version)) return;
  const task = start("download");
  if (task === null) return;
  button.disabled = true;
  const status = elements["reference-status"];
  status.textContent = "正在核验整件权限…";
  try {
    const response = await authorizedFetch(task, `/employee/originals/${encodeURIComponent(version)}`);
    if (response === null || !isCurrent(task) || !button.isConnected) return;
    if (response.status === 404 || response.status === 403) {
      status.textContent = "当前凭据不能下载该版本原件。";
      return;
    }
    const filename = /^attachment; filename="(original\.(?:md|csv|pdf|docx|xlsx|pptx|html|png|jpg))"$/.exec(
      response.headers.get("Content-Disposition"),
    )?.[1];
    if (response.status !== 200 || !filename || response.headers.get("Content-Type") !== "application/octet-stream") {
      throw new Error("Invalid original download response");
    }
    const length = Number(response.headers.get("Content-Length"));
    if (!Number.isSafeInteger(length) || length < 1 || length > 16 * 1024 * 1024) {
      throw new Error("Invalid original download length");
    }
    const blob = await response.blob();
    if (!isCurrent(task) || !button.isConnected || document.hidden) return;
    if (blob.size !== length) throw new Error("Incomplete original download");
    const url = URL.createObjectURL(blob);
    try {
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      link.click();
      status.textContent = "已发起原件下载。";
    } finally {
      setTimeout(() => URL.revokeObjectURL(url), 0);
    }
  } catch {
    if (isCurrent(task) && button.isConnected) status.textContent = "暂时无法下载原件，请稍后重试。";
  } finally {
    if (isCurrent(task)) {
      button.disabled = false;
      session.download = null;
    }
  }
}

function passageView(passage, origin, original = false) {
  const container = document.createElement(original ? "article" : "li");
  container.className = original ? "passage original" : "passage";
  const actions = document.createElement("div");
  actions.className = "feedback-actions";

  if (original) {
    const metaStrip = document.createElement("div");
    metaStrip.className = "doc-meta-strip";
    metaStrip.append(
      textElement("p", `当前版本：${passage.version_label}（第 ${passage.excerpt_revision} 次核对）`, "meta"),
      textElement("p", `有效时间：${passage.valid_from} 起${passage.valid_until ? `，${passage.valid_until} 起停用` : "长期有效"}`, "meta"),
    );
    if (passage.data_as_of) {
      metaStrip.append(textElement("p", `数据更新至：${passage.data_as_of}`, "meta"));
    }

    const ribbon = document.createElement("div");
    ribbon.className = "anchor-ribbon";
    ribbon.append(
      textElement("span", "所在位置", "anchor-tag"),
      textElement("p", locationText(passage.location), "meta"),
    );

    const tip = textElement(
      "p",
      "贴心提示：想发给同事可点下方“复制这条规定的链接”（对方打开时也会自动核对查看权限）；想看整份文件可点下载。",
      "integrity-tip",
    );

    const codes = document.createElement("div");
    codes.className = "tech-codes-strip";
    codes.append(
      textElement("p", "规定编号", "meta"),
      textElement("code", passage.passage_id),
      textElement("p", "本次核对流水号", "meta"),
      textElement("code", origin),
    );

    const copy = textElement("button", "复制这条规定的链接", "primary-button btn-ink");
    copy.type = "button";
    copy.setAttribute("aria-label", "复制引用链接");
    copy.addEventListener("click", () => copyReferenceLink(copy, passage.passage_id));
    actions.append(copy);

    if (referenceFormat.test(passage.version_id)) {
      const download = textElement("button", "下载整份文件", "quiet-button");
      download.type = "button";
      download.setAttribute("aria-label", "下载完整原件");
      download.addEventListener("click", () => downloadOriginal(download, passage.version_id));
      actions.append(download);
    }

    const report = textElement("button", "内容有误？点我反馈", "quiet-button btn-gold-soft");
    report.type = "button";
    report.setAttribute("aria-label", "反馈此引用");
    report.addEventListener("click", () => openFeedback(origin, passage));
    actions.append(report);

    container.append(
      textElement("h3", passage.title),
      metaStrip,
      ribbon,
      textElement("p", passage.excerpt, "excerpt"),
      tip,
      codes,
      actions,
    );
    return container;
  }

  const badgeInfo = detectMineralBadge(passage.location);
  const badge = textElement("span", badgeInfo.label, badgeInfo.cls);
  badge.setAttribute("aria-hidden", "true");

  const bodyCol = document.createElement("div");
  const titleLine = document.createElement("div");
  titleLine.className = "hit-title-line";
  titleLine.append(
    textElement("h3", passage.title),
    textElement("span", `正在执行 · ${passage.version_label}`, "version"),
  );

  const open = textElement("button", "看右边原文", "read-button");
  open.type = "button";
  open.setAttribute("aria-label", `核对原文：${passage.title}`);
  open.setAttribute("aria-pressed", "false");
  open.addEventListener("click", () => readReference(passage.passage_id, open));
  actions.append(open);

  const report = textElement("button", "内容有误？反馈", "read-button");
  report.type = "button";
  report.setAttribute("aria-label", "反馈此引用");
  report.addEventListener("click", () => openFeedback(origin, passage));
  actions.append(report);

  bodyCol.append(
    titleLine,
    textElement("p", locationText(passage.location), "meta"),
    textElement("p", passage.excerpt, "excerpt"),
    textElement("p", `自 ${passage.valid_from} 起生效${passage.valid_until ? `（至 ${passage.valid_until}）` : ""}`, "meta"),
  );
  if (passage.data_as_of) bodyCol.append(textElement("p", `数据更新至 ${passage.data_as_of}`, "meta"));
  bodyCol.append(actions);

  const cardGrid = document.createElement("div");
  cardGrid.className = "hit-card-grid";
  cardGrid.append(badge, bodyCol);
  container.append(cardGrid);
  return container;
}

function wikiView(page) {
  const article = document.createElement("article");
  const claims = document.createElement("ol");
  claims.className = "wiki-claims";
  for (const claim of page.claims) {
    const item = document.createElement("li");
    const links = document.createElement("div");
    links.className = "claim-links";
    for (const [index, passageId] of claim.passage_ids.entries()) {
      const button = textElement("button", `看原文 ${index + 1}`, "read-button");
      button.type = "button";
      button.setAttribute("aria-label", `核对依据 ${index + 1}`);
      button.setAttribute("aria-pressed", "false");
      button.addEventListener("click", () => readReference(passageId, button));
      links.append(button);
    }
    item.append(textElement("p", claim.text), links);
    claims.append(item);
  }
  article.append(textElement("h4", page.title), claims);
  return article;
}

function showResultStatus(originalCount, topicCount) {
  const headline = originalCount ? `${originalCount} 条可核对依据`
    : elements["source-facets"].hidden ? "没有找到原文检索结果" : "有匹配资料，当前条数上限不足以显示完整证据";
  elements["result-status"].textContent = topicCount ? `${headline}，附 ${topicCount} 篇已审核 Wiki。`
    : originalCount || !elements["source-facets"].hidden ? headline : "没有找到可用依据。可换个关键词或检查业务日期。";
}

function showSourceFacets(facets) {
  if (!Array.isArray(facets) || facets.some(entry =>
    !referenceFormat.test(entry.source_id) || typeof entry.example_title !== "string"
    || !Number.isSafeInteger(entry.document_count) || entry.document_count < 1
  )) throw new Error("Invalid source facets");
  elements["source-facet-list"].replaceChildren(...facets.map(entry => {
    const row = document.createElement("li");
    row.append(textElement("span", `${entry.example_title} · ${entry.source_id.slice(0, 8)}`),
      textElement("strong", `${entry.document_count} 份`));
    return row;
  }));
  elements["source-facets"].hidden = facets.length === 0;
}

function showDepartmentFacets(facets) {
  if (!Array.isArray(facets)) {
    elements["department-facet-list"].replaceChildren();
    elements["department-facets"].hidden = true;
    return;
  }
  if (facets.some(entry =>
    typeof entry.department_code !== "string" || typeof entry.department_name !== "string"
    || !Number.isSafeInteger(entry.document_count) || entry.document_count < 1
  )) throw new Error("Invalid department facets");
  elements["department-facet-list"].replaceChildren(...facets.map(entry => {
    const row = document.createElement("li");
    row.append(textElement("span", `${entry.department_name} · ${entry.department_code}`),
      textElement("strong", `${entry.document_count} 份`));
    return row;
  }));
  elements["department-facets"].hidden = facets.length === 0;
}

async function loadDepartmentOptions() {
  clearDepartmentOptions();
  const task = start("departmentOptions");
  if (task === null) return;
  const day = elements["business-day"].value;
  const query = day ? `?${new URLSearchParams({business_date: day})}` : "";
  const status = elements["department-options-status"];
  status.textContent = "正在核验可筛选部门…";
  try {
    const response = await request(task, `/employee/department-options${query}`);
    if (response === null || !isCurrent(task) || elements["business-day"].value !== day) return;
    if (response.status !== 200) {
      status.textContent = errorMessage(response.status, response.body);
      return;
    }
    const depts = response.body.departments;
    if (!Array.isArray(depts) || depts.some(entry =>
      typeof entry.department_code !== "string" || typeof entry.department_name !== "string"
      || !Number.isSafeInteger(entry.document_count) || entry.document_count < 1
    )) throw new Error("Invalid department options");
    if (!depts.length) {
      status.textContent = "该业务日期没有可筛选的部门。";
      return;
    }
    const choice = elements["department-options"];
    choice.replaceChildren(new Option("不限部门", ""), ...depts.map(entry =>
      new Option(`${entry.department_name}（${entry.document_count} 份）`, entry.department_code)
    ));
    choice.value = elements["department-code"].value.trim().toLowerCase();
    elements["department-options-panel"].hidden = false;
    status.textContent = "";
  } catch {
    if (isCurrent(task)) status.textContent = "暂时无法核验可筛选部门。";
  } finally {
    if (isCurrent(task)) session.departmentOptions = null;
  }
}

async function loadSourceOptions() {
  clearSourceOptions();
  const task = start("sourceOptions");
  if (task === null) return;
  const day = elements["business-day"].value;
  const query = day ? `?${new URLSearchParams({business_date: day})}` : "";
  const status = elements["source-options-status"];
  status.textContent = "正在核验可筛选来源…";
  try {
    const response = await request(task, `/employee/source-options${query}`);
    if (response === null || !isCurrent(task) || elements["business-day"].value !== day) return;
    if (response.status !== 200) {
      status.textContent = errorMessage(response.status, response.body);
      return;
    }
    const options = response.body.options;
    if (!Array.isArray(options) || options.some(option =>
      !referenceFormat.test(option.source_id) || typeof option.example_title !== "string"
    )) throw new Error("Invalid source options");
    if (!options.length) {
      status.textContent = "该业务日期没有可筛选的来源。";
      return;
    }
    const choice = elements["source-options"];
    choice.replaceChildren(new Option("不限来源", ""), ...options.map(option =>
      new Option(`${option.example_title} · ${option.source_id.slice(0, 8)}`, option.source_id)
    ));
    choice.value = elements["source-ref"].value.trim().toLowerCase();
    elements["source-options-panel"].hidden = false;
    status.textContent = "";
  } catch {
    if (isCurrent(task)) status.textContent = "暂时无法核验可筛选来源。";
  } finally {
    if (isCurrent(task)) session.sourceOptions = null;
  }
}

async function loadSearchSuggestions() {
  clearSearchSuggestions();
  const task = start("suggestions");
  if (task === null) return;
  const prefix = elements.query.value.trim();
  const day = elements["business-day"].value;
  const sourceRef = elements["source-ref"].value.trim();
  const status = elements["search-suggestion-status"];
  if (!prefix || [...prefix].length > 64 || (sourceRef && !referenceFormat.test(sourceRef))) {
    status.textContent = "请输入不超过 64 字的关键词开头，并检查文件库编号。";
    session.suggestions = null;
    return;
  }
  status.textContent = "正在帮你匹配相关规定标题…";
  try {
    const response = await request(task, "/employee/search-suggestions", {
      prefix, ...(day ? { business_date: day } : {}), ...(sourceRef ? { source_id: sourceRef } : {}),
    });
    if (response === null || !isCurrent(task)) return;
    if (response.status !== 200) {
      status.textContent = errorMessage(response.status, response.body);
      return;
    }
    const { suggestions } = response.body;
    if (!Array.isArray(suggestions) || suggestions.some(entry =>
      typeof entry.title !== "string" || !referenceFormat.test(entry.passage_id)
    )) throw new Error("Invalid search suggestions");
    const list = elements["search-suggestion-list"];
    list.replaceChildren(...suggestions.map(entry => {
      const row = document.createElement("li");
      const button = textElement("button", entry.title, "quiet-button");
      button.type = "button";
      button.setAttribute("aria-label", `核对建议：${entry.title}`);
      button.addEventListener("click", () => readReference(entry.passage_id));
      row.append(button);
      return row;
    }));
    list.hidden = suggestions.length === 0;
    status.textContent = suggestions.length ? "" : "没有匹配的可读标题。";
  } catch {
    if (isCurrent(task)) status.textContent = "暂时无法核验标题建议。";
  } finally {
    if (isCurrent(task)) session.suggestions = null;
  }
}

async function search(query, businessDate, topK, sourceRef, departmentCode = "") {
  const task = start("search");
  if (task === null) return;
  const includeWiki = elements["include-wiki"].checked;
  cancel("reference");
  clearFeedbackDraft();
  clearReference();
  clearResults("正在查找当前可读的依据…");
  elements.results.setAttribute("aria-busy", "true");
  try {
    const response = await request(task, "/v1/search", {
      query, top_k: topK, include_wiki: includeWiki, include_source_facets: true, include_department_facets: true,
      ...(businessDate ? { business_date: businessDate } : {}),
      ...(sourceRef ? { source_ids: [sourceRef] } : {}),
      ...(departmentCode ? { departments: [departmentCode] } : {}),
    });
    if (response === null || !isCurrent(task)) return;
    const { status, body } = response;
    if (status !== 200) {
      clearResults(errorMessage(status, body));
      return;
    }
    if (body.status !== "hits" && body.status !== "no_evidence") throw new Error("Invalid evidence response");
    const topics = includeWiki && elements["include-wiki"].checked ? body.wiki : [];
    const topicViews = topics.map(wikiView);
    elements.results.replaceChildren(...body.passages.map(passage => passageView(passage, body.request_id)));
    elements["wiki-result-list"].replaceChildren(...topicViews);
    elements["wiki-results"].hidden = topics.length === 0;
    showSourceFacets(body.source_facets);
    showDepartmentFacets(body.department_facets);
    elements["result-day"].textContent = `业务日期 ${body.business_date}`;
    elements["result-day"].hidden = false;
    elements["result-request"].querySelector("code").textContent = body.request_id;
    elements["result-request"].hidden = false;
    session.originSearch = body.request_id;
    elements["report-gap"].hidden = false;
    showResultStatus(body.passages.length, topics.length);
  } catch {
    if (isCurrent(task)) clearResults(retryMessage);
  } finally {
    if (isCurrent(task)) {
      elements.results.setAttribute("aria-busy", "false");
      session.search = null;
    }
  }
}

async function readReference(id, sourceButton) {
  const task = start("reference");
  if (task === null) return;
  clearFeedbackDraft();
  clearReference("正在重新核验这条引用…");
  if (!referenceFormat.test(id)) {
    clearReference("请输入完整的引用编号。");
    session.reference = null;
    return;
  }
  if (sourceButton) sourceButton.setAttribute("aria-pressed", "true");
  elements["reference-content"].setAttribute("aria-busy", "true");
  try {
    const response = await request(task, `/v1/passages/${encodeURIComponent(id)}`);
    if (response === null || !isCurrent(task)) return;
    const { status, body } = response;
    if (status !== 200) {
      cancel("search");
      clearResults();
      clearReference(errorMessage(status, body, true));
      return;
    }
    if (body.passage?.passage_id !== id.toLowerCase()) throw new Error("Citation response mismatch");
    elements["reference-status"].textContent = "已重新核验。以下是当前获准查看的摘录。";
    const view = passageView(body.passage, body.request_id, true);
    view.tabIndex = -1;
    elements["reference-content"].replaceChildren(view);
    view.focus();
  } catch {
    if (isCurrent(task)) {
      cancel("search");
      clearResults();
      clearReference(retryMessage);
    }
  } finally {
    if (isCurrent(task)) {
      elements["reference-content"].setAttribute("aria-busy", "false");
      session.reference = null;
    }
  }
}

async function submitFeedback() {
  const draft = session?.draft;
  if (!draft) return;
  const note = elements["feedback-note"].value.trim();
  if (new TextEncoder().encode(note).length > 2048) {
    elements["feedback-status"].textContent = "补充说明过长，请缩短后提交。";
    return;
  }
  if (draft.note !== note) {
    draft.note = note;
    draft.key = crypto.randomUUID();
  }
  const task = start("feedback");
  elements["submit-feedback"].disabled = true;
  elements["feedback-status"].textContent = "正在提交反馈…";
  try {
    const response = await request(task, "/internal/feedback", {
      origin_request_id: draft.origin,
      category: draft.passageId ? "incorrect_evidence" : "missing_evidence",
      ...(draft.passageId ? { passage_id: draft.passageId } : {}), ...(note ? { note } : {}),
    }, draft.key);
    if (response === null) return;
    if (response.status === 403) {
      elements["feedback-status"].textContent = "当前凭据无法反馈这条结果。";
      return;
    }
    if (response.status !== 200 || !referenceFormat.test(response.body.feedback_id)) throw new Error("Feedback unavailable");
    clearFeedbackDraft();
    elements["feedback-id"].value = response.body.feedback_id;
    clearFeedbackConclusion();
    elements["feedback-status"].textContent = "已提交，待核对。请保留反馈编号以查询进度。";
    elements["feedback-id"].focus();
  } catch {
    if (isCurrent(task)) elements["feedback-status"].textContent = "暂未确认反馈结果，请重试。";
  } finally {
    if (isCurrent(task)) {
      elements["submit-feedback"].disabled = false;
      session.feedback = null;
    }
  }
}

async function lookupFeedback() {
  clearFeedbackDraft();
  clearFeedbackConclusion();
  const task = start("feedback");
  if (task === null) return;
  const ref = elements["feedback-id"].value.trim().toLowerCase();
  if (!referenceFormat.test(ref)) {
    elements["feedback-status"].textContent = "请输入完整的反馈编号。";
    session.feedback = null;
    return;
  }
  elements["feedback-status"].textContent = "正在查询进度…";
  try {
    const response = await request(task, `/internal/feedback/${encodeURIComponent(ref)}`);
    if (response === null) return;
    if (response.status === 403) {
      elements["feedback-status"].textContent = "当前凭据无法查看这条反馈。";
      return;
    }
    const status = feedbackStates.get(response.body.state);
    if (response.status !== 200 || response.body.feedback_id !== ref || !status || !Number.isInteger(response.body.generation)) {
      throw new Error("Feedback progress unavailable");
    }
    elements["feedback-status"].textContent = `${status} · 第 ${response.body.generation} 代`;
    const conclusion = feedbackConclusions.get(response.body.conclusion_code);
    if (conclusion) {
      elements["feedback-conclusion"].textContent = `处理结论：${conclusion}`;
      elements["feedback-conclusion"].hidden = false;
    }
  } catch {
    if (isCurrent(task)) elements["feedback-status"].textContent = "暂时无法查询进度，请稍后重试。";
  } finally {
    if (isCurrent(task)) session.feedback = null;
  }
}

function feedbackNoticeRow(item) {
  const label = feedbackNoticeLabels.get(item.state);
  if (!label || !referenceFormat.test(item.feedback_id) || !referenceFormat.test(item.notice_id)) {
    throw new Error("Invalid feedback notice");
  }
  const row = textElement("li", "", "feedback-notice-row");
  const summary = textElement("div", "");
  summary.append(textElement("p", label), textElement("code", item.feedback_id));
  const action = textElement("button", "查看处理进度", "quiet-button");
  action.type = "button";
  action.setAttribute("aria-describedby", `notice-${item.notice_id}`);
  summary.id = `notice-${item.notice_id}`;
  action.addEventListener("click", () => {
    elements["feedback-id"].value = item.feedback_id;
    elements["feedback-id"].focus();
    lookupFeedback();
  });
  row.append(summary, action);
  return row;
}

async function loadFeedbackNotices(after = null) {
  const task = start("notices");
  if (task === null) return;
  clearFeedbackNotices();
  const status = elements["feedback-notice-status"];
  const list = elements["feedback-notice-list"];
  status.textContent = "正在读取通知…";
  list.setAttribute("aria-busy", "true");
  try {
    const response = await request(task, `/internal/feedback/notices${after ? `?after=${encodeURIComponent(after)}` : ""}`);
    if (response === null) return;
    if (response.status === 403) {
      status.textContent = "当前凭据无法查看反馈通知。";
      return;
    }
    const { items, next_cursor: next } = response.body;
    if (response.status !== 200 || !Array.isArray(items) || (next !== null && !referenceFormat.test(next))) {
      throw new Error("Feedback notices unavailable");
    }
    list.replaceChildren(...items.map(feedbackNoticeRow));
    session.nextNotice = next;
    elements["feedback-notice-next"].hidden = next === null;
    status.textContent = items.length ? "通知仅显示处理状态；打开工单可查看当前结论。" : "当前没有反馈通知。";
  } catch {
    if (isCurrent(task)) status.textContent = "暂时无法读取通知，请稍后重试。";
  } finally {
    if (isCurrent(task)) {
      list.setAttribute("aria-busy", "false");
      session.notices = null;
    }
  }
}

function unlockWithToken(token) {
  const shared = pendingSharedReference;
  lock();
  if (!credentialFormat.test(token)) {
    pendingSharedReference = shared;
    accessMessage("请输入完整的本机测试凭据。");
    elements["access-token"].focus();
    return false;
  }
  session = { token, search: null, reference: null, feedback: null, originSearch: null, draft: null };
  elements["locked-panel"].hidden = true;
  elements["session-actions"].hidden = false;
  elements.workspace.hidden = false;
  elements.query.focus();
  if (shared) readReference(shared);
  return true;
}

function renderInkShanShui() {
  function hash(n) {
    const x = Math.sin(n * 127.1 + 311.7) * 43758.5453123;
    return x - Math.floor(x);
  }
  function noise1D(x, seed) {
    const i = Math.floor(x);
    const f = x - i;
    const u = f * f * (3 - 2 * f);
    return hash(i + seed) * (1 - u) + hash(i + 1 + seed) * u;
  }
  function fbm(x, seed, octaves) {
    let v = 0, amp = 0.5, freq = 1;
    for (let o = 0; o < octaves; o++) {
      v += amp * noise1D(x * freq, seed + o * 19.3);
      freq *= 2.05;
      amp *= 0.5;
    }
    return v;
  }

  document.querySelectorAll(".ink-sidebar").forEach(sb => {
    if (sb.querySelector(".sidebar-ink-canvas")) return;
    const c = document.createElement("canvas");
    c.className = "sidebar-ink-canvas";
    c.setAttribute("aria-hidden", "true");
    const W = 476, H = 1040;
    c.width = W;
    c.height = H;
    sb.insertBefore(c, sb.firstChild);
    const ctx = c.getContext("2d");
    if (!ctx) return;

    const smokeGrad = ctx.createRadialGradient(W * 0.72, H * 0.34, 20, W * 0.65, H * 0.42, W * 0.95);
    smokeGrad.addColorStop(0, "rgba(138, 142, 146, 0.22)");
    smokeGrad.addColorStop(0.55, "rgba(78, 82, 86, 0.10)");
    smokeGrad.addColorStop(1, "rgba(24, 25, 27, 0)");
    ctx.fillStyle = smokeGrad;
    ctx.fillRect(0, 0, W, H);

    function drawRidge(baseY, amp, scale, seed, fillTop, fillBot, goldStroke) {
      const pts = [];
      ctx.beginPath();
      ctx.moveTo(0, H);
      for (let x = 0; x <= W; x += 3) {
        const env = 0.65 + 0.55 * Math.sin((x / W) * Math.PI * 0.92 + 0.3);
        const y = baseY - fbm(x * scale, seed, 5) * amp * env;
        pts.push([x, y]);
        ctx.lineTo(x, y);
      }
      ctx.lineTo(W, H);
      ctx.closePath();
      const g = ctx.createLinearGradient(0, baseY - amp, 0, H);
      g.addColorStop(0, fillTop);
      g.addColorStop(1, fillBot);
      ctx.fillStyle = g;
      ctx.fill();

      if (goldStroke) {
        ctx.save();
        ctx.beginPath();
        pts.forEach(([x, y], idx) => {
          if (idx === 0) ctx.moveTo(x, y + 1.5);
          else ctx.lineTo(x, y + 1.5);
        });
        const gg = ctx.createLinearGradient(W * 0.08, 0, W * 0.92, 0);
        gg.addColorStop(0, "rgba(216, 180, 106, 0)");
        gg.addColorStop(0.35, goldStroke);
        gg.addColorStop(0.75, "rgba(230, 198, 128, 0.52)");
        gg.addColorStop(1, "rgba(180, 140, 65, 0.08)");
        ctx.strokeStyle = gg;
        ctx.lineWidth = 2.2;
        ctx.stroke();
        ctx.restore();
      }
    }

    drawRidge(H * 0.50, 220, 0.007, 4.2, "rgba(98, 103, 108, 0.42)", "rgba(28, 30, 33, 0.85)", null);

    const mist1 = ctx.createRadialGradient(W * 0.48, H * 0.54, 10, W * 0.48, H * 0.56, W * 0.72);
    mist1.addColorStop(0, "rgba(238, 235, 226, 0.24)");
    mist1.addColorStop(0.6, "rgba(210, 207, 198, 0.09)");
    mist1.addColorStop(1, "rgba(25, 26, 28, 0)");
    ctx.fillStyle = mist1;
    ctx.fillRect(0, H * 0.25, W, H * 0.55);

    drawRidge(H * 0.64, 250, 0.0095, 13.7, "rgba(36, 38, 42, 0.92)", "rgba(14, 15, 17, 0.98)", "rgba(208, 168, 90, 0.44)");
    drawRidge(H * 0.80, 210, 0.012, 29.1, "rgba(15, 16, 18, 0.95)", "rgba(8, 9, 10, 1)", "rgba(197, 155, 72, 0.26)");

    for (let i = 0; i < 16; i++) {
      const cx = (hash(i * 3.1) * 0.68 - 0.08) * W;
      const cy = H * (0.73 + hash(i * 7.7) * 0.27);
      const rx = 75 + hash(i * 5.3) * 130;
      const mg = ctx.createRadialGradient(cx, cy, 4, cx, cy, rx);
      const alpha = 0.14 + hash(i * 11.9) * 0.16;
      mg.addColorStop(0, `rgba(244, 241, 234, ${alpha})`);
      mg.addColorStop(0.55, `rgba(222, 218, 208, ${alpha * 0.45})`);
      mg.addColorStop(1, "rgba(244, 241, 234, 0)");
      ctx.fillStyle = mg;
      ctx.beginPath();
      ctx.arc(cx, cy, rx, 0, Math.PI * 2);
      ctx.fill();
    }

    for (let s = 0; s < 36; s++) {
      const sx = hash(s * 17.3) * W * 0.62;
      const sy = H * (0.76 + hash(s * 23.1) * 0.23);
      const sr = 1.2 + Math.pow(hash(s * 31.7), 2.4) * 9.0;
      ctx.fillStyle = `rgba(18, 19, 21, ${0.28 + hash(s * 41.2) * 0.55})`;
      ctx.beginPath();
      ctx.ellipse(sx, sy, sr * 1.25, sr * 0.85, hash(s) * Math.PI, 0, Math.PI * 2);
      ctx.fill();
    }

    for (let g = 0; g < 14; g++) {
      const gx = W * (0.18 + hash(g * 19.9) * 0.68);
      const gy = H * (0.48 + hash(g * 29.3) * 0.36);
      const gr = 1.0 + hash(g * 37.1) * 1.8;
      ctx.fillStyle = `rgba(226, 193, 120, ${0.25 + hash(g * 13.3) * 0.35})`;
      ctx.beginPath();
      ctx.arc(gx, gy, gr, 0, Math.PI * 2);
      ctx.fill();
    }

    const topFade = ctx.createLinearGradient(0, 0, 0, H * 0.26);
    topFade.addColorStop(0, "rgba(24, 25, 27, 1)");
    topFade.addColorStop(1, "rgba(24, 25, 27, 0)");
    ctx.fillStyle = topFade;
    ctx.fillRect(0, 0, W, H * 0.26);
  });

  document.querySelectorAll(".mist-search-card").forEach(banner => {
    if (banner.querySelector(".banner-mist-canvas")) return;
    const bc = document.createElement("canvas");
    bc.className = "banner-mist-canvas";
    bc.setAttribute("aria-hidden", "true");
    const BW = 1400, BH = 280;
    bc.width = BW;
    bc.height = BH;
    banner.insertBefore(bc, banner.firstChild);
    const bctx = bc.getContext("2d");
    if (!bctx) return;

    function bannerRidge(baseY, amp, scale, seed, rgbaTop, goldRgba) {
      bctx.beginPath();
      bctx.moveTo(BW * 0.12, BH);
      const pts = [];
      for (let x = Math.floor(BW * 0.12); x <= BW; x += 4) {
        const fadeLeft = Math.min(1, (x - BW * 0.12) / (BW * 0.28));
        const y = baseY - fbm(x * scale, seed, 4) * amp * fadeLeft;
        pts.push([x, y]);
        bctx.lineTo(x, y);
      }
      bctx.lineTo(BW, BH);
      bctx.closePath();
      const g = bctx.createLinearGradient(0, baseY - amp, 0, BH);
      g.addColorStop(0, rgbaTop);
      g.addColorStop(1, "rgba(250, 248, 243, 0)");
      bctx.fillStyle = g;
      bctx.fill();

      if (goldRgba) {
        bctx.beginPath();
        pts.forEach(([x, y], i) => (i === 0 ? bctx.moveTo(x, y) : bctx.lineTo(x, y)));
        bctx.strokeStyle = goldRgba;
        bctx.lineWidth = 1.4;
        bctx.stroke();
      }
    }

    bannerRidge(BH * 0.86, 155, 0.0045, 8.1, "rgba(116, 122, 128, 0.095)", null);
    bannerRidge(BH * 0.94, 120, 0.0062, 21.4, "rgba(197, 155, 72, 0.085)", "rgba(197, 155, 72, 0.24)");
  });
}

document.querySelectorAll(".sb-nav [data-nav-target]").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".sb-nav .sb-item").forEach(item => item.classList.remove("active"));
    btn.classList.add("active");
    if (session === null) {
      elements["access-token"].focus();
      return;
    }
    const target = btn.dataset.navTarget;
    if (target === "search") {
      elements.query.focus();
    } else if (target === "wiki") {
      elements["include-wiki"].checked = true;
      if (!elements["wiki-results"].hidden) {
        elements["wiki-results"].scrollIntoView({ behavior: "smooth", block: "nearest" });
      } else {
        elements.query.focus();
      }
    } else if (target === "direct-ref") {
      elements["direct-reference"].open = true;
      elements["reference-id"].focus();
    } else if (target === "feedback") {
      document.getElementById("feedback-section")?.scrollIntoView({ behavior: "smooth", block: "start" });
      elements["feedback-notices"].focus();
    }
  });
});

elements["access-form"].addEventListener("submit", event => {
  event.preventDefault();
  unlockWithToken(elements["access-token"].value.trim());
});

elements["search-form"].addEventListener("submit", event => {
  event.preventDefault();
  clearSearchSuggestions();
  const query = elements.query.value.trim();
  const sourceRef = elements["source-ref"].value.trim();
  const departmentCode = elements["department-code"].value.trim().toLowerCase();
  if (!query || (sourceRef && !referenceFormat.test(sourceRef)) || (departmentCode && !departmentCodeFormat.test(departmentCode))) {
    cancel("search");
    cancel("reference");
    clearFeedbackDraft();
    clearResults(!query ? "请输入关键词或问题。" : (sourceRef && !referenceFormat.test(sourceRef)) ? "请输入完整的来源编号，或清空此项。" : "部门代码仅支持小写字母、数字、下划线和短横线。");
    clearReference();
    (!query ? elements.query : (sourceRef && !referenceFormat.test(sourceRef)) ? elements["source-ref"] : elements["department-code"]).focus();
    return;
  }
  search(query, elements["business-day"].value, elements["passage-count"].valueAsNumber, sourceRef, departmentCode);
});

elements["reference-form"].addEventListener("submit", event => {
  event.preventDefault();
  const id = elements["reference-id"].value.trim();
  elements["reference-id"].value = "";
  readReference(id);
});

elements["load-source-options"].addEventListener("click", loadSourceOptions);
elements["load-department-options"].addEventListener("click", loadDepartmentOptions);
elements["business-day"].addEventListener("input", () => { clearSourceOptions(); clearDepartmentOptions(); });
elements["department-options"].addEventListener("change", () => {
  elements["department-code"].value = elements["department-options"].value;
});
elements["department-code"].addEventListener("input", () => {
  elements["department-options"].value = elements["department-code"].value.trim().toLowerCase();
});
elements["load-search-suggestions"].addEventListener("click", loadSearchSuggestions);
elements.query.addEventListener("input", clearSearchSuggestions);
elements["business-day"].addEventListener("input", clearSearchSuggestions);
elements["source-options"].addEventListener("change", () => {
  elements["source-ref"].value = elements["source-options"].value;
  clearSearchSuggestions();
});
elements["source-ref"].addEventListener("input", () => {
  elements["source-options"].value = elements["source-ref"].value.trim().toLowerCase();
  clearSearchSuggestions();
});

elements["include-wiki"].addEventListener("change", () => {
  if (!elements["include-wiki"].checked && !elements["wiki-results"].hidden) {
    clearWiki();
    showResultStatus(elements.results.childElementCount, 0);
  }
});
elements["report-gap"].addEventListener("click", () => openFeedback(session?.originSearch));
elements["feedback-form"].addEventListener("submit", event => {
  event.preventDefault();
  submitFeedback();
});
elements["feedback-lookup"].addEventListener("submit", event => {
  event.preventDefault();
  lookupFeedback();
});
elements["feedback-notices"].addEventListener("click", () => loadFeedbackNotices());
elements["feedback-notice-next"].addEventListener("click", () => {
  if (session?.nextNotice) {
    elements["feedback-notices"].focus();
    loadFeedbackNotices(session.nextNotice);
  }
});
elements["switch-employee"].addEventListener("click", () => lock("已清除上一个员工的凭据和结果。", true));
elements.logout.addEventListener("click", () => lock("已退出，凭据和结果已清除。", true));
window.addEventListener("pagehide", () => lock());
window.addEventListener("pageshow", event => {
  if (event.persisted) lock("此页面已重新锁定，请载入凭据。");
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) lock("页面已锁定，请重新载入凭据。");
});
window.addEventListener("hashchange", loadSharedReference);
async function initOidcSso() {
  const hash = location.hash || "";
  if (hash.startsWith("#oidc_ticket=")) {
    const ticket = decodeURIComponent(hash.slice("#oidc_ticket=".length));
    history.replaceState(null, "", location.pathname + location.search);
    if (ticket) {
      try {
        const res = await fetch("/auth/oidc/exchange", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ticket }),
          cache: "no-store",
          credentials: "same-origin",
        });
        if (res.ok) {
          const data = await res.json();
          if (data.access_token && unlockWithToken(data.access_token)) return;
        }
        accessMessage("企业单点登录票据校验失败，请重新登录。");
      } catch {
        accessMessage("企业单点登录交换失败，请重试。");
      }
    }
  }
  try {
    const statusRes = await fetch("/auth/oidc/status", { cache: "no-store" });
    if (statusRes.ok) {
      const info = await statusRes.json();
      if (info && info.enabled === true) {
        elements["oidc-sso-box"].hidden = false;
        elements["oidc-login-button"].addEventListener("click", () => {
          window.location.assign(`/auth/oidc/login?return_to=${encodeURIComponent(location.pathname)}`);
        });
      }
    }
  } catch {
    // Keep OIDC SSO hidden if status endpoint is unavailable.
  }
}

renderInkShanShui();
lock();
loadSharedReference();
initOidcSso();

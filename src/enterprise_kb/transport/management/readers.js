const modelEgress = document.body.hasAttribute("data-model-egress-policy");
const prefix = modelEgress ? "model-egress" : "readers";
const endpoint = modelEgress ? "model-egress-policy" : "access-policy";
const ruleLabel = modelEgress ? "外发规则" : "读者规则";
const ui = Object.fromEntries([
  "lock", "access", "token", "workspace", "logout", "lookup", "source", "source-options", "source-id", "status", "ruleset",
  "meta", "retained", "editor", "basis", "confirm", "save", "rows", "row", "add",
].map(name => [name, document.getElementById(`${prefix}-${name}`)]));
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const sourcePicker = modelEgress ? null : ui["source-options"];
const sourceStates = { active: "启用中", suspended: "已停用" };
const zonedTime = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/;
const editorRule = modelEgress
  ? { operation: "send_model_evidence", destination: "synthetic-gateway" }
  : { operation: "read_passage", purpose: "employee_evidence", destination: "employee" };
const missingResponse = "未收到规则操作结果；保存结果未知时请保留表单原样重试。";
let session = null;
let sourceSearch = null;
let sourceTimer = null;

function clearSourceOptions() {
  sourceSearch?.abort();
  sourceSearch = null;
  clearTimeout(sourceTimer);
  sourceTimer = null;
  if (!sourcePicker) return;
  ui["source-id"].value = "";
  sourcePicker.hidden = true;
  sourcePicker.replaceChildren();
}

async function searchSources(query) {
  const active = session;
  if (!active || !sourcePicker || !query || uuid.test(query)) return;
  sourceSearch?.abort();
  const controller = new AbortController();
  sourceSearch = controller;
  const current = () => session === active && sourceSearch === controller && !controller.signal.aborted;
  ui.status.textContent = "正在搜索可管理的文件库…";
  try {
    const response = await fetch(`/internal/sources/options?usage=readers&q=${encodeURIComponent(query)}&limit=20`, {
      headers: { Authorization: `Bearer ${active.token}` }, signal: controller.signal,
      cache: "no-store", credentials: "omit", mode: "same-origin", redirect: "error", referrerPolicy: "no-referrer",
    });
    if (!current()) return;
    if (response.status === 401) return lock("凭据无效或已过期，请重新载入。", true);
    if (response.status === 403) {
      ui.status.textContent = "当前凭据不能搜索可管理的文件库。";
      return;
    }
    if (!response.ok) throw new Error("Source options are unavailable.");
    const data = await response.json();
    if (!current()) return;
    if (!Array.isArray(data.sources) || data.sources.length > 20) throw new TypeError("Invalid source options.");
    const options = data.sources.map(source => {
      if (!uuid.test(source.id) || typeof source.name !== "string" || typeof source.status !== "string") {
        throw new TypeError("Invalid source option.");
      }
      const button = document.createElement("button");
      button.type = "button";
      button.className = "quiet-button";
      button.setAttribute("role", "option");
      button.textContent = `${source.name} · ${sourceStates[source.status] ?? source.status}`;
      button.addEventListener("click", () => {
        if (session !== active) return;
        ui.source.value = source.name;
        clearSourceOptions();
        ui["source-id"].value = source.id;
        send(source.id, null, body => renderSnapshot(source.id, body));
      });
      return button;
    });
    sourcePicker.replaceChildren(...options);
    sourcePicker.hidden = options.length === 0;
    ui.status.textContent = options.length ? "请选择要设置权限的文件库。" : "没有找到可管理的文件库。";
  } catch {
    if (current()) ui.status.textContent = "暂时无法搜索文件库，请稍后重试。";
  } finally {
    if (current()) sourceSearch = null;
  }
}

function clearSnapshot() {
  if (session) {
    session.snapshot = null;
    session.command = null;
  }
  ui.ruleset.hidden = true;
  ui.editor.reset();
  ui.rows.replaceChildren();
  ui.meta.textContent = "";
  if (ui.retained) ui.retained.textContent = "";
  ui.save.disabled = true;
}

function lock(message = "", focus = false) {
  session?.pending?.abort();
  session = null;
  clearSourceOptions();
  clearSnapshot();
  ui.lookup.reset();
  ui.lookup.inert = false;
  ui.editor.inert = false;
  ui.token.value = "";
  ui.status.textContent = message;
  ui.workspace.hidden = true;
  ui.lock.hidden = false;
  if (focus) ui.token.focus();
}

function requireConfirmation() {
  ui.confirm.checked = false;
  ui.save.disabled = true;
}

function refreshRows() {
  Array.from(ui.rows.children).forEach((row, index) => {
    row.querySelector("legend").textContent = `${ruleLabel} ${index + 1}`;
  });
  ui.add.disabled = ui.rows.children.length + session.snapshot.retained.length >= 500;
  requireConfirmation();
}

function addRule(existing = null) {
  const row = ui.row.content.firstElementChild.cloneNode(true);
  if (existing) {
    for (const name of ["subject_id", "effect", "passage_id", "valid_from", "valid_until"]) {
      if (name !== "subject_id") row.querySelector(`[name=${name}]`).value = existing[name] ?? "";
    }
    row.querySelector('[name=subject_id]').value = existing.subject_name ?? existing.subject_id ?? "";
    row.querySelector('[name=subject_id]').dataset.principalRef = existing.subject_id ?? "";
    if (modelEgress) row.querySelector("[name=purpose]").value = existing.purpose;
    else row.querySelector("[name=whole_source]").checked = !existing.passage_id;
    for (const field of row.querySelectorAll("[name=fields]")) field.checked = existing.fields.includes(field.value);
  }
  row.querySelector("button").addEventListener("click", () => {
    row.remove();
    refreshRows();
    ui.add.focus();
  });
  if (!modelEgress) attachSubjectPicker(row);
  ui.rows.append(row);
  return row;
}

function attachSubjectPicker(row) {
  const input = row.querySelector('[name="subject_id"]');
  const options = row.querySelector(".subject-picker-options");
  let controller = null;
  let timer = null;
  const clear = () => {
    controller?.abort();
    clearTimeout(timer);
    options.replaceChildren();
    options.hidden = true;
  };
  const search = async () => {
    const source = session?.snapshot?.source;
    const query = input.value.trim();
    if (!source || !query || uuid.test(query)) return;
    controller?.abort();
    controller = new AbortController();
    try {
      const response = await fetch(`/internal/sources/${source}/reader-subjects?q=${encodeURIComponent(query)}&limit=20`, {
        headers: { Authorization: `Bearer ${session.token}` }, signal: controller.signal,
        cache: "no-store", credentials: "omit", mode: "same-origin", redirect: "error", referrerPolicy: "no-referrer",
      });
      if (!response.ok) throw new Error("Subject options unavailable.");
      const data = await response.json();
      if (!Array.isArray(data.subjects)) throw new TypeError("Invalid subject options.");
      const buttons = data.subjects.map(subject => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "quiet-button";
        button.setAttribute("role", "option");
        button.disabled = subject.selectable === false;
        const state = subject.selectable ? "" : ` · ${subject.status === "departed" ? "已离职" : "已停用"}`;
        button.textContent = `${subject.name}${subject.department ? ` · ${subject.department}` : ""}${state}`;
        button.addEventListener("click", () => {
          input.value = subject.name;
          input.dataset.principalRef = subject.id;
          clear();
          input.focus();
        });
        return button;
      });
      options.replaceChildren(...buttons);
      options.hidden = buttons.length === 0;
    } catch (error) {
      if (error.name !== "AbortError") options.hidden = true;
    }
  };
  input.addEventListener("input", () => {
    delete input.dataset.principalRef;
    clear();
    clearTimeout(timer);
    timer = setTimeout(search, 180);
    requireConfirmation();
  });
  input.addEventListener("keydown", event => {
    if (event.key === "Escape") clear();
  });
}

function renderSnapshot(source, body) {
  if (!Number.isSafeInteger(body.safety_epoch) || body.safety_epoch < 1 || !Array.isArray(body.rules) || body.rules.length > 500) {
    throw new TypeError("Invalid policy snapshot.");
  }
  const editable = [];
  const retained = [];
  for (const rule of body.rules) {
    if (Object.entries(editorRule).every(([key, value]) => rule[key] === value)) editable.push(rule);
    else if (modelEgress) throw new TypeError("Unexpected rule scope in the model egress snapshot.");
    else retained.push(rule);
  }
  editable.forEach(addRule);
  session.snapshot = { source, epoch: body.safety_epoch, retained };
  ui.meta.textContent = modelEgress
    ? (body.policy_revision === null ? "尚未登记共享策略。" : `当前共享策略修订 ${body.policy_revision}。`)
    : (body.policy_revision === null ? "未配置本地规则。" : `当前规则修订 ${body.policy_revision}。`);
  if (ui.retained) ui.retained.textContent = `保留 ${retained.length} 条本地工作区规则。`;
  refreshRows();
  ui.ruleset.hidden = false;
  ui.status.textContent = "当前规则已载入。";
}

function collectRules() {
  return Array.from(ui.rows.children, (row, index) => {
    const get = name => row.querySelector(`[name=${name}]`).value.trim();
    const subjectInput = row.querySelector('[name="subject_id"]');
    const subject = subjectInput.dataset.principalRef || get("subject_id"), passage = get("passage_id");
    const start = get("valid_from"), end = get("valid_until");
    const fields = Array.from(row.querySelectorAll("[name=fields]:checked"), item => item.value);
    if (modelEgress) {
      const purpose = get("purpose");
      if (!uuid.test(subject) || !uuid.test(passage) || !purpose || !fields.length ||
          !zonedTime.test(start) || !zonedTime.test(end)) {
        throw new TypeError(`请核对第 ${index + 1} 条规则：填写主体及片段、选择用途及字段，起止时间均须带时区。`);
      }
      return { ...editorRule, purpose, subject_id: subject, passage_id: passage, effect: get("effect"),
        fields, valid_from: start, valid_until: end };
    }
    const wholeSource = row.querySelector("[name=whole_source]").checked;
    if (!uuid.test(subject) || Boolean(passage) === wholeSource || (passage && !uuid.test(passage)) ||
        !fields.length || !zonedTime.test(start) || (end && !zonedTime.test(end))) {
      throw new TypeError(`请核对第 ${index + 1} 条规则：填写主体、选择片段或整个来源、勾选字段并使用带时区的时刻。`);
    }
    return {
      ...editorRule, subject_id: subject, effect: get("effect"), fields, valid_from: start,
      ...(passage ? { passage_id: passage } : {}), ...(end ? { valid_until: end } : {}),
    };
  });
}

async function send(source, command, accept) {
  const active = session;
  active.pending?.abort();
  const pending = new AbortController();
  active.pending = pending;
  const current = () => session === active && active.pending === pending;
  ui.lookup.inert = Boolean(command);
  ui.editor.inert = Boolean(command);
  ui.status.textContent = command ? "正在保存来源规则…" : "正在读取当前规则…";
  try {
    const headers = { "Authorization": `Bearer ${active.token}` };
    if (command) {
      headers["Content-Type"] = "application/json";
      headers["Idempotency-Key"] = command.key;
    }
    const response = await fetch(`/internal/sources/${source}/${endpoint}`, {
      method: command ? "POST" : "GET", headers, body: command?.body, signal: pending.signal,
    });
    const data = response.ok ? await response.json() : null;
    if (!current()) return;
    if (response.ok) {
      accept(data);
    } else {
      if ([401, 403, 409].includes(response.status)) clearSnapshot();
      ui.status.textContent = {
        400: "规则参数无效，请核对编号、字段和时间区间。",
        401: "凭据无效或已过期，请更换凭据。",
        403: "当前凭据不能管理该来源的规则。",
        409: "规则已变化或提交冲突，请读取当前规则后重新核对。",
        413: "规则清单超过大小限制。",
      }[response.status] || missingResponse;
    }
  } catch {
    if (current()) ui.status.textContent = missingResponse;
  } finally {
    if (current()) {
      active.pending = null;
      ui.lookup.inert = false;
      ui.editor.inert = false;
    }
  }
}

ui.access.addEventListener("submit", event => {
  event.preventDefault();
  const token = ui.token.value.trim();
  if (!token || session) return;
  session = { token };
  ui.token.value = "";
  ui.lock.hidden = true;
  ui.workspace.hidden = false;
  ui.source.focus();
});
ui.logout.addEventListener("click", () => { lock(); ui.token.focus(); });
window.addEventListener("pagehide", lock);
window.addEventListener("pageshow", event => { if (event.persisted) lock(); });
document.addEventListener("visibilitychange", () => { if (document.hidden) lock(); });
ui.source.addEventListener("input", () => {
  if (!session) return;
  session.pending?.abort();
  session.pending = null;
  clearSnapshot();
  clearSourceOptions();
  ui.status.textContent = "";
  if (sourcePicker && !uuid.test(ui.source.value.trim())) {
    sourceTimer = setTimeout(() => searchSources(ui.source.value.trim()), 180);
  }
});
ui.lookup.addEventListener("submit", event => {
  event.preventDefault();
  if (!session || ui.lookup.inert) return;
  clearSnapshot();
  const query = ui.source.value.trim();
  const source = (ui["source-id"].value || query).toLowerCase();
  if (!uuid.test(source)) {
    if (sourcePicker) searchSources(query);
    else ui.status.textContent = "请输入有效的来源编号。";
    return;
  }
  clearSourceOptions();
  ui["source-id"].value = source;
  send(source, null, body => renderSnapshot(source, body));
});
ui.add.addEventListener("click", () => {
  const row = addRule();
  refreshRows();
  row.querySelector("[name=subject_id]").focus();
});
ui.editor.addEventListener("input", event => {
  if (event.target === ui.confirm) ui.save.disabled = !ui.confirm.checked;
  else requireConfirmation();
});
ui.editor.addEventListener("submit", event => {
  event.preventDefault();
  const snapshot = session?.snapshot;
  if (!snapshot || !ui.confirm.checked || session.pending) return;
  const basis = ui.basis.value.trim();
  if (!uuid.test(basis)) {
    ui.status.textContent = "请输入有效的变更依据编号。";
    return;
  }
  let rules;
  try {
    rules = collectRules();
  } catch (error) {
    ui.status.textContent = error.message;
    return;
  }
  const body = JSON.stringify({ expected_epoch: snapshot.epoch, basis_id: basis, rules: [...rules, ...snapshot.retained] });
  if (session.command?.body !== body) session.command = { body, key: crypto.randomUUID() };
  send(snapshot.source, session.command, receipt => {
    if (!Number.isSafeInteger(receipt.policy_revision) || receipt.policy_revision !== snapshot.epoch + 1) {
      throw new TypeError("Invalid policy receipt.");
    }
    clearSnapshot();
    ui.status.textContent = `已登记规则修订 ${receipt.policy_revision}。`;
  });
});

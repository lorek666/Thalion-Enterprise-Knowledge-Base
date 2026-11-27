const ui = Object.fromEntries([
  "lock", "access", "token", "workspace", "logout", "lookup", "document", "status", "receipt",
  "details", "state", "subject", "expiry", "editor", "action", "assignment", "employee", "until", "basis",
].map(name => [name, document.getElementById(`responsibility-${name}`)]));
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const zonedTime = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/;
const labels = {
  assigned: "已登记有效负责人。",
  unassigned: "当前没有负责人。",
  expired: "负责人任期已到，不沿用前任。",
  inactive: "最近登记的员工已停用，当前没有有效负责人。",
};
let session = null;

function syncAction() {
  const revoke = ui.action.value === "revoke";
  ui.assignment.hidden = revoke;
  ui.employee.disabled = revoke;
  ui.until.disabled = revoke;
}

function clearSnapshot() {
  if (session) {
    session.snapshot = null;
    session.command = null;
  }
  ui.details.hidden = true;
  ui.editor.reset();
  syncAction();
  for (const item of [ui.state, ui.subject, ui.expiry, ui.receipt]) item.textContent = "";
}

function lock() {
  session?.pending?.abort();
  session = null;
  clearSnapshot();
  ui.lookup.reset();
  ui.lookup.inert = false;
  ui.editor.inert = false;
  ui.token.value = "";
  ui.status.textContent = "";
  ui.workspace.hidden = true;
  ui.lock.hidden = false;
}

async function send(documentRef, command, accept) {
  const active = session;
  active.pending?.abort();
  const pending = new AbortController();
  active.pending = pending;
  const current = () => session === active && active.pending === pending;
  const retryMessage = command ? "未收到保存结果，请保留表单原样重试。" : "暂时无法读取负责人，请重试。";
  ui.lookup.inert = Boolean(command);
  ui.editor.inert = Boolean(command);
  ui.status.textContent = command ? "正在保存责任决定…" : "正在读取当前负责人…";
  try {
    const headers = { "Authorization": `Bearer ${active.token}` };
    if (command) {
      headers["Content-Type"] = "application/json";
      headers["Idempotency-Key"] = command.key;
    }
    const response = await fetch(`/internal/sources/documents/${documentRef}/responsibility`, {
      method: command ? "POST" : "GET", headers, body: command?.body, signal: pending.signal,
    });
    const body = response.ok ? await response.json() : null;
    if (!current()) return;
    if (response.ok) {
      accept(body);
    } else {
      if ([401, 403, 409].includes(response.status)) clearSnapshot();
      ui.status.textContent = {
        400: "参数无效，请核对员工编号、依据和任期截止时间。",
        401: "凭据无效或已过期，请更换凭据。",
        403: "当前凭据不能管理该资料的负责人。",
        409: "负责人的决定已变化或提交冲突，请重新读取。",
      }[response.status] || retryMessage;
    }
  } catch {
    if (current()) ui.status.textContent = retryMessage;
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
  ui.document.focus();
});
ui.logout.addEventListener("click", () => { lock(); ui.token.focus(); });
window.addEventListener("pagehide", lock);
window.addEventListener("pageshow", event => { if (event.persisted) lock(); });
document.addEventListener("visibilitychange", () => { if (document.hidden) lock(); });
ui.action.addEventListener("change", syncAction);
ui.document.addEventListener("input", () => {
  if (!session) return;
  session.pending?.abort();
  session.pending = null;
  clearSnapshot();
  ui.status.textContent = "";
});
ui.lookup.addEventListener("submit", event => {
  event.preventDefault();
  if (!session || ui.lookup.inert) return;
  clearSnapshot();
  const documentRef = ui.document.value.trim().toLowerCase();
  if (!uuid.test(documentRef)) {
    ui.status.textContent = "请输入有效的资料编号。";
    return;
  }
  send(documentRef, null, body => {
    if (body.document_id !== documentRef || !Number.isSafeInteger(body.generation) || body.generation < 0 ||
        !Object.hasOwn(labels, body.state) || (body.state === "assigned" && !uuid.test(body.responsible_id))) {
      throw new TypeError("Invalid responsibility snapshot.");
    }
    session.snapshot = { documentRef, generation: body.generation };
    ui.state.textContent = body.generation === 0 ? "尚未登记负责人。" : labels[body.state];
    ui.subject.textContent = body.state === "assigned" ? body.responsible_id : "";
    ui.expiry.textContent = body.expires_at ? `任期截止：${body.expires_at}` : "";
    ui.details.hidden = false;
    ui.status.textContent = `已读取当前决定（代次 ${body.generation}）。`;
  });
});

ui.editor.addEventListener("submit", event => {
  event.preventDefault();
  const snapshot = session?.snapshot;
  if (!snapshot || session.pending) return;
  const basis = ui.basis.value.trim();
  const revoked = ui.action.value === "revoke";
  const subject = revoked ? null : ui.employee.value.trim();
  const expiry = revoked ? "" : ui.until.value.trim();
  if (!uuid.test(basis) || (!revoked && !uuid.test(subject)) || (expiry && !zonedTime.test(expiry))) {
    ui.status.textContent = "请填写有效的员工及依据编号；截止时间必须带时区。";
    return;
  }
  const body = JSON.stringify({
    expected_generation: snapshot.generation, responsible_id: subject, basis_id: basis,
    ...(expiry ? { expires_at: expiry } : {}),
  });
  if (session.command?.body !== body) session.command = { body, key: crypto.randomUUID() };
  send(snapshot.documentRef, session.command, receipt => {
    if (receipt.generation !== snapshot.generation + 1 || !uuid.test(receipt.assignment_id)) {
      throw new TypeError("Invalid responsibility receipt.");
    }
    clearSnapshot();
    ui.status.textContent = `已登记责任决定（代次 ${receipt.generation}）。`;
    ui.receipt.textContent = `决定编号：${receipt.assignment_id}`;
  });
});

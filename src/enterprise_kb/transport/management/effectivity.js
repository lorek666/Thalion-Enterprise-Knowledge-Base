const ui = Object.fromEntries([
  "lock", "lock-message", "access", "token", "workspace", "logout", "form", "version",
  "submit", "status", "receipt", "decision", "request",
  "preview-btn", "preview", "preview-summary", "preview-readiness", "preview-wiki", "preview-overlaps",
  "stop-form", "stop-version", "stop-kind", "stop-basis", "stop-reason",
  "stop-preview-btn", "stop-submit", "stop-status", "stop-impact",
  "conflict-form", "conflict-version", "conflict-existing", "conflict-start", "conflict-end",
  "conflict-region", "conflict-traveler", "conflict-basis", "conflict-summary",
  "conflict-submit", "conflict-status", "conflict-query-form", "conflict-document",
  "conflict-load", "conflict-list",
  "resolve-form", "resolve-id", "resolve-outcome", "resolve-basis", "resolve-linked",
  "resolve-conclusion", "resolve-submit", "resolve-status",
].map(name => [name, document.getElementById(`effectivity-${name}`)]));
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const errors = {
  400: "审批参数无效，请核对编号、日期和适用范围。",
  401: "凭据无效或已过期，请更换凭据。",
  403: "只有当前来源指定的审批人可以登记。",
  409: "与现有决定冲突，请核对日期、范围和被替代决定。",
  503: "审批服务暂不可用，请保留表单原样重试。",
};
const conflictErrors = {
  400: "争议或裁定参数无效，请核对编号、日期和说明。",
  401: "凭据无效或已过期，请更换凭据。",
  403: "只有当前来源指定的审批人或制度负责人可执行该操作。",
  409: "争议记录不存在真实范围重叠、已裁定或幂等键冲突。",
  503: "服务暂不可用，请保留表单原样重试。",
};
const unknownResult = "未收到审批结果，请保留表单原样重试。";
let session = null;

function clearList(element) {
  while (element.firstChild) element.removeChild(element.firstChild);
}

function appendItem(list, text) {
  const item = document.createElement("li");
  item.textContent = text;
  list.appendChild(item);
  return item;
}

function clearReceipt() {
  ui.receipt.hidden = true;
  ui.decision.textContent = "";
  ui.request.textContent = "";
  ui.status.textContent = "";
}

function clearPreview() {
  ui.preview.hidden = true;
  ui["preview-summary"].textContent = "";
  ui["preview-readiness"].textContent = "";
  clearList(ui["preview-wiki"]);
  clearList(ui["preview-overlaps"]);
}

function clearExtraPanels() {
  clearPreview();
  ui["stop-form"].reset();
  ui["stop-form"].inert = false;
  ui["stop-submit"].disabled = false;
  ui["stop-preview-btn"].disabled = false;
  ui["stop-status"].textContent = "";
  clearList(ui["stop-impact"]);
  ui["conflict-form"].reset();
  ui["conflict-form"].inert = false;
  ui["conflict-submit"].disabled = false;
  ui["conflict-status"].textContent = "";
  ui["conflict-query-form"].reset();
  clearList(ui["conflict-list"]);
  ui["resolve-form"].reset();
  ui["resolve-form"].inert = false;
  ui["resolve-submit"].disabled = false;
  ui["resolve-status"].textContent = "";
}

function lock(message = "") {
  session?.pending?.abort();
  session = null;
  ui.form.reset();
  ui.form.inert = false;
  ui.submit.disabled = false;
  ui["preview-btn"].disabled = false;
  ui.token.value = "";
  ui.workspace.hidden = true;
  ui.lock.hidden = false;
  ui["lock-message"].textContent = message;
  clearReceipt();
  clearExtraPanels();
}

ui.access.addEventListener("submit", event => {
  event.preventDefault();
  if (session) return;
  const token = ui.token.value.trim();
  if (!token) {
    ui["lock-message"].textContent = "请输入管理测试凭据。";
    return;
  }
  session = { token };
  ui.token.value = "";
  ui["lock-message"].textContent = "";
  ui.lock.hidden = true;
  ui.workspace.hidden = false;
  ui.version.focus();
});

ui.logout.addEventListener("click", () => {
  lock();
  ui.token.focus();
});
window.addEventListener("pagehide", () => lock());
window.addEventListener("pageshow", event => {
  if (event.persisted) lock("页面已重新锁定，请载入审批凭据。");
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) lock("页面已锁定，请重新载入审批凭据。");
});
ui.form.addEventListener("input", clearReceipt);

ui["preview-btn"].addEventListener("click", async () => {
  const activeSession = session;
  if (!activeSession || activeSession.pending) return;
  clearPreview();
  const { version, basis_id: _ignoredBasis, ...argumentsByName } = Object.fromEntries(
    Array.from(new FormData(ui.form), ([name, value]) => [name, value.trim()]).filter(([, value]) => value),
  );
  if (!version || !uuid.test(version) || !argumentsByName.valid_from ||
      (argumentsByName.replaces_id && !uuid.test(argumentsByName.replaces_id))) {
    ui.status.textContent = "预览换版需要有效的版本编号与生效日期。";
    return;
  }
  const pending = new AbortController();
  activeSession.pending = pending;
  ui.form.inert = true;
  ui["preview-btn"].disabled = true;
  ui.submit.disabled = true;
  ui.status.textContent = "正在预览切换日期与受影响主题…";
  try {
    const response = await fetch(`/internal/sources/versions/${version}/effectivity-preview`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${activeSession.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(argumentsByName),
      signal: pending.signal,
    });
    if (session !== activeSession) return;
    if (!response.ok) {
      ui.status.textContent = errors[response.status] || unknownResult;
      return;
    }
    const data = await response.json();
    if (session !== activeSession) return;
    ui["preview-summary"].textContent =
      `切换日期：${data.switch_date}｜文档：${data.document_id}｜替代关系：${data.replacement_status}｜未决争议：${data.open_conflict_count}`;
    ui["preview-readiness"].textContent = data.insufficient_evidence_notice
      ? `就绪状态：${data.processing_readiness}（${data.insufficient_evidence_notice}）`
      : `就绪状态：${data.processing_readiness}（已完成解析与质控批准）`;
    if (data.affected_wiki_topics.length === 0) {
      appendItem(ui["preview-wiki"], "受影响主题页：暂无已发布主题页引用此文档。");
    } else {
      for (const topic of data.affected_wiki_topics) {
        appendItem(
          ui["preview-wiki"],
          `受影响主题：${topic.topic_key}（第 ${topic.generation} 代，影响：${topic.impact_kind}）`,
        );
      }
    }
    if (data.overlapping_decisions.length === 0) {
      appendItem(ui["preview-overlaps"], "适用范围重叠检查：未发现未声明替代的重叠决定。");
    } else {
      for (const overlap of data.overlapping_decisions) {
        const range = `${overlap.valid_from} 至 ${overlap.effective_to || "无截止"}`;
        const scopeText = `地区=${overlap.region || "不限"}，类别=${overlap.traveler_class || "不限"}`;
        appendItem(
          ui["preview-overlaps"],
          `重叠决定：${overlap.decision_id}（${overlap.overlap_kind}，${range}，${scopeText}）`,
        );
      }
    }
    ui.preview.hidden = false;
    ui.status.textContent = "已加载换版影响预览。";
  } catch {
    if (session === activeSession) ui.status.textContent = unknownResult;
  } finally {
    if (session === activeSession) {
      activeSession.pending = null;
      ui.form.inert = false;
      ui["preview-btn"].disabled = false;
      ui.submit.disabled = false;
    }
  }
});

ui.form.addEventListener("submit", async event => {
  event.preventDefault();
  const activeSession = session;
  if (!activeSession || activeSession.pending) return;
  clearReceipt();
  const { version, ...argumentsByName } = Object.fromEntries(
    Array.from(new FormData(ui.form), ([name, value]) => [name, value.trim()]).filter(([, value]) => value),
  );
  if (!version || !uuid.test(version) || !uuid.test(argumentsByName.basis_id || "") ||
      (argumentsByName.replaces_id && !uuid.test(argumentsByName.replaces_id))) {
    ui.status.textContent = "请输入有效的版本、依据及被替代决定编号。";
    return;
  }
  const path = `/internal/sources/versions/${version}/effectivity`;
  const body = JSON.stringify(argumentsByName);
  if (activeSession.command?.path !== path || activeSession.command.body !== body) {
    activeSession.command = { path, body, key: crypto.randomUUID() };
  }
  const pending = new AbortController();
  activeSession.pending = pending;
  ui.form.inert = true;
  ui.submit.disabled = true;
  ui.status.textContent = "正在登记生效决定…";
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${activeSession.token}`,
        "Content-Type": "application/json",
        "Idempotency-Key": activeSession.command.key,
      },
      body,
      signal: pending.signal,
    });
    if (session !== activeSession) return;
    if (!response.ok) {
      ui.status.textContent = errors[response.status] || unknownResult;
      return;
    }
    const receipt = await response.json();
    if (session !== activeSession) return;
    if (!receipt || !uuid.test(receipt.decision_id) || !uuid.test(receipt.request_id)) {
      ui.status.textContent = unknownResult;
      return;
    }
    ui.decision.textContent = receipt.decision_id;
    ui.request.textContent = receipt.request_id;
    ui.receipt.hidden = false;
    ui.status.textContent = "已登记生效决定。";
  } catch {
    if (session === activeSession) ui.status.textContent = unknownResult;
  } finally {
    if (session === activeSession) {
      activeSession.pending = null;
      ui.form.inert = false;
      ui["preview-btn"].disabled = false;
      ui.submit.disabled = false;
    }
  }
});

ui["stop-preview-btn"].addEventListener("click", async () => {
  const activeSession = session;
  if (!activeSession || activeSession.pending) return;
  clearList(ui["stop-impact"]);
  const version = ui["stop-version"].value.trim();
  const kind = ui["stop-kind"].value;
  if (!uuid.test(version)) {
    ui["stop-status"].textContent = "请输入有效的待撤回/暂停版本编号。";
    return;
  }
  const pending = new AbortController();
  activeSession.pending = pending;
  ui["stop-form"].inert = true;
  ui["stop-preview-btn"].disabled = true;
  ui["stop-submit"].disabled = true;
  ui["stop-status"].textContent = "正在计算撤回/暂停影响范围…";
  try {
    const response = await fetch(`/internal/sources/versions/${version}/stop-preview`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${activeSession.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ kind }),
      signal: pending.signal,
    });
    if (session !== activeSession) return;
    if (!response.ok) {
      ui["stop-status"].textContent = errors[response.status] || unknownResult;
      return;
    }
    const data = await response.json();
    if (session !== activeSession) return;
    appendItem(
      ui["stop-impact"],
      `停止片段检索：是｜关联生效决定：${data.active_decisions.length} 条｜已停用：${data.already_stopped ? "是" : "否"}`,
    );
    if (data.affected_wiki_topics.length === 0) {
      appendItem(ui["stop-impact"], "受影响已发布主题页：0 个。");
    } else {
      for (const topic of data.affected_wiki_topics) {
        appendItem(
          ui["stop-impact"],
          `将立即停用主题：${topic.topic_key}（第 ${topic.generation} 代）`,
        );
      }
    }
    ui["stop-status"].textContent = "已加载撤回影响预览，请填写原因后确认执行。";
  } catch {
    if (session === activeSession) ui["stop-status"].textContent = unknownResult;
  } finally {
    if (session === activeSession) {
      activeSession.pending = null;
      ui["stop-form"].inert = false;
      ui["stop-preview-btn"].disabled = false;
      ui["stop-submit"].disabled = false;
    }
  }
});

ui["stop-form"].addEventListener("submit", async event => {
  event.preventDefault();
  const activeSession = session;
  if (!activeSession || activeSession.pending) return;
  clearList(ui["stop-impact"]);
  const version = ui["stop-version"].value.trim();
  const kind = ui["stop-kind"].value;
  const basisId = ui["stop-basis"].value.trim();
  const reason = ui["stop-reason"].value.trim();
  if (!uuid.test(version) || !uuid.test(basisId) || !reason) {
    ui["stop-status"].textContent = "请填写有效的版本编号、停用依据编号和撤回原因。";
    return;
  }
  const path = `/internal/sources/versions/${version}/stop`;
  const body = JSON.stringify({ kind, basis_id: basisId, reason });
  if (activeSession.stopCommand?.path !== path || activeSession.stopCommand.body !== body) {
    activeSession.stopCommand = { path, body, key: crypto.randomUUID() };
  }
  const pending = new AbortController();
  activeSession.pending = pending;
  ui["stop-form"].inert = true;
  ui["stop-preview-btn"].disabled = true;
  ui["stop-submit"].disabled = true;
  ui["stop-status"].textContent = "正在执行撤回/暂停并停用受影响主题…";
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${activeSession.token}`,
        "Content-Type": "application/json",
        "Idempotency-Key": activeSession.stopCommand.key,
      },
      body,
      signal: pending.signal,
    });
    if (session !== activeSession) return;
    if (!response.ok) {
      ui["stop-status"].textContent = errors[response.status] || unknownResult;
      return;
    }
    const receipt = await response.json();
    if (session !== activeSession) return;
    ui["stop-status"].textContent = `已执行 ${receipt.kind}，决定编号：${receipt.decision_id}`;
    for (const topic of receipt.affected_wiki_topics || []) {
      appendItem(ui["stop-impact"], `已停用主题：${topic.topic_key}（原因：${topic.reason}）`);
    }
  } catch {
    if (session === activeSession) ui["stop-status"].textContent = unknownResult;
  } finally {
    if (session === activeSession) {
      activeSession.pending = null;
      ui["stop-form"].inert = false;
      ui["stop-preview-btn"].disabled = false;
      ui["stop-submit"].disabled = false;
    }
  }
});

ui["conflict-form"].addEventListener("submit", async event => {
  event.preventDefault();
  const activeSession = session;
  if (!activeSession || activeSession.pending) return;
  const { version, ...argumentsByName } = Object.fromEntries(
    Array.from(new FormData(ui["conflict-form"]), ([name, value]) => [name, value.trim()]).filter(([, value]) => value),
  );
  if (!uuid.test(version || "") || !uuid.test(argumentsByName.existing_decision_id || "") ||
      !uuid.test(argumentsByName.basis_id || "") || !argumentsByName.valid_from || !argumentsByName.summary) {
    ui["conflict-status"].textContent = "请填写有效的候选版本、重叠决定、生效日期、依据编号与争议说明。";
    return;
  }
  const path = `/internal/sources/versions/${version}/effectivity-conflicts`;
  const body = JSON.stringify(argumentsByName);
  if (activeSession.conflictCommand?.path !== path || activeSession.conflictCommand.body !== body) {
    activeSession.conflictCommand = { path, body, key: crypto.randomUUID() };
  }
  const pending = new AbortController();
  activeSession.pending = pending;
  ui["conflict-form"].inert = true;
  ui["conflict-submit"].disabled = true;
  ui["conflict-status"].textContent = "正在登记重叠争议记录…";
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${activeSession.token}`,
        "Content-Type": "application/json",
        "Idempotency-Key": activeSession.conflictCommand.key,
      },
      body,
      signal: pending.signal,
    });
    if (session !== activeSession) return;
    if (!response.ok) {
      ui["conflict-status"].textContent = conflictErrors[response.status] || unknownResult;
      return;
    }
    const receipt = await response.json();
    if (session !== activeSession) return;
    ui["conflict-status"].textContent = `已登记重叠争议：${receipt.conflict_id}（文档：${receipt.document_id}）`;
    ui["conflict-document"].value = receipt.document_id;
    ui["resolve-id"].value = receipt.conflict_id;
  } catch {
    if (session === activeSession) ui["conflict-status"].textContent = unknownResult;
  } finally {
    if (session === activeSession) {
      activeSession.pending = null;
      ui["conflict-form"].inert = false;
      ui["conflict-submit"].disabled = false;
    }
  }
});

ui["conflict-query-form"].addEventListener("submit", async event => {
  event.preventDefault();
  const activeSession = session;
  if (!activeSession || activeSession.pending) return;
  clearList(ui["conflict-list"]);
  const documentId = ui["conflict-document"].value.trim();
  if (!uuid.test(documentId)) {
    ui["conflict-status"].textContent = "请输入有效的文档编号。";
    return;
  }
  const pending = new AbortController();
  activeSession.pending = pending;
  ui["conflict-status"].textContent = "正在加载文档重叠争议记录…";
  try {
    const response = await fetch(`/internal/sources/documents/${documentId}/effectivity-conflicts`, {
      method: "GET",
      headers: { "Authorization": `Bearer ${activeSession.token}` },
      signal: pending.signal,
    });
    if (session !== activeSession) return;
    if (!response.ok) {
      ui["conflict-status"].textContent = conflictErrors[response.status] || unknownResult;
      return;
    }
    const data = await response.json();
    if (session !== activeSession) return;
    if (!data.conflicts || data.conflicts.length === 0) {
      appendItem(ui["conflict-list"], "当前文档无重叠争议记录。");
    } else {
      for (const item of data.conflicts) {
        const stateText = item.status === "resolved"
          ? `已裁定（${item.resolution.outcome}：${item.resolution.conclusion}）`
          : "待制度负责人裁定";
        appendItem(
          ui["conflict-list"],
          `争议 ${item.conflict_id}｜状态：${stateText}｜现有决定：${item.existing_decision_id}｜说明：${item.summary}`,
        );
      }
    }
    ui["conflict-status"].textContent = `已加载 ${data.conflicts.length} 条争议记录。`;
  } catch {
    if (session === activeSession) ui["conflict-status"].textContent = unknownResult;
  } finally {
    if (session === activeSession) activeSession.pending = null;
  }
});

ui["resolve-form"].addEventListener("submit", async event => {
  event.preventDefault();
  const activeSession = session;
  if (!activeSession || activeSession.pending) return;
  const { conflict_id: conflictId, ...argumentsByName } = Object.fromEntries(
    Array.from(new FormData(ui["resolve-form"]), ([name, value]) => [name, value.trim()]).filter(([, value]) => value),
  );
  if (!uuid.test(conflictId || "") || !uuid.test(argumentsByName.basis_id || "") ||
      (argumentsByName.linked_decision_id && !uuid.test(argumentsByName.linked_decision_id)) ||
      !argumentsByName.conclusion) {
    ui["resolve-status"].textContent = "请填写有效的争议编号、裁定依据编号和结论说明。";
    return;
  }
  const path = `/internal/sources/effectivity-conflicts/${conflictId}/resolution`;
  const body = JSON.stringify(argumentsByName);
  if (activeSession.resolveCommand?.path !== path || activeSession.resolveCommand.body !== body) {
    activeSession.resolveCommand = { path, body, key: crypto.randomUUID() };
  }
  const pending = new AbortController();
  activeSession.pending = pending;
  ui["resolve-form"].inert = true;
  ui["resolve-submit"].disabled = true;
  ui["resolve-status"].textContent = "正在提交争议裁定结论…";
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${activeSession.token}`,
        "Content-Type": "application/json",
        "Idempotency-Key": activeSession.resolveCommand.key,
      },
      body,
      signal: pending.signal,
    });
    if (session !== activeSession) return;
    if (!response.ok) {
      ui["resolve-status"].textContent = conflictErrors[response.status] || unknownResult;
      return;
    }
    const receipt = await response.json();
    if (session !== activeSession) return;
    ui["resolve-status"].textContent = `已记录裁定结论：${receipt.resolution_id}（${receipt.outcome}）`;
  } catch {
    if (session === activeSession) ui["resolve-status"].textContent = unknownResult;
  } finally {
    if (session === activeSession) {
      activeSession.pending = null;
      ui["resolve-form"].inert = false;
      ui["resolve-submit"].disabled = false;
    }
  }
});

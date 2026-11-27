(() => {
  let token = "";

  function randomUuid() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
      return window.crypto.randomUUID();
    }
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (ch) => {
      const r = Math.floor(Math.random() * 16);
      return (ch === "x" ? r : (r & 0x3) | 0x8).toString(16);
    });
  }

  const el = (id) => document.getElementById(id);

  function clearScreen() {
    token = "";
    el("gov-token").value = "";
    el("gov-workspace").hidden = true;
    el("gov-lock").hidden = false;
    el("gov-status").textContent = "";
    el("gov-space-meta").textContent = "";
    el("gov-groups-list").replaceChildren();
    el("gov-delegations-list").replaceChildren();
    el("gov-receipts-list").replaceChildren();
    el("gov-group-result").textContent = "";
    el("gov-delegation-result").textContent = "";
    el("gov-transition-summary").textContent = "";
    el("gov-handoff-result").textContent = "";
  }

  async function apiRequest(path, method = "GET", body = null) {
    const headers = { Authorization: `Bearer ${token}` };
    const options = { method, headers, cache: "no-store" };
    if (body !== null) {
      headers["Content-Type"] = "application/json";
      headers["Idempotency-Key"] = `gov-${randomUuid()}`;
      options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = (data.error && data.error.message) || `HTTP ${response.status}`;
      throw new Error(message);
    }
    return data;
  }

  function renderOverview(data) {
    const sp = data.space;
    el("gov-space-meta").textContent =
      `空间 ${sp.name} (${sp.classification}) · 状态 ${sp.lifecycle} · 安全代次 ${sp.safety_epoch}`;
    el("gov-status").textContent =
      `已载入治理总览：共享组 ${data.shared_groups.length}，委派 ${data.delegations.length}，交接验收单 ${data.handoff_receipts.length}。`;

    const groupsBox = el("gov-groups-list");
    groupsBox.replaceChildren();
    for (const grp of data.shared_groups) {
      const card = document.createElement("div");
      card.className = "repair-change";
      const title = document.createElement("p");
      title.textContent = `${grp.name} [${grp.state}] · 用途 ${grp.purpose} · 组主体 ${grp.group_principal_id}`;
      const meta = document.createElement("p");
      meta.className = "repair-meta";
      meta.textContent = `范围 ${grp.scope_summary} · 复核日 ${grp.review_at} · 到期 ${grp.expires_at} · 成员 ${grp.members.length}`;
      card.append(title, meta);
      groupsBox.append(card);
    }

    const delBox = el("gov-delegations-list");
    delBox.replaceChildren();
    for (const del of data.delegations) {
      const card = document.createElement("div");
      card.className = "repair-change";
      const title = document.createElement("p");
      title.textContent = `委派 ${del.delegation_id} [${del.state}] · 代理人 ${del.delegate_id}`;
      const meta = document.createElement("p");
      meta.className = "repair-meta";
      meta.textContent = `权限 ${del.scopes.join(", ")} · 复核日 ${del.review_at} · 到期 ${del.expires_at}`;
      card.append(title, meta);
      delBox.append(card);
    }

    const recBox = el("gov-receipts-list");
    recBox.replaceChildren();
    for (const rec of data.handoff_receipts) {
      const card = document.createElement("div");
      card.className = "repair-change";
      const title = document.createElement("p");
      title.textContent = `验收单 ${rec.receipt_id} (${rec.transition_kind}) · 交接时间 ${rec.handed_off_at}`;
      const meta = document.createElement("p");
      meta.className = "repair-meta";
      meta.textContent =
        `复核日 ${rec.review_at} · 撤共享成员 ${rec.revoked_group_member_count} · 撤委派 ${rec.revoked_delegation_count} · 移交责任 ${rec.reassigned_document_count} · 剩余待办纠错 ${rec.remaining_open_feedback_count}`;
      card.append(title, meta);
      recBox.append(card);
    }
  }

  async function refreshOverview() {
    try {
      const data = await apiRequest("/internal/governance");
      renderOverview(data);
    } catch (err) {
      el("gov-status").textContent = `载入失败：${err.message}`;
    }
  }

  el("gov-access").addEventListener("submit", async (event) => {
    event.preventDefault();
    token = el("gov-token").value.trim();
    if (!token) return;
    el("gov-lock").hidden = true;
    el("gov-workspace").hidden = false;
    await refreshOverview();
  });

  el("gov-refresh").addEventListener("click", refreshOverview);
  el("gov-logout").addEventListener("click", clearScreen);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && token) clearScreen();
  });

  el("gov-group-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const data = await apiRequest("/internal/governance/shared-groups", "POST", {
        target_source_id: el("gov-group-source").value.trim(),
        name: el("gov-group-name").value.trim(),
        purpose: el("gov-group-purpose").value.trim(),
        scope_summary: el("gov-group-scope").value.trim(),
        starts_at: el("gov-group-start").value.trim(),
        review_at: el("gov-group-review").value.trim(),
        expires_at: el("gov-group-expiry").value.trim(),
        basis_id: el("gov-group-basis").value.trim(),
      });
      el("gov-group-result").textContent =
        `已创建限时共享组 ${data.group_id}（组主体 ${data.group_principal_id}）。`;
      await refreshOverview();
    } catch (err) {
      el("gov-group-result").textContent = `创建失败：${err.message}`;
    }
  });

  el("gov-delegation-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const scopes = Array.from(document.querySelectorAll('input[name="del_scope"]:checked')).map((i) => i.value);
    try {
      const data = await apiRequest("/internal/governance/delegations", "POST", {
        delegate_id: el("gov-del-delegate").value.trim(),
        scopes,
        purpose: el("gov-del-purpose").value.trim(),
        starts_at: el("gov-del-start").value.trim(),
        review_at: el("gov-del-review").value.trim(),
        expires_at: el("gov-del-expiry").value.trim(),
        basis_id: el("gov-del-basis").value.trim(),
      });
      el("gov-delegation-result").textContent = `已签发空间委派 ${data.delegation_id}。`;
      await refreshOverview();
    } catch (err) {
      el("gov-delegation-result").textContent = `签发失败：${err.message}`;
    }
  });

  el("gov-transition-lookup").addEventListener("submit", async (event) => {
    event.preventDefault();
    const emp = el("gov-trans-employee").value.trim();
    try {
      const data = await apiRequest(`/internal/governance/transitions/${encodeURIComponent(emp)}`);
      el("gov-transition-summary").textContent =
        `员工状态 ${data.employee_active ? "在职" : "停用"} · 生效资料责任 ${data.active_document_responsibilities.length} · 待办纠错 ${data.open_feedback_items.length} · 共享组成员 ${data.active_shared_group_memberships.length} · 有效委派 ${data.active_incoming_delegations.length}`;
    } catch (err) {
      el("gov-transition-summary").textContent = `核查失败：${err.message}`;
    }
  });

  el("gov-handoff-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const emp = el("gov-trans-employee").value.trim();
    const body = {
      transition_kind: el("gov-handoff-kind").value,
      review_at: el("gov-handoff-review").value.trim(),
      basis_id: el("gov-handoff-basis").value.trim(),
    };
    const suc = el("gov-handoff-successor").value.trim();
    if (suc) body.successor_id = suc;
    const del = el("gov-handoff-delegation").value.trim();
    if (del) body.delegation_id = del;
    try {
      const data = await apiRequest(`/internal/governance/transitions/${encodeURIComponent(emp)}/handoff`, "POST", body);
      el("gov-handoff-result").textContent =
        `已签发交接验收单 ${data.receipt_id}（复核日 ${data.review_at}，交接时间 ${data.handed_off_at}）。`;
      await refreshOverview();
    } catch (err) {
      el("gov-handoff-result").textContent = `办理失败：${err.message}`;
    }
  });
})();

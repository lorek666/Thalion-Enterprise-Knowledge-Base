const ui = Object.fromEntries([
  "lock", "access", "token", "lock-message", "workspace", "title", "lookup", "id", "id-value", "options",
  "refresh", "logout", "status", "sections",
].map(name => [name, document.getElementById(`sources-${name}`)]));

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const stages = { parse: "资料解析", synthetic_model_excerpts: "合成模型任务", other: "其他任务" };
const jobStates = {
  external_budget_blocked: "预算阻断", awaiting_external: "等待外部回执", retry_delayed: "延时重试",
  lease_expired: "租约已过期", inconsistent: "状态待核对", ready: "待领取", leased: "租约有效",
};
const warnStates = new Set(["external_budget_blocked", "awaiting_external", "lease_expired", "inconsistent"]);
const lifecycleLabels = { active: "启用中", suspended: "已停用" };
const admissionLabels = { synthetic_only: "本机合成范围", production_approved: "生产准入范围" };
const utcTime = new Intl.DateTimeFormat("zh-CN", {
  timeZone: "UTC", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit",
  minute: "2-digit", second: "2-digit", hourCycle: "h23",
});
let session = null;
let sourceTimer = null;

function clearSourceOptions() {
  session?.search?.abort();
  if (session) session.search = null;
  clearTimeout(sourceTimer);
  sourceTimer = null;
  ui["id-value"].value = "";
  ui.options.hidden = true;
  ui.options.replaceChildren();
}

async function searchSources(query) {
  const owner = session;
  if (owner === null || !query || uuidPattern.test(query)) return;
  owner.search?.abort();
  const controller = new AbortController();
  owner.search = controller;
  const current = () => session === owner && owner.search === controller && !controller.signal.aborted;
  ui.status.textContent = "正在搜索可查看的文件库…";
  try {
    const response = await fetch(`/internal/sources/options?usage=sync&q=${encodeURIComponent(query)}&limit=20`, {
      headers: { Authorization: `Bearer ${owner.token}` }, signal: controller.signal,
      cache: "no-store", credentials: "omit", mode: "same-origin", redirect: "error", referrerPolicy: "no-referrer",
    });
    if (!current()) return;
    if (response.status === 401) return lock("凭据无效或已过期，请重新载入。", true);
    if (response.status === 403) {
      ui.status.textContent = "当前凭据不能搜索可查看的文件库。";
      return;
    }
    if (!response.ok) throw new Error("Source options are unavailable.");
    const data = await response.json();
    if (!current()) return;
    if (!Array.isArray(data.sources) || data.sources.length > 20) throw new TypeError("Invalid source options.");
    const options = data.sources.map(source => {
      if (!uuidPattern.test(source.id) || typeof source.name !== "string" || typeof source.status !== "string") {
        throw new TypeError("Invalid source option.");
      }
      const button = document.createElement("button");
      button.type = "button";
      button.className = "quiet-button";
      button.setAttribute("role", "option");
      button.textContent = `${source.name} · ${lifecycleLabels[source.status] ?? source.status}`;
      button.addEventListener("click", () => {
        if (session !== owner) return;
        ui.id.value = source.name;
        clearSourceOptions();
        ui["id-value"].value = source.id;
        load(source.id);
      });
      return button;
    });
    ui.options.replaceChildren(...options);
    ui.options.hidden = options.length === 0;
    ui.status.textContent = options.length ? "请选择要查看同步状态的文件库。" : "没有找到可查看的文件库。";
  } catch {
    if (current()) ui.status.textContent = "暂时无法搜索文件库，请稍后重试。";
  } finally {
    if (current()) owner.search = null;
  }
}

function text(tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = String(value);
  if (className) node.className = className;
  return node;
}

function formatUtc(isoString) {
  return `${utcTime.format(new Date(isoString))} UTC`;
}

function ageLabel(ageMs) {
  const minutes = Math.floor(ageMs / 60_000);
  if (!minutes) return "不足 1 分钟";
  const hours = Math.floor(minutes / 60);
  return hours ? `${hours} 小时 ${minutes % 60} 分钟` : `${minutes} 分钟`;
}

function metric(label, value, warning = false) {
  const item = document.createElement("div");
  const name = text("dt", label, warning ? "wiki-state" : "");
  if (warning) name.dataset.state = "needs_rebuild";
  item.append(name, text("dd", value));
  return item;
}

function detailLine(label, value) {
  const line = text("p", "", "wiki-generation repair-meta");
  line.append(text("strong", label), " ", text("span", value));
  return line;
}

function badge(label, warning = false) {
  const pill = text("span", label, "wiki-state");
  if (warning) pill.dataset.state = "needs_rebuild";
  return pill;
}

function resetSnapshot() {
  ui.sections.replaceChildren();
  ui.sections.setAttribute("aria-busy", "false");
  ui.status.textContent = "";
}

function lock(message = "", focus = false) {
  if (session !== null) {
    session.pending?.abort();
    session.search?.abort();
    session.token = "";
    session.sourceId = "";
  }
  session = null;
  clearSourceOptions();
  ui.token.value = "";
  ui.id.value = "";
  ui.refresh.hidden = true;
  resetSnapshot();
  ui.workspace.hidden = true;
  ui.lock.hidden = false;
  ui["lock-message"].textContent = message;
  if (focus) ui.token.focus();
}

function card(title, subtitle = "") {
  const item = text("li", "", "wiki-topic");
  const heading = text("div", "", "wiki-topic-header");
  heading.append(text("h3", title));
  if (subtitle) heading.append(text("span", subtitle, "wiki-generation"));
  item.append(heading);
  return item;
}

function renderContractCard(data) {
  const item = card("来源契约与状态", `契约修订 v${data.contract_revision}`);
  const suspended = data.lifecycle !== "active";
  item.append(badge(lifecycleLabels[data.lifecycle] ?? data.lifecycle, suspended));
  const grid = text("dl", "", "wiki-counts");
  grid.append(
    metric("准入范围", admissionLabels[data.admission] ?? data.admission),
    metric("当前契约修订", `v${data.contract_revision}`),
  );
  item.append(grid, detailLine("来源编号", data.source_id));
  return item;
}

function renderContentCard(content) {
  const item = card("内容分页水位", content ? `第 ${content.sequence} 页` : "尚未提交");
  if (!content) {
    item.append(text("p", "当前契约修订尚未提交内容分页。", "wiki-generation"));
    return item;
  }
  const grid = text("dl", "", "wiki-counts");
  grid.append(
    metric("分页序号", content.sequence),
    metric("本页登记条目", content.item_count),
  );
  item.append(
    grid,
    detailLine("内容游标", content.through_cursor),
    detailLine("提交时刻", formatUtc(content.committed_at)),
  );
  return item;
}

function renderInventoryCard(inventory) {
  const item = card("完整盘点对账", inventory ? `第 ${inventory.sequence} 次盘点` : "尚未完成");
  if (!inventory) {
    item.append(text("p", "当前契约修订尚未记录完整盘点对账。", "wiki-generation"));
    return item;
  }
  const counts = inventory.difference_counts;
  const totalDiffs = counts.version_not_registered + counts.digest_mismatch + counts.not_enumerated;
  if (totalDiffs > 0) item.append(badge(`存在 ${totalDiffs} 项盘点差异`, true));
  const grid = text("dl", "", "wiki-counts");
  grid.append(
    metric("清单条目数", inventory.entry_count),
    metric("完全匹配数", inventory.matched_count),
    metric("版本未登记", counts.version_not_registered, counts.version_not_registered > 0),
    metric("摘要不符", counts.digest_mismatch, counts.digest_mismatch > 0),
    metric("未在清单出现", counts.not_enumerated, counts.not_enumerated > 0),
  );
  item.append(
    grid,
    detailLine("盘点快照", inventory.snapshot_ref),
    detailLine("关联内容位置", inventory.content_position ?? "无（空内容位置）"),
    detailLine("盘点时刻", formatUtc(inventory.committed_at)),
    text("p", "未在清单出现仅表示待核对，不代表自动删除。", "wiki-generation"),
  );
  return item;
}

function renderPermissionAndRestrictionsCard(checkpoint, receipts) {
  const item = card(
    "独立权限确认点与显式收紧回执",
    checkpoint ? `确认点 #${checkpoint.sequence}` : "尚未登记确认点",
  );
  const acknowledgedInCheckpoint = checkpoint ? checkpoint.acknowledged_count : 0;
  const checkpointLastGen = checkpoint?.last_acknowledged_generation ?? 0;
  const latestRevGen = receipts.latest_authority_generation ?? 0;
  if (receipts.by_kind.permission_revoked > acknowledgedInCheckpoint || latestRevGen > checkpointLastGen) {
    item.append(badge("存在尚未并入权限确认点的撤权回执", true));
  }
  const grid = text("dl", "", "wiki-counts");
  grid.append(
    metric("权限权威代次", checkpoint ? checkpoint.authority_generation : "未登记"),
    metric("确认点已涵盖撤权", checkpoint ? checkpoint.acknowledged_count : 0),
    metric("显式收紧回执总数", receipts.total),
    metric("主动撤回", receipts.by_kind.withdrawn),
    metric("删除阻断", receipts.by_kind.deleted),
    metric("源端撤权回执", receipts.by_kind.permission_revoked),
  );
  item.append(grid);
  if (checkpoint) {
    item.append(
      detailLine("权限确认点", checkpoint.checkpoint_ref),
      detailLine("确认时契约修订", `v${checkpoint.contract_revision}`),
      detailLine("最后确认撤权代次", checkpoint.last_acknowledged_generation ?? "无"),
      detailLine("确认时刻", formatUtc(checkpoint.committed_at)),
    );
  } else {
    item.append(text("p", "尚未登记独立权限确认点；交付时仍强制执行实时权威终检。", "wiki-generation"));
  }
  if (receipts.latest_committed_at) {
    item.append(detailLine("最近收紧回执时刻", formatUtc(receipts.latest_committed_at)));
  }
  return item;
}

function renderProcessingCard(processing) {
  const item = card("受影响资料、质控与入库异常");
  const grid = text("dl", "", "wiki-counts");
  grid.append(
    metric("登记文档", processing.registered_documents),
    metric("登记版本", processing.registered_versions),
    metric("当前契约版本", processing.current_contract_versions),
    metric("已阻断版本", processing.blocked_versions, processing.blocked_versions > 0),
    metric("待质控复核", processing.pending_quality_reviews, processing.pending_quality_reviews > 0),
    metric("待审核 OCR 页", processing.pending_ocr_review_pages, processing.pending_ocr_review_pages > 0),
    metric("已隔离版本", processing.quarantined_versions, processing.quarantined_versions > 0),
    metric("入库拒收项", processing.rejected_ingest_items, processing.rejected_ingest_items > 0),
    metric("待确认入库项", processing.needs_confirmation_ingest_items, processing.needs_confirmation_ingest_items > 0),
  );
  item.append(grid);
  return item;
}

function renderStageRow(stage, backlog, throughput) {
  const item = card(stages[stage] ?? stages.other, `未完成 ${backlog?.unfinished ?? 0}`);
  const counters = text("dl", "", "wiki-counts");
  counters.append(
    metric("近一小时已知入队", throughput?.enqueued ?? 0),
    metric("近一小时成功完成", throughput?.succeeded ?? 0),
  );
  for (const [state, label] of Object.entries(jobStates)) {
    const count = backlog?.states[state];
    if (count) counters.append(metric(label, count, warnStates.has(state)));
  }
  const age = backlog?.oldest_known_age_ms;
  if (age != null) counters.append(metric("最长已知队龄", ageLabel(age)));
  if (backlog?.unknown_enqueue_time) {
    counters.append(metric("入队时间未知", backlog.unknown_enqueue_time));
  }
  item.append(counters);
  if (backlog?.next_retry_at) {
    item.append(detailLine("最早计划重试", formatUtc(backlog.next_retry_at)));
  }
  return item;
}

async function load(sourceId) {
  const owner = session;
  if (owner === null) return;
  const normalized = sourceId.trim();
  owner.pending?.abort();
  owner.pending = null;
  if (!uuidPattern.test(normalized)) {
    owner.sourceId = "";
    ui.refresh.hidden = true;
    resetSnapshot();
    ui.status.textContent = "请输入完整的来源 UUID。";
    return;
  }
  owner.sourceId = normalized;
  const controller = new AbortController();
  owner.pending = controller;
  const current = () => session === owner && owner.pending === controller && !controller.signal.aborted;
  resetSnapshot();
  ui.sections.setAttribute("aria-busy", "true");
  ui.status.textContent = "正在读取来源同步状态…";
  try {
    const response = await fetch(`/internal/sources/${normalized}/sync-status`, {
      headers: { Authorization: `Bearer ${owner.token}` }, signal: controller.signal, cache: "no-store",
      credentials: "omit", mode: "same-origin", redirect: "error", referrerPolicy: "no-referrer",
    });
    if (!current()) return;
    if (response.status === 401) return lock("凭据无效或已过期，请重新载入。", true);
    if (response.status === 403) {
      ui.refresh.hidden = true;
      ui.status.textContent = "当前凭据无权查看该来源的同步状态。";
      return;
    }
    if (response.status === 400) {
      ui.refresh.hidden = true;
      ui.status.textContent = "来源编号格式无效，请核对后重试。";
      return;
    }
    if (!response.ok) throw new Error("Source sync status is unavailable.");
    const data = await response.json();
    if (!current()) return;
    const cards = [
      renderContractCard(data),
      renderContentCard(data.content_sync),
      renderInventoryCard(data.inventory_reconciliation),
      renderPermissionAndRestrictionsCard(data.permission_checkpoint, data.restriction_receipts),
      renderProcessingCard(data.processing_and_review),
    ];
    const unfinished = new Map(data.job_backlog_by_stage.map(entry => [entry.stage, entry]));
    const recent = new Map(data.job_throughput_by_stage.map(entry => [entry.stage, entry]));
    const stageCards = Object.keys(stages)
      .filter(stage => unfinished.has(stage) || recent.has(stage))
      .map(stage => renderStageRow(stage, unfinished.get(stage), recent.get(stage)));
    if (stageCards.length) {
      cards.push(...stageCards);
    } else {
      const emptyJobs = card("来源任务积压", "未完成 0");
      emptyJobs.append(text("p", "该来源暂无未完成或近一小时任务。", "wiki-generation"));
      cards.push(emptyJobs);
    }
    ui.sections.replaceChildren(...cards);
    ui.refresh.hidden = false;
    ui.status.textContent = `快照 ${formatUtc(data.observed_at)}`;
  } catch {
    if (current()) ui.status.textContent = "暂时无法读取来源同步状态，请刷新重试。";
  } finally {
    if (current()) {
      ui.sections.setAttribute("aria-busy", "false");
      owner.pending = null;
    }
  }
}

ui.access.addEventListener("submit", event => {
  event.preventDefault();
  const token = ui.token.value.trim();
  lock();
  if (!/^[A-Za-z0-9_.-]{32,16384}$/.test(token)) return lock("请输入完整的本机管理测试凭据。", true);
  session = { token, sourceId: "", pending: null };
  ui.lock.hidden = true;
  ui.workspace.hidden = false;
  ui.id.focus();
});
ui.id.addEventListener("input", () => {
  if (!session) return;
  session.pending?.abort();
  session.pending = null;
  clearSourceOptions();
  session.sourceId = "";
  ui.refresh.hidden = true;
  resetSnapshot();
  if (!uuidPattern.test(ui.id.value.trim())) {
    sourceTimer = setTimeout(() => searchSources(ui.id.value.trim()), 180);
  }
});
ui.lookup.addEventListener("submit", event => {
  event.preventDefault();
  if (!session) return;
  const query = ui.id.value.trim();
  const sourceId = ui["id-value"].value || query;
  if (!uuidPattern.test(sourceId)) {
    searchSources(query);
    return;
  }
  clearSourceOptions();
  ui["id-value"].value = sourceId;
  load(sourceId);
});
ui.refresh.addEventListener("click", () => {
  if (session?.sourceId) load(session.sourceId);
});
ui.logout.addEventListener("click", () => lock("已退出，凭据与快照已清除。", true));
window.addEventListener("pagehide", () => lock());
window.addEventListener("pageshow", event => {
  if (event.persisted) lock("页面已重新锁定，请载入凭据。");
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) lock("页面已锁定，请重新载入凭据。");
});
lock();

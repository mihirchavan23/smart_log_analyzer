/**
 * Phase 5 Dashboard Logic
 * Connects to live Backend APIs:
 * - GET /api/stats
 * - GET /api/anomalies/history
 * - GET /api/batches
 * - POST /api/generate
 * - POST /api/analyze
 * - POST /api/analyze/batch
 * - POST /api/anomalies/:id/explain
 */

let allAnomalies = [];
let allBatches = [];
let selectedAnomaly = null;
let currentBatchInfo = null;

// DOM Elements
const statTotalLogs = document.getElementById("stat-total-logs");
const statCurrentBatchFooter = document.getElementById("stat-current-batch-footer");
const statTotalAnomalies = document.getElementById("stat-total-anomalies");
const statAnomalyRate = document.getElementById("stat-anomaly-rate");
const statNormalLogs = document.getElementById("stat-normal-logs");
const statNormalRate = document.getElementById("stat-normal-rate");
const statTotalBatches = document.getElementById("stat-total-batches");
const badgeAnomalyCount = document.getElementById("badge-anomaly-count");
const badgeBatchCount = document.getElementById("badge-batch-count");

// Current Batch Banner
const currentBatchBanner = document.getElementById("current-batch-banner");
const bannerBatchId = document.getElementById("banner-batch-id");
const bannerBatchGenerated = document.getElementById("banner-batch-generated");
const bannerBatchAnomalies = document.getElementById("banner-batch-anomalies");
const bannerBatchRate = document.getElementById("banner-batch-rate");

const anomaliesTableBody = document.getElementById("anomalies-table-body");
const batchesTableBody = document.getElementById("batches-table-body");
const filterType = document.getElementById("filter-type");
const searchInput = document.getElementById("search-input");

// Modal Elements
const detailModal = document.getElementById("detail-modal");
const modalClose = document.getElementById("modal-close");
const modalCloseFooter = document.getElementById("modal-close-footer");
const modalTitle = document.getElementById("modal-title");
const modalTypeBadge = document.getElementById("modal-type-badge");
const modalScoreValue = document.getElementById("modal-score-value");
const modalScoreBar = document.getElementById("modal-score-bar");
const modalReasonsList = document.getElementById("modal-reasons-list");
const modalEvidenceGrid = document.getElementById("modal-evidence-grid");

const featIp = document.getElementById("feat-ip");
const featFailure = document.getElementById("feat-failure");
const featStatus = document.getElementById("feat-status");
const featLatency = document.getElementById("feat-latency");
const featError = document.getElementById("feat-error");

const barFeatIp = document.getElementById("bar-feat-ip");
const barFeatFailure = document.getElementById("bar-feat-failure");
const barFeatStatus = document.getElementById("bar-feat-status");
const barFeatLatency = document.getElementById("bar-feat-latency");
const barFeatError = document.getElementById("bar-feat-error");

// AI Elements
const btnTriggerAi = document.getElementById("btn-trigger-ai");
const aiResultCard = document.getElementById("ai-result-card");
const aiLoading = document.getElementById("ai-loading");
const aiProviderBadge = document.getElementById("ai-provider-badge");
const aiNoticeBox = document.getElementById("ai-notice-box");
const aiSummaryText = document.getElementById("ai-summary-text");
const aiCauseText = document.getElementById("ai-cause-text");
const aiSeverityBadge = document.getElementById("ai-severity-badge");
const aiEvidenceList = document.getElementById("ai-evidence-list");
const aiActionList = document.getElementById("ai-action-list");
const aiConfidenceVal = document.getElementById("ai-confidence-val");

// Chart Canvases
const canvasTimeline = document.getElementById("chart-timeline");
const canvasTypes = document.getElementById("chart-types");
const canvasHealth = document.getElementById("chart-health");

// ----------------------------------------------------
// Initialization & Data Fetching
// ----------------------------------------------------

async function fetchDashboardData() {
  try {
    // 1. Fetch Stats
    const statsRes = await fetch("/api/stats");
    const statsData = await statsRes.json();

    // 2. Fetch Batches History
    const batchRes = await fetch("/api/batches");
    const batchData = await batchRes.json();
    allBatches = batchData.batches || [];

    // 3. Fetch Anomaly History
    const anomRes = await fetch("/api/anomalies/history?limit=200");
    const anomData = await anomRes.json();
    allAnomalies = anomData.anomalies || [];

    // If history is empty, check latest in-memory analysis
    if (allAnomalies.length === 0) {
      const latestRes = await fetch("/api/anomalies");
      const latestData = await latestRes.json();
      allAnomalies = latestData.anomalies || [];
    }

    updateMetrics(statsData, allAnomalies, allBatches);
    renderAnomaliesTable(getFilteredAnomalies());
    renderBatchesTable(allBatches);
    renderCharts(statsData, allAnomalies);
  } catch (err) {
    console.error("Failed to load dashboard data:", err);
  }
}

function updateMetrics(statsData, anomalies, batches) {
  const persisted = (statsData && statsData.persisted) || {};

  const totalLogs = persisted.total_logs || 0;
  const totalAnomalies = persisted.total_anomalies || anomalies.length;
  const normalLogs = Math.max(0, totalLogs - totalAnomalies);
  const rate = totalLogs > 0 ? (totalAnomalies / totalLogs) * 100 : 0;
  const normalRate = totalLogs > 0 ? (normalLogs / totalLogs) * 100 : 100;

  statTotalLogs.textContent = totalLogs.toLocaleString();
  statTotalAnomalies.textContent = totalAnomalies.toLocaleString();
  statAnomalyRate.textContent = `${rate.toFixed(1)}% anomaly rate`;
  statNormalLogs.textContent = normalLogs.toLocaleString();
  statNormalRate.textContent = `${normalRate.toFixed(1)}% healthy traffic`;
  statTotalBatches.textContent = (batches.length || persisted.total_batches || 0).toLocaleString();

  if (currentBatchInfo) {
    statCurrentBatchFooter.textContent = `Latest Batch: ${currentBatchInfo.generated} logs (${currentBatchInfo.anomalies} anomalies)`;
  } else if (batches.length > 0) {
    const latestBatch = batches[0];
    statCurrentBatchFooter.textContent = `Latest Batch: ${latestBatch.total_logs} logs (${latestBatch.anomalies_detected} anomalies)`;
  } else {
    statCurrentBatchFooter.textContent = "No batches processed yet";
  }

  badgeAnomalyCount.textContent = `${anomalies.length} items`;
  badgeBatchCount.textContent = `${batches.length} batches`;
}

// ----------------------------------------------------
// Filtering & Table Rendering
// ----------------------------------------------------

function getFilteredAnomalies() {
  const selectedType = filterType.value;
  const query = (searchInput.value || "").toLowerCase().trim();

  return allAnomalies.filter((a) => {
    if (selectedType !== "ALL" && a.type !== selectedType) {
      return false;
    }
    if (query) {
      const ip = (a.ip_address || (a.relevant_evidence && a.relevant_evidence.ip_address) || "").toLowerCase();
      const endpoint = (a.endpoint || (a.relevant_evidence && a.relevant_evidence.endpoint) || "").toLowerCase();
      const status = String(a.status_code || (a.relevant_evidence && a.relevant_evidence.status_code) || "");
      const type = (a.type || "").toLowerCase();
      const reasons = Array.isArray(a.reasons) ? a.reasons.join(" ").toLowerCase() : "";
      if (!ip.includes(query) && !endpoint.includes(query) && !status.includes(query) && !type.includes(query) && !reasons.includes(query)) {
        return false;
      }
    }
    return true;
  });
}

function getTypeClass(type) {
  switch (type) {
    case "AUTHENTICATION_ABUSE": return "type-auth";
    case "SERVER_ERROR_BURST": return "type-server";
    case "LATENCY_SPIKE": return "type-latency";
    case "REQUEST_FLOOD": return "type-flood";
    case "ERROR_PATTERN": return "type-pattern";
    default: return "type-general";
  }
}

function renderAnomaliesTable(anomalies) {
  if (!anomalies || anomalies.length === 0) {
    anomaliesTableBody.innerHTML = `
      <tr>
        <td colspan="8" class="text-center empty-state">No anomalies found. Click "Generate & Ingest" or "Run Detection" to start.</td>
      </tr>
    `;
    return;
  }

  anomaliesTableBody.innerHTML = anomalies
    .map((a, idx) => {
      const ev = a.relevant_evidence || {};
      const scoreClass = a.score >= 0.85 ? "score-high" : "score-med";
      const typeClass = getTypeClass(a.type);
      const timeStr = a.timestamp || ev.timestamp ? new Date(a.timestamp || ev.timestamp).toLocaleTimeString() : `#${a.log_index || idx}`;
      const primaryReason = a.reasons && a.reasons.length > 0 ? a.reasons[0] : "Anomaly threshold exceeded";

      return `
        <tr>
          <td><span class="mono-text">${a.id || `log-${idx}`}</span><br><small class="text-dim">${timeStr}</small></td>
          <td><span class="mono-text font-bold">${ev.ip_address || a.ip_address || "—"}</span></td>
          <td>
            <span class="mono-text">${ev.endpoint || a.endpoint || "/"}</span>
            <small class="badge-count">${ev.request_type || "GET"}</small>
          </td>
          <td>
            <span class="score-badge ${Number(ev.status_code || a.status_code) >= 400 ? 'score-high' : 'score-med'}">
              ${ev.status_code || a.status_code || 200}
            </span>
          </td>
          <td><span class="score-badge ${scoreClass}">${Number(a.score).toFixed(2)}</span></td>
          <td><span class="type-pill ${typeClass}">${a.type || "ANOMALY"}</span></td>
          <td style="max-width: 280px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;" title="${primaryReason}">
            ${primaryReason}
          </td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="openAnomalyModal('${a.id}')">
              Inspect & Explain
            </button>
          </td>
        </tr>
      `;
    })
    .join("");
}

function renderBatchesTable(batches) {
  if (!batches || batches.length === 0) {
    batchesTableBody.innerHTML = `
      <tr>
        <td colspan="6" class="text-center empty-state">No batches recorded in database yet.</td>
      </tr>
    `;
    return;
  }

  batchesTableBody.innerHTML = batches
    .map((b) => {
      const time = new Date(b.created_at).toLocaleString();
      const ratePct = ((b.anomaly_rate || 0) * 100).toFixed(1);
      return `
        <tr>
          <td><span class="mono-text font-bold">${b.batch_id}</span></td>
          <td><span class="mono-text">${time}</span></td>
          <td><span class="score-badge">${b.total_logs} logs</span></td>
          <td><span class="score-badge ${b.anomalies_detected > 0 ? 'score-high' : 'score-med'}">${b.anomalies_detected} anomalies</span></td>
          <td><span class="text-danger font-bold">${ratePct}%</span></td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="loadBatchDetails('${b.batch_id}')">
              View Batch
            </button>
          </td>
        </tr>
      `;
    })
    .join("");
}

// ----------------------------------------------------
// Modal & AI Explanation
// ----------------------------------------------------

window.openAnomalyModal = function (anomalyId) {
  selectedAnomaly = allAnomalies.find((a) => a.id === anomalyId) || null;
  if (!selectedAnomaly) return;

  const a = selectedAnomaly;
  const ev = a.relevant_evidence || {};
  const fv = a.feature_values || {};

  modalTitle.textContent = `Anomaly Details — ${a.id}`;
  modalTypeBadge.className = `type-pill ${getTypeClass(a.type)}`;
  modalTypeBadge.textContent = a.type;

  modalScoreValue.textContent = Number(a.score).toFixed(2);
  modalScoreBar.style.width = `${Math.min(100, Math.max(0, a.score * 100))}%`;

  // Signals
  const ipVal = Number(fv.ip || 0);
  const failVal = Number(fv.failure || 0);
  const statusVal = Number(fv.status || 0);
  const latVal = Number(fv.latency || 0);
  const errVal = Number(fv.errorRarity || 0);

  featIp.textContent = ipVal.toFixed(2);
  featFailure.textContent = failVal.toFixed(2);
  featStatus.textContent = statusVal.toFixed(2);
  featLatency.textContent = latVal.toFixed(2);
  featError.textContent = errVal.toFixed(2);

  barFeatIp.style.width = `${ipVal * 100}%`;
  barFeatFailure.style.width = `${failVal * 100}%`;
  barFeatStatus.style.width = `${statusVal * 100}%`;
  barFeatLatency.style.width = `${latVal * 100}%`;
  barFeatError.style.width = `${errVal * 100}%`;

  // Reasons
  modalReasonsList.innerHTML = (a.reasons || ["Anomaly threshold reached"])
    .map((r) => `<li>${r}</li>`)
    .join("");

  // Evidence Grid
  const evidenceFields = [
    { label: "Timestamp", val: a.timestamp || ev.timestamp || "—" },
    { label: "IP Address", val: ev.ip_address || a.ip_address || "—" },
    { label: "Endpoint", val: ev.endpoint || a.endpoint || "—" },
    { label: "HTTP Status", val: ev.status_code || a.status_code || "—" },
    { label: "Severity", val: ev.severity || a.severity || "—" },
    { label: "Event Type", val: ev.event_type || a.event_type || "—" },
    { label: "Response Latency", val: ev.response_time_ms !== null && ev.response_time_ms !== undefined ? `${ev.response_time_ms} ms` : "—" },
    { label: "Exception Type", val: ev.exception_type || "None" },
    { label: "Error Code", val: ev.error_code || "None" },
    { label: "Session ID", val: ev.session_id || a.session_id || "—" },
    { label: "Log Message", val: ev.log_message || a.log_message || "—" },
  ];

  modalEvidenceGrid.innerHTML = evidenceFields
    .map(
      (f) => `
      <div class="evidence-cell">
        <div class="evidence-label">${f.label}</div>
        <div class="evidence-value">${f.val}</div>
      </div>
    `
    )
    .join("");

  // Reset AI card
  aiResultCard.classList.add("hidden");
  aiLoading.classList.add("hidden");

  detailModal.classList.remove("hidden");
};

window.loadBatchDetails = async function (batchId) {
  try {
    const res = await fetch(`/api/batches/${batchId}`);
    const data = await res.json();
    if (data.anomalies) {
      allAnomalies = data.anomalies;
      renderAnomaliesTable(allAnomalies);
      window.scrollTo({ top: document.querySelector(".explorer-section").offsetTop - 40, behavior: "smooth" });
    }
  } catch (err) {
    console.error("Failed to load batch:", err);
  }
};

// Close Modal
function closeModal() {
  detailModal.classList.add("hidden");
}

modalClose.addEventListener("click", closeModal);
modalCloseFooter.addEventListener("click", closeModal);
detailModal.addEventListener("click", (e) => {
  if (e.target === detailModal) closeModal();
});

// Trigger AI Explanation
btnTriggerAi.addEventListener("click", async () => {
  if (!selectedAnomaly) return;

  aiLoading.classList.remove("hidden");
  aiResultCard.classList.add("hidden");

  try {
    const res = await fetch(`/api/anomalies/${selectedAnomaly.id}/explain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ anomaly: selectedAnomaly }),
    });
    const data = await res.json();
    const exp = data.explanation || {};

    if (exp.message && aiNoticeBox) {
      aiNoticeBox.textContent = `Notice: ${exp.message}`;
      aiNoticeBox.classList.remove("hidden");
    } else if (aiNoticeBox) {
      aiNoticeBox.classList.add("hidden");
    }

    aiProviderBadge.textContent = `Provider: ${exp.provider || "AI Engine"}`;
    aiSummaryText.textContent = exp.summary || "No summary available.";
    aiCauseText.textContent = exp.probable_root_cause || "Unidentified root cause.";
    aiSeverityBadge.textContent = exp.impact_severity || "HIGH";

    // Format Evidence List
    const evidenceItems = Array.isArray(exp.relevant_evidence)
      ? exp.relevant_evidence
      : [JSON.stringify(exp.relevant_evidence || exp.evidence_used || {})];
    aiEvidenceList.innerHTML = evidenceItems.map((item) => `<li>${item}</li>`).join("");

    // Format Action List
    const actionItems = Array.isArray(exp.recommended_action)
      ? exp.recommended_action
      : [String(exp.recommended_action || "Investigate logs.")];
    aiActionList.innerHTML = actionItems.map((item) => `<li>${item}</li>`).join("");

    aiConfidenceVal.textContent = `${Math.round((exp.confidence || 0.9) * 100)}%`;

    aiLoading.classList.add("hidden");
    aiResultCard.classList.remove("hidden");
  } catch (err) {
    aiLoading.classList.add("hidden");
    alert("AI Explanation request failed: " + err.message);
  }
});

// ----------------------------------------------------
// Action Buttons: Generate & Analyze
// ----------------------------------------------------

document.getElementById("btn-quick-generate").addEventListener("click", async () => {
  const btn = document.getElementById("btn-quick-generate");
  btn.disabled = true;
  btn.textContent = "Generating & Ingesting...";

  try {
    // 1. Generate EXACTLY 1000 logs
    const genRes = await fetch("/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ count: 1000, anomalyRate: 0.1 }),
    });
    const genData = await genRes.json();
    const newLogs = genData.logs || [];

    // 2. Submit ONLY this new batch with unique batchId to batch processing
    const batchId = `batch-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const batchRes = await fetch("/api/analyze/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ batchId, logs: newLogs }),
    });
    const batchResult = await batchRes.json();

    // 3. Show Current Batch Banner
    currentBatchInfo = {
      batchId: batchResult.batch_id,
      generated: batchResult.total_logs || newLogs.length,
      anomalies: batchResult.anomalies_detected || 0,
      rate: ((batchResult.anomaly_rate || 0) * 100).toFixed(1),
      requested: genData.meta ? genData.meta.requested : (batchResult.total_logs || newLogs.length),
      normalCount: genData.meta ? genData.meta.normalCount : 0,
      anomalousCount: genData.meta ? genData.meta.anomalousCount : 0,
    };

    bannerBatchId.textContent = currentBatchInfo.batchId;
    bannerBatchGenerated.textContent =
      `Requested: ${currentBatchInfo.requested} → Generated: ${currentBatchInfo.generated} (Normal: ${currentBatchInfo.normalCount}, Anomalous: ${currentBatchInfo.anomalousCount})`;
    bannerBatchAnomalies.textContent = `${currentBatchInfo.anomalies} anomalies`;
    bannerBatchRate.textContent = `${currentBatchInfo.rate}%`;
    currentBatchBanner.classList.remove("hidden");

    await fetchDashboardData();
  } catch (err) {
    alert("Failed to generate and analyze: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span class="btn-icon">✨</span> Generate & Ingest (1000 Logs)`;
  }
});

document.getElementById("btn-run-analyze").addEventListener("click", async () => {
  const btn = document.getElementById("btn-run-analyze");
  btn.disabled = true;
  btn.textContent = "Analyzing...";

  try {
    await fetch("/api/analyze", { method: "POST" });
    await fetchDashboardData();
  } catch (err) {
    alert("Detection failed: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span class="btn-icon">🔍</span> Run Detection`;
  }
});

document.getElementById("btn-refresh").addEventListener("click", () => {
  fetchDashboardData();
});

filterType.addEventListener("change", () => {
  renderAnomaliesTable(getFilteredAnomalies());
});

searchInput.addEventListener("input", () => {
  renderAnomaliesTable(getFilteredAnomalies());
});

// ----------------------------------------------------
// Canvas Chart Renderers (Pure Vanilla JS, 0 dependencies)
// ----------------------------------------------------

function renderCharts(statsData, anomalies) {
  drawTimelineChart(canvasTimeline, anomalies);
  drawTypesChart(canvasTypes, anomalies);
  drawHealthChart(canvasHealth, statsData, anomalies);
}

/**
 * Renders anomaly trend timeline using actual chronological timestamp buckets.
 */
function drawTimelineChart(canvas, anomalies) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = (canvas.width = canvas.parentElement.clientWidth);
  const h = (canvas.height = 180);

  ctx.clearRect(0, 0, w, h);

  if (!anomalies || anomalies.length === 0) {
    ctx.fillStyle = "#6b7280";
    ctx.font = "12px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No anomaly events to display", w / 2, h / 2);
    return;
  }

  // Extract valid timestamps
  const timestamps = anomalies
    .map((a) => {
      const ts = a.timestamp || (a.relevant_evidence && a.relevant_evidence.timestamp);
      return ts ? new Date(ts).getTime() : null;
    })
    .filter((t) => t !== null && !Number.isNaN(t));

  if (timestamps.length === 0) {
    ctx.fillStyle = "#6b7280";
    ctx.font = "12px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No timestamp metadata available for trend", w / 2, h / 2);
    return;
  }

  const minTime = Math.min(...timestamps);
  const maxTime = Math.max(...timestamps);
  const numBuckets = 8;
  const bucketDuration = Math.max(1000, (maxTime - minTime) / numBuckets);

  const buckets = new Array(numBuckets).fill(0);
  timestamps.forEach((t) => {
    let b = Math.floor((t - minTime) / bucketDuration);
    if (b >= numBuckets) b = numBuckets - 1;
    buckets[b]++;
  });

  const maxVal = Math.max(...buckets, 1);
  const padLeft = 36;
  const padRight = 20;
  const padBottom = 28;
  const padTop = 16;
  const barWidth = (w - padLeft - padRight) / numBuckets - 8;

  // Baseline grid line
  ctx.strokeStyle = "rgba(255,255,255,0.08)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padLeft, h - padBottom);
  ctx.lineTo(w - padRight, h - padBottom);
  ctx.stroke();

  // Draw Bars and Timestamp Labels
  buckets.forEach((val, i) => {
    const x = padLeft + i * (barWidth + 8);
    const barHeight = ((h - padBottom - padTop) * val) / maxVal;
    const y = h - padBottom - barHeight;

    const grad = ctx.createLinearGradient(0, y, 0, h - padBottom);
    grad.addColorStop(0, "#ef4444");
    grad.addColorStop(1, "rgba(239, 68, 68, 0.2)");

    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.roundRect(x, y, barWidth, barHeight, [4, 4, 0, 0]);
    ctx.fill();

    // Actual Time Label for bucket
    const bucketTime = new Date(minTime + i * bucketDuration);
    const timeLabel = `${bucketTime.getHours().toString().padStart(2, '0')}:${bucketTime.getMinutes().toString().padStart(2, '0')}:${bucketTime.getSeconds().toString().padStart(2, '0')}`;

    ctx.fillStyle = "#9ca3af";
    ctx.font = "10px JetBrains Mono, monospace";
    ctx.textAlign = "center";
    ctx.fillText(timeLabel, x + barWidth / 2, h - 8);

    // Value count label on top of bar
    if (val > 0) {
      ctx.fillStyle = "#fca5a5";
      ctx.font = "bold 10px JetBrains Mono, monospace";
      ctx.fillText(String(val), x + barWidth / 2, y - 4);
    }
  });
}

function drawTypesChart(canvas, anomalies) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = (canvas.width = canvas.parentElement.clientWidth);
  const h = (canvas.height = 180);

  ctx.clearRect(0, 0, w, h);

  const typeCounts = {};
  anomalies.forEach((a) => {
    const t = a.type || "GENERAL";
    typeCounts[t] = (typeCounts[t] || 0) + 1;
  });

  const keys = Object.keys(typeCounts);
  if (keys.length === 0) {
    ctx.fillStyle = "#6b7280";
    ctx.font = "12px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No anomaly types recorded", w / 2, h / 2);
    return;
  }

  const colors = ["#f87171", "#fb923c", "#facc15", "#c084fc", "#60a5fa", "#9ca3af"];
  const maxVal = Math.max(...Object.values(typeCounts), 1);
  const rowHeight = (h - 20) / Math.max(keys.length, 1);

  keys.slice(0, 5).forEach((key, i) => {
    const val = typeCounts[key];
    const y = 14 + i * rowHeight;
    const barWidth = ((w - 150) * val) / maxVal;

    // Label
    ctx.fillStyle = "#9ca3af";
    ctx.font = "11px Inter, sans-serif";
    ctx.textAlign = "left";
    const shortKey = key.replace(/_/g, " ").toLowerCase();
    ctx.fillText(shortKey.substring(0, 14), 10, y + 10);

    // Bar
    ctx.fillStyle = colors[i % colors.length];
    ctx.beginPath();
    ctx.roundRect(120, y, barWidth, 12, 3);
    ctx.fill();

    // Value
    ctx.fillStyle = "#f3f4f6";
    ctx.font = "10px JetBrains Mono, monospace";
    ctx.fillText(String(val), 126 + barWidth, y + 10);
  });
}

function drawHealthChart(canvas, statsData, anomalies) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = (canvas.width = canvas.parentElement.clientWidth);
  const h = (canvas.height = 180);

  ctx.clearRect(0, 0, w, h);

  const persisted = (statsData && statsData.persisted) || {};
  const totalLogs = Math.max(persisted.total_logs || 0, anomalies.length, 1);
  const totalAnomalies = Math.max(persisted.total_anomalies || 0, anomalies.length);
  const normalLogs = Math.max(0, totalLogs - totalAnomalies);

  const cx = w / 2;
  const cy = h / 2;
  const r = 58;
  const strokeW = 16;

  const anomRatio = totalAnomalies / totalLogs;
  const anomAngle = anomRatio * 2 * Math.PI;

  // Background circle (Normal)
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, 2 * Math.PI);
  ctx.strokeStyle = "rgba(16, 185, 129, 0.4)";
  ctx.lineWidth = strokeW;
  ctx.stroke();

  // Anomalies Arc
  if (anomRatio > 0) {
    ctx.beginPath();
    ctx.arc(cx, cy, r, -Math.PI / 2, -Math.PI / 2 + anomAngle);
    ctx.strokeStyle = "#ef4444";
    ctx.lineWidth = strokeW;
    ctx.stroke();
  }

  // Center text
  ctx.fillStyle = "#ffffff";
  ctx.font = "bold 18px Inter, sans-serif";
  ctx.textAlign = "center";
  ctx.fillText(`${((1 - anomRatio) * 100).toFixed(0)}%`, cx, cy + 4);

  ctx.fillStyle = "#9ca3af";
  ctx.font = "10px Inter, sans-serif";
  ctx.fillText("Healthy", cx, cy + 18);
}

// Initial Fetch
fetchDashboardData();

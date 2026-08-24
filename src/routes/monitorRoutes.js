/**
 * Browser Monitor Routes
 * Receives telemetry from the Chrome extension, normalizes it into the existing
 * log schema, runs the existing anomaly detector, and persists results.
 *
 * POST /api/monitor/events  — Receives browser telemetry batch
 * GET  /api/monitor/events  — Returns recent monitored events + anomaly summary
 */

const express = require("express");
const { analyzeLogs } = require("../detector/anomalyDetector");
const db = require("../storage/db");

const router = express.Router();

// In-memory ring buffer for recent monitor sessions (last 200 events)
const MAX_MONITOR_EVENTS = 200;
let recentMonitorEvents = [];
let monitorSessionSummary = {
  totalEvents: 0,
  errors: 0,
  status4xx: 0,
  status5xx: 0,
  slowRequests: 0,
  anomaliesDetected: 0,
  lastBatchId: null,
  lastUpdated: null,
};

/**
 * Converts a single raw browser telemetry event into the existing log schema.
 */
function normalizeEventToLog(event, targetHostname) {
  const ts = event.timestamp || new Date().toISOString();
  const url = event.url || targetHostname || "unknown";
  const status = Number(event.status) || 200;
  const duration = Number(event.duration) || 0;
  const method = (event.method || "GET").toUpperCase();
  const eventType = event.type || "network_request";
  const errorStr = event.error || null;

  // Derive safe hostname/path from url
  let hostname = url;
  let endpoint = "/";
  try {
    const parsed = new URL(url.startsWith("http") ? url : `http://${url}`);
    hostname = parsed.hostname;
    endpoint = parsed.pathname || "/";
  } catch {
    hostname = String(url).split("/")[0] || "browser-monitor";
    endpoint = "/" + String(url).split("/").slice(1, 3).join("/");
  }

  let severity = "INFO";
  if (status >= 500 || eventType === "js_error" || eventType === "navigation_error") {
    severity = "CRITICAL";
  } else if (status >= 400 || eventType === "network_error" || eventType === "promise_rejection") {
    severity = "WARNING";
  } else if (duration >= 2000) {
    severity = "WARNING";
  }

  const isError = status >= 400 || severity === "CRITICAL" || severity === "WARNING";

  return {
    timestamp: ts,
    ip_address: hostname,           // We use hostname as the "IP" equivalent
    request_type: method,
    endpoint,
    status_code: status,
    severity,
    event_type: eventType,
    user_agent: `BrowserMonitor/1.0 (${eventType})`,
    session_id: `monitor-tab-${event.tabId || "unknown"}`,
    location: "browser-client",
    error_code: isError ? (errorStr ? String(errorStr).substring(0, 40) : `ERR_${status}`) : null,
    exception_type: (eventType === "js_error" || eventType === "promise_rejection") ? eventType : null,
    log_message: event.message || `${method} ${endpoint} - ${status} (${duration}ms)`,
    response_time_ms: duration,
  };
}

/**
 * POST /api/monitor/events
 * Receives browser telemetry and runs the existing anomaly detector.
 */
router.post("/monitor/events", (req, res) => {
  const body = req.body || {};
  const rawEvents = Array.isArray(body.events) ? body.events : [];
  const targetUrl = body.targetUrl || "";
  const tabId = body.tabId || "unknown";

  if (rawEvents.length === 0) {
    return res.status(400).json({ error: "No events provided in 'events' array." });
  }

  // Cap events per request to prevent abuse
  const safeEvents = rawEvents.slice(0, 100);

  // Normalize browser events to existing log schema
  const normalizedLogs = safeEvents
    .filter((e) => e && typeof e === "object")
    .map((e) => normalizeEventToLog(e, targetUrl));

  if (normalizedLogs.length === 0) {
    return res.status(400).json({ error: "All provided events were invalid or malformed." });
  }

  // Track in ring buffer
  recentMonitorEvents = [...recentMonitorEvents, ...normalizedLogs].slice(-MAX_MONITOR_EVENTS);

  // Run existing anomaly detector on this batch
  const analysis = analyzeLogs(normalizedLogs);

  // Update session summary
  monitorSessionSummary.totalEvents += normalizedLogs.length;
  monitorSessionSummary.lastUpdated = new Date().toISOString();
  for (const log of normalizedLogs) {
    if (log.status_code >= 500) monitorSessionSummary.status5xx++;
    else if (log.status_code >= 400) monitorSessionSummary.status4xx++;
    if (log.severity === "CRITICAL" || log.severity === "ERROR") monitorSessionSummary.errors++;
    if (log.response_time_ms >= 2000) monitorSessionSummary.slowRequests++;
  }
  monitorSessionSummary.anomaliesDetected += analysis.anomalies_detected;

  // Persist as a monitor batch in SQLite if anomalies were detected
  if (analysis.anomalies_detected > 0) {
    const batchId = `monitor-${tabId}-${Date.now()}`;
    try {
      if (!db.hasBatch(batchId)) {
        db.saveBatch({
          batchId,
          totalLogs: normalizedLogs.length,
          anomaliesDetected: analysis.anomalies_detected,
          normalCount: analysis.normal_count,
          anomalyRate: analysis.anomaly_rate,
          meta: {
            source: "browser_monitor",
            tabId,
            targetUrl,
            anomalies_by_type: analysis.anomalies_by_type,
          },
          logs: normalizedLogs,
          anomalies: analysis.anomalies,
        });
        monitorSessionSummary.lastBatchId = batchId;
      }
    } catch {
      // Non-critical: continue even if persist fails
    }
  }

  return res.status(200).json({
    received: safeEvents.length,
    normalized: normalizedLogs.length,
    anomalies_detected: analysis.anomalies_detected,
    anomaly_rate: analysis.anomaly_rate,
    anomalies: analysis.anomalies,
    session_summary: monitorSessionSummary,
  });
});

/**
 * GET /api/monitor/events
 * Returns recent events and session anomaly summary.
 */
router.get("/monitor/events", (req, res) => {
  const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 50));
  return res.status(200).json({
    session_summary: monitorSessionSummary,
    recent_events: recentMonitorEvents.slice(-limit),
  });
});

/**
 * POST /api/monitor/reset
 * Resets in-memory monitor session counters (for testing).
 */
router.post("/monitor/reset", (req, res) => {
  recentMonitorEvents = [];
  monitorSessionSummary = {
    totalEvents: 0,
    errors: 0,
    status4xx: 0,
    status5xx: 0,
    slowRequests: 0,
    anomaliesDetected: 0,
    lastBatchId: null,
    lastUpdated: null,
  };
  return res.json({ message: "Monitor session reset." });
});

module.exports = router;

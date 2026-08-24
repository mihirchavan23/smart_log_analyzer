const express = require("express");
const logStore = require("../models/logStore");
const anomalyStore = require("../models/anomalyStore");
const { analyzeLogs } = require("../detector/anomalyDetector");
const { explainAnomaly } = require("../ai/aiService");
const db = require("../storage/db");

const router = express.Router();

/**
 * Handler for POST /api/analyze
 * Analyzes currently stored Phase 1 logs (or custom batch passed in body).
 */
function handleAnalyze(req, res) {
  const body = req.body;
  const logsToAnalyze =
    body && Array.isArray(body.logs)
      ? body.logs
      : Array.isArray(body) && body.length > 0
      ? body
      : logStore.getLogs();

  const result = analyzeLogs(logsToAnalyze);
  anomalyStore.setLatestAnalysis(result);

  return res.status(200).json(result);
}

/**
 * Handler for GET /api/anomalies
 * Returns the latest anomaly analysis result.
 */
function handleGetAnomalies(req, res) {
  let latest = anomalyStore.getLatestAnalysis();

  if (!latest) {
    const logs = logStore.getLogs();
    latest = analyzeLogs(logs);
    anomalyStore.setLatestAnalysis(latest);
  }

  return res.status(200).json(latest);
}

/**
 * Handler for POST /api/anomalies/:id/explain
 * Provides AI root-cause analysis for an identified anomaly.
 */
async function handleExplainAnomaly(req, res) {
  const { id } = req.params;

  // 1. Try to find from persistent DB first
  let anomaly = db.getAnomalyById(id);

  // 2. If not found in DB, check latest in-memory analysis
  if (!anomaly) {
    const latest = anomalyStore.getLatestAnalysis();
    if (latest && Array.isArray(latest.anomalies)) {
      anomaly = latest.anomalies.find((a) => a.id === id || String(a.log_index) === String(id));
    }
  }

  // 3. Fallback: Check if anomaly object was sent directly in body
  if (!anomaly && req.body && req.body.anomaly) {
    anomaly = req.body.anomaly;
  }

  if (!anomaly) {
    return res.status(404).json({
      error: `Anomaly with ID '${id}' not found. Run analysis or batch processing first.`,
    });
  }

  try {
    const explanation = await explainAnomaly(anomaly);
    return res.status(200).json({
      anomaly_id: id,
      type: anomaly.type,
      score: anomaly.score,
      explanation,
    });
  } catch (err) {
    return res.status(500).json({
      error: "Failed to generate AI explanation",
      details: err.message,
    });
  }
}

/**
 * GET /api/stats
 * Global statistics for dashboard.
 */
function handleGetStats(req, res) {
  const stats = db.getGlobalStats();
  const inMemoryLogs = logStore.getLogs().length;
  const latest = anomalyStore.getLatestAnalysis();

  return res.status(200).json({
    persisted: stats,
    in_memory: {
      total_logs: inMemoryLogs,
      latest_anomalies_count: latest ? latest.anomalies_detected : 0,
    },
  });
}

// Route mappings
router.post("/analyze", handleAnalyze);
router.post("/api/analyze", handleAnalyze);

router.get("/anomalies", handleGetAnomalies);
router.get("/api/anomalies", handleGetAnomalies);

router.post("/anomalies/:id/explain", handleExplainAnomaly);
router.post("/api/anomalies/:id/explain", handleExplainAnomaly);

router.get("/stats", handleGetStats);
router.get("/api/stats", handleGetStats);

module.exports = router;

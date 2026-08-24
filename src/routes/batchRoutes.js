const express = require("express");
const { validateBatch } = require("../validation/logValidator");
const { analyzeLogs } = require("../detector/anomalyDetector");
const db = require("../storage/db");

const router = express.Router();

/**
 * Helper to generate unique batch IDs.
 */
function generateBatchId() {
  return `batch-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
}

/**
 * POST /api/analyze/batch
 * Receives/processes a batch with a unique batchId, runs Phase 2 detector,
 * persists the batch and its anomaly report into SQLite, and returns batch summary.
 */
router.post("/analyze/batch", (req, res) => {
  const body = req.body || {};
  let { batchId, logs } = body;

  const records = Array.isArray(logs) ? logs : Array.isArray(body) ? body : null;

  if (!Array.isArray(records)) {
    return res.status(400).json({
      error: "Request body must contain a 'logs' array field or be an array of logs.",
      received: 0,
    });
  }

  // Generate batchId if not provided
  if (!batchId || typeof batchId !== "string" || batchId.trim() === "") {
    batchId = generateBatchId();
  } else {
    batchId = batchId.trim();
  }

  // Prevent duplicate processing
  if (db.hasBatch(batchId)) {
    return res.status(409).json({
      error: `Batch with ID '${batchId}' has already been processed. Duplicate processing prevented.`,
      batchId,
    });
  }

  // Validate logs batch
  const { valid, rejected } = validateBatch(records);

  // Run Phase 2 Deterministic Anomaly Detection
  const analysisResult = analyzeLogs(valid);

  // Persist batch, logs, and anomalies in SQLite
  const savedBatch = db.saveBatch({
    batchId,
    totalLogs: valid.length,
    anomaliesDetected: analysisResult.anomalies_detected,
    normalCount: analysisResult.normal_count,
    anomalyRate: analysisResult.anomaly_rate,
    meta: {
      rejected_count: rejected.length,
      anomalies_by_type: analysisResult.anomalies_by_type,
    },
    logs: valid,
    anomalies: analysisResult.anomalies,
  });

  return res.status(201).json({
    message: "Batch processed and persisted successfully.",
    batch_id: batchId,
    received: records.length,
    valid: valid.length,
    rejected: rejected.length,
    total_logs: valid.length,
    anomalies_detected: analysisResult.anomalies_detected,
    normal_count: analysisResult.normal_count,
    anomaly_rate: analysisResult.anomaly_rate,
    anomalies_by_type: analysisResult.anomalies_by_type,
    anomalies: analysisResult.anomalies,
    processed_at: savedBatch.created_at,
  });
});

/**
 * GET /api/batches
 * Returns batch history sorted newest first.
 */
router.get("/batches", (req, res) => {
  const batches = db.getBatches();
  return res.status(200).json({
    count: batches.length,
    batches,
  });
});

/**
 * GET /api/batches/:batchId
 * Returns batch details and all its anomalies.
 */
router.get("/batches/:batchId", (req, res) => {
  const { batchId } = req.params;
  const batch = db.getBatch(batchId);

  if (!batch) {
    return res.status(404).json({
      error: `Batch '${batchId}' not found.`,
    });
  }

  return res.status(200).json(batch);
});

/**
 * GET /api/anomalies/history
 * Returns persisted anomalies across all batches, newest first.
 */
router.get("/anomalies/history", (req, res) => {
  const limit = Math.max(1, Math.min(500, Number(req.query.limit) || 100));
  const offset = Math.max(0, Number(req.query.offset) || 0);

  const anomalies = db.getAnomalyHistory(limit, offset);
  return res.status(200).json({
    count: anomalies.length,
    limit,
    offset,
    anomalies,
  });
});

module.exports = router;

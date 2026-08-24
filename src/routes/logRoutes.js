const express = require("express");
const { generateLogs } = require("../generator/logGenerator");
const { validateBatch } = require("../validation/logValidator");
const store = require("../models/logStore");

const router = express.Router();

/**
 * POST /api/logs
 * Accepts a batch of logs: { logs: [...] }
 * Validates each record; rejects invalid ones without crashing.
 */
router.post("/logs", (req, res) => {
  const body = req.body;
  const records = Array.isArray(body) ? body : body && body.logs;

  if (!Array.isArray(records)) {
    return res.status(400).json({
      error:
        "Request body must be an array of logs, or an object with a 'logs' array field.",
      received: 0,
      valid: 0,
      rejected: 0,
      validation_errors: [],
    });
  }

  const { valid, rejected } = validateBatch(records);

  if (valid.length > 0) {
    store.addLogs(valid);
  }

  return res.status(200).json({
    received: records.length,
    valid: valid.length,
    rejected: rejected.length,
    validation_errors: rejected.map((r, i) => ({
      index: i,
      errors: r.errors,
      record: r.record,
    })),
  });
});

/**
 * GET /api/logs
 * Returns all currently loaded (in-memory) logs.
 */
router.get("/logs", (req, res) => {
  const logs = store.getLogs();
  return res.status(200).json({
    count: logs.length,
    logs,
  });
});

/**
 * POST /api/generate
 * Generates a synthetic batch and returns it.
 * Body (optional): { count, anomalyRate }
 */
router.post("/generate", (req, res) => {
  const body = req.body || {};
  let { count, anomalyRate } = body;

  count = count === undefined ? 100 : Number(count);
  anomalyRate = anomalyRate === undefined ? 0.05 : Number(anomalyRate);

  if (!Number.isFinite(count) || count < 0) {
    return res.status(400).json({ error: "count must be a non-negative number" });
  }
  if (!Number.isFinite(anomalyRate) || anomalyRate < 0 || anomalyRate > 1) {
    return res.status(400).json({ error: "anomalyRate must be a number between 0 and 1" });
  }

  const { logs, meta } = generateLogs(count, anomalyRate);
  store.addLogs(logs);

  return res.status(201).json({
    generated: logs.length,
    meta,
    totalInStore: store.getLogs().length,
    logs,
  });
});

module.exports = router;

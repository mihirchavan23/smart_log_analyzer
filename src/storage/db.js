/**
 * Phase 3 - Lightweight Persistent Storage Module (SQLite)
 * Uses Node.js built-in node:sqlite with file-persistence in data/analyzer.db.
 * Includes JSON file and In-Memory fallbacks to ensure compatibility in any environment (including Vercel/serverless).
 */

const fs = require("fs");
const path = require("path");
const os = require("os");

const isServerless = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);
let DATA_DIR = path.resolve(__dirname, "../../data");

// If running in serverless environment, use OS temp directory for writable persistence
if (isServerless) {
  DATA_DIR = path.join(os.tmpdir(), "smart-log-analyzer-data");
}

try {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
} catch {
  // If local directory creation fails (e.g. read-only filesystem), fallback to os.tmpdir()
  DATA_DIR = path.join(os.tmpdir(), "smart-log-analyzer-data");
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
  } catch {
    // Ignore: memory fallback will handle if disk is completely unwritable
  }
}

const DB_PATH = path.join(DATA_DIR, "analyzer.db");
const JSON_FALLBACK_PATH = path.join(DATA_DIR, "analyzer_fallback.json");

let sqliteDb = null;
let useJsonFallback = false;
let useMemoryFallback = false;
let memoryStore = { batches: {}, logs: [], ai_explanations: {} };

try {
  const { DatabaseSync } = require("node:sqlite");
  sqliteDb = new DatabaseSync(DB_PATH);

  // Initialize schema
  sqliteDb.exec(`
    CREATE TABLE IF NOT EXISTS batches (
      batch_id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      total_logs INTEGER NOT NULL,
      anomalies_detected INTEGER NOT NULL,
      normal_count INTEGER NOT NULL,
      anomaly_rate REAL NOT NULL,
      meta TEXT
    );

    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      batch_id TEXT NOT NULL,
      log_index INTEGER NOT NULL,
      timestamp TEXT,
      ip_address TEXT,
      request_type TEXT,
      endpoint TEXT,
      status_code INTEGER,
      severity TEXT,
      event_type TEXT,
      user_agent TEXT,
      session_id TEXT,
      location TEXT,
      error_code TEXT,
      exception_type TEXT,
      log_message TEXT,
      response_time_ms REAL,
      is_anomaly INTEGER DEFAULT 0,
      score REAL,
      anomaly_type TEXT,
      reasons TEXT,
      feature_values TEXT,
      relevant_evidence TEXT,
      FOREIGN KEY (batch_id) REFERENCES batches(batch_id)
    );

    CREATE TABLE IF NOT EXISTS ai_explanations (
      anomaly_id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      explanation_json TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_logs_batch_id ON logs(batch_id);
    CREATE INDEX IF NOT EXISTS idx_logs_is_anomaly ON logs(is_anomaly);
  `);
} catch (err) {
  useJsonFallback = true;
  try {
    if (!fs.existsSync(JSON_FALLBACK_PATH)) {
      fs.writeFileSync(
        JSON_FALLBACK_PATH,
        JSON.stringify(memoryStore, null, 2)
      );
    }
  } catch (fileErr) {
    useMemoryFallback = true;
  }
}

function getJsonData() {
  if (useMemoryFallback) {
    return memoryStore;
  }
  try {
    return JSON.parse(fs.readFileSync(JSON_FALLBACK_PATH, "utf8"));
  } catch {
    return memoryStore;
  }
}

function saveJsonData(data) {
  memoryStore = data;
  if (!useMemoryFallback) {
    try {
      fs.writeFileSync(JSON_FALLBACK_PATH, JSON.stringify(data, null, 2));
    } catch {
      useMemoryFallback = true;
    }
  }
}

// ----------------------------------------------------
// Public Storage API
// ----------------------------------------------------

function hasBatch(batchId) {
  if (!batchId) return false;
  if (!useJsonFallback && sqliteDb) {
    try {
      const row = sqliteDb.prepare("SELECT batch_id FROM batches WHERE batch_id = ?").get(batchId);
      return Boolean(row);
    } catch {
      // Fallback
    }
  }
  const data = getJsonData();
  return Boolean(data.batches && data.batches[batchId]);
}

function saveBatch({ batchId, totalLogs, anomaliesDetected, normalCount, anomalyRate, meta, logs, anomalies }) {
  const createdAt = new Date().toISOString();
  const anomalyMap = new Map();
  if (Array.isArray(anomalies)) {
    anomalies.forEach((a) => {
      anomalyMap.set(a.log_index, a);
    });
  }

  if (!useJsonFallback && sqliteDb) {
    try {
      const insertBatch = sqliteDb.prepare(`
        INSERT INTO batches (batch_id, created_at, total_logs, anomalies_detected, normal_count, anomaly_rate, meta)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      insertBatch.run(
        batchId,
        createdAt,
        totalLogs,
        anomaliesDetected,
        normalCount,
        anomalyRate,
        JSON.stringify(meta || {})
      );

      const insertLog = sqliteDb.prepare(`
        INSERT INTO logs (
          batch_id, log_index, timestamp, ip_address, request_type, endpoint,
          status_code, severity, event_type, user_agent, session_id, location,
          error_code, exception_type, log_message, response_time_ms,
          is_anomaly, score, anomaly_type, reasons, feature_values, relevant_evidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      logs.forEach((log, index) => {
        const anom = anomalyMap.get(index);
        insertLog.run(
          batchId,
          index,
          log.timestamp || null,
          log.ip_address || null,
          log.request_type || null,
          log.endpoint || null,
          log.status_code !== undefined ? Number(log.status_code) : null,
          log.severity || null,
          log.event_type || null,
          log.user_agent || null,
          log.session_id || null,
          log.location || null,
          log.error_code || null,
          log.exception_type || null,
          log.log_message || null,
          log.response_time_ms !== undefined ? Number(log.response_time_ms) : null,
          anom ? 1 : 0,
          anom ? anom.score : null,
          anom ? anom.type : null,
          anom ? JSON.stringify(anom.reasons) : null,
          anom ? JSON.stringify(anom.feature_values) : null,
          anom ? JSON.stringify(anom.relevant_evidence) : null
        );
      });

      return {
        batch_id: batchId,
        created_at: createdAt,
        total_logs: totalLogs,
        anomalies_detected: anomaliesDetected,
        normal_count: normalCount,
        anomaly_rate: anomalyRate,
      };
    } catch {
      // Fallback if sqlite run fails
    }
  }

  const data = getJsonData();
  data.batches[batchId] = {
    batch_id: batchId,
    created_at: createdAt,
    total_logs: totalLogs,
    anomalies_detected: anomaliesDetected,
    normal_count: normalCount,
    anomaly_rate: anomalyRate,
    meta: meta || {},
  };

  logs.forEach((log, index) => {
    const anom = anomalyMap.get(index);
    data.logs.push({
      batch_id: batchId,
      log_index: index,
      ...log,
      is_anomaly: anom ? 1 : 0,
      score: anom ? anom.score : null,
      anomaly_type: anom ? anom.type : null,
      reasons: anom ? anom.reasons : null,
      feature_values: anom ? anom.feature_values : null,
      relevant_evidence: anom ? anom.relevant_evidence : null,
    });
  });
  saveJsonData(data);

  return {
    batch_id: batchId,
    created_at: createdAt,
    total_logs: totalLogs,
    anomalies_detected: anomaliesDetected,
    normal_count: normalCount,
    anomaly_rate: anomalyRate,
  };
}

function getBatches() {
  if (!useJsonFallback && sqliteDb) {
    try {
      const rows = sqliteDb.prepare("SELECT * FROM batches ORDER BY created_at DESC").all();
      return rows.map((r) => ({
        batch_id: r.batch_id,
        created_at: r.created_at,
        total_logs: r.total_logs,
        anomalies_detected: r.anomalies_detected,
        normal_count: r.normal_count,
        anomaly_rate: r.anomaly_rate,
        meta: r.meta ? JSON.parse(r.meta) : {},
      }));
    } catch {
      // Fallback
    }
  }
  const data = getJsonData();
  return Object.values(data.batches || {}).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
}

function getBatch(batchId) {
  if (!useJsonFallback && sqliteDb) {
    try {
      const batchRow = sqliteDb.prepare("SELECT * FROM batches WHERE batch_id = ?").get(batchId);
      if (!batchRow) return null;

      const logRows = sqliteDb.prepare("SELECT * FROM logs WHERE batch_id = ? ORDER BY log_index ASC").all(batchId);
      const anomalies = [];

      logRows.forEach((r) => {
        if (r.is_anomaly === 1) {
          anomalies.push({
            id: `batch-${r.batch_id}-log-${r.log_index}`,
            batch_id: r.batch_id,
            log_index: r.log_index,
            score: r.score,
            type: r.anomaly_type,
            reasons: r.reasons ? JSON.parse(r.reasons) : [],
            feature_values: r.feature_values ? JSON.parse(r.feature_values) : {},
            relevant_evidence: r.relevant_evidence ? JSON.parse(r.relevant_evidence) : {},
          });
        }
      });

      return {
        batch_id: batchRow.batch_id,
        created_at: batchRow.created_at,
        total_logs: batchRow.total_logs,
        anomalies_detected: batchRow.anomalies_detected,
        normal_count: batchRow.normal_count,
        anomaly_rate: batchRow.anomaly_rate,
        meta: batchRow.meta ? JSON.parse(batchRow.meta) : {},
        anomalies,
      };
    } catch {
      // Fallback
    }
  }

  const data = getJsonData();
  const batch = data.batches && data.batches[batchId];
  if (!batch) return null;

  const logs = (data.logs || []).filter((l) => l.batch_id === batchId);
  const anomalies = logs
    .filter((l) => l.is_anomaly === 1)
    .map((l) => ({
      id: `batch-${l.batch_id}-log-${l.log_index}`,
      batch_id: l.batch_id,
      log_index: l.log_index,
      score: l.score,
      type: l.anomaly_type,
      reasons: l.reasons || [],
      feature_values: l.feature_values || {},
      relevant_evidence: l.relevant_evidence || {},
    }));

  return {
    ...batch,
    anomalies,
  };
}

function getAnomalyHistory(limit = 100, offset = 0) {
  if (!useJsonFallback && sqliteDb) {
    try {
      const rows = sqliteDb
        .prepare(`
          SELECT l.*, b.created_at as batch_created_at
          FROM logs l
          JOIN batches b ON l.batch_id = b.batch_id
          WHERE l.is_anomaly = 1
          ORDER BY l.id DESC
          LIMIT ? OFFSET ?
        `)
        .all(limit, offset);

      return rows.map((r) => ({
        id: `batch-${r.batch_id}-log-${r.log_index}`,
        batch_id: r.batch_id,
        log_index: r.log_index,
        timestamp: r.timestamp || r.batch_created_at,
        ip_address: r.ip_address,
        endpoint: r.endpoint,
        status_code: r.status_code,
        score: r.score,
        type: r.anomaly_type,
        reasons: r.reasons ? JSON.parse(r.reasons) : [],
        feature_values: r.feature_values ? JSON.parse(r.feature_values) : {},
        relevant_evidence: r.relevant_evidence ? JSON.parse(r.relevant_evidence) : {},
      }));
    } catch {
      // Fallback
    }
  }

  const data = getJsonData();
  const anomalousLogs = (data.logs || []).filter((l) => l.is_anomaly === 1);
  return anomalousLogs
    .slice()
    .reverse()
    .slice(offset, offset + limit)
    .map((l) => ({
      id: `batch-${l.batch_id}-log-${l.log_index}`,
      batch_id: l.batch_id,
      log_index: l.log_index,
      timestamp: l.timestamp,
      ip_address: l.ip_address,
      endpoint: l.endpoint,
      status_code: l.status_code,
      score: l.score,
      type: l.anomaly_type,
      reasons: l.reasons || [],
      feature_values: l.feature_values || {},
      relevant_evidence: l.relevant_evidence || {},
    }));
}

function getAnomalyById(id) {
  if (!id) return null;

  // Handle format "batch-BATCHID-log-INDEX" or "log-INDEX"
  let batchId = null;
  let logIndex = null;

  if (id.startsWith("batch-")) {
    const parts = id.replace("batch-", "").split("-log-");
    if (parts.length === 2) {
      batchId = parts[0];
      logIndex = Number(parts[1]);
    }
  } else if (id.startsWith("log-")) {
    logIndex = Number(id.replace("log-", ""));
  } else if (!Number.isNaN(Number(id))) {
    logIndex = Number(id);
  }

  if (!useJsonFallback && sqliteDb) {
    try {
      let row = null;
      if (batchId !== null && logIndex !== null) {
        row = sqliteDb.prepare("SELECT * FROM logs WHERE batch_id = ? AND log_index = ?").get(batchId, logIndex);
      } else if (logIndex !== null) {
        row = sqliteDb.prepare("SELECT * FROM logs WHERE log_index = ? ORDER BY id DESC LIMIT 1").get(logIndex);
      }

      if (row) {
        return {
          id: `batch-${row.batch_id}-log-${row.log_index}`,
          batch_id: row.batch_id,
          log_index: row.log_index,
          timestamp: row.timestamp,
          ip_address: row.ip_address,
          endpoint: row.endpoint,
          status_code: row.status_code,
          score: row.score,
          type: row.anomaly_type || "GENERAL_ANOMALY",
          reasons: row.reasons ? JSON.parse(row.reasons) : [],
          feature_values: row.feature_values ? JSON.parse(row.feature_values) : {},
          relevant_evidence: row.relevant_evidence ? JSON.parse(row.relevant_evidence) : {},
        };
      }
    } catch {
      // Fallback
    }
  }

  const data = getJsonData();
  const logs = data.logs || [];
  let matchingLog = null;

  if (batchId !== null && logIndex !== null) {
    matchingLog = logs.find((l) => l.batch_id === batchId && l.log_index === logIndex);
  } else if (logIndex !== null) {
    matchingLog = logs.find((l) => l.log_index === logIndex);
  }

  if (matchingLog) {
    return {
      id: `batch-${matchingLog.batch_id}-log-${matchingLog.log_index}`,
      batch_id: matchingLog.batch_id,
      log_index: matchingLog.log_index,
      timestamp: matchingLog.timestamp,
      ip_address: matchingLog.ip_address,
      endpoint: matchingLog.endpoint,
      status_code: matchingLog.status_code,
      score: matchingLog.score,
      type: matchingLog.anomaly_type || "GENERAL_ANOMALY",
      reasons: matchingLog.reasons || [],
      feature_values: matchingLog.feature_values || {},
      relevant_evidence: matchingLog.relevant_evidence || {},
    };
  }

  return null;
}

function saveAiExplanation(anomalyId, explanation) {
  const createdAt = new Date().toISOString();
  if (!useJsonFallback && sqliteDb) {
    try {
      const stmt = sqliteDb.prepare(`
        INSERT INTO ai_explanations (anomaly_id, created_at, explanation_json)
        VALUES (?, ?, ?)
        ON CONFLICT(anomaly_id) DO UPDATE SET
          created_at = excluded.created_at,
          explanation_json = excluded.explanation_json
      `);
      stmt.run(anomalyId, createdAt, JSON.stringify(explanation));
      return;
    } catch {
      // Fallback
    }
  }

  const data = getJsonData();
  data.ai_explanations = data.ai_explanations || {};
  data.ai_explanations[anomalyId] = {
    anomaly_id: anomalyId,
    created_at: createdAt,
    explanation,
  };
  saveJsonData(data);
}

function getAiExplanation(anomalyId) {
  if (!useJsonFallback && sqliteDb) {
    try {
      const row = sqliteDb.prepare("SELECT * FROM ai_explanations WHERE anomaly_id = ?").get(anomalyId);
      return row && row.explanation_json ? JSON.parse(row.explanation_json) : null;
    } catch {
      // Fallback
    }
  }
  const data = getJsonData();
  const entry = data.ai_explanations && data.ai_explanations[anomalyId];
  return entry ? entry.explanation : null;
}

function getGlobalStats() {
  if (!useJsonFallback && sqliteDb) {
    try {
      const batchStats = sqliteDb.prepare(`
        SELECT
          COUNT(*) as total_batches,
          COALESCE(SUM(total_logs), 0) as total_logs,
          COALESCE(SUM(anomalies_detected), 0) as total_anomalies
        FROM batches
      `).get();

      const typeRows = sqliteDb.prepare(`
        SELECT anomaly_type, COUNT(*) as count
        FROM logs
        WHERE is_anomaly = 1 AND anomaly_type IS NOT NULL
        GROUP BY anomaly_type
      `).all();

      const typeDistribution = {};
      typeRows.forEach((r) => {
        typeDistribution[r.anomaly_type] = r.count;
      });

      const recentLogs = sqliteDb.prepare(`
        SELECT timestamp, is_anomaly, score, response_time_ms
        FROM logs
        ORDER BY id DESC
        LIMIT 100
      `).all();

      return {
        total_batches: batchStats.total_batches,
        total_logs: batchStats.total_logs,
        total_anomalies: batchStats.total_anomalies,
        anomaly_rate: batchStats.total_logs > 0 ? Number((batchStats.total_anomalies / batchStats.total_logs).toFixed(4)) : 0,
        type_distribution: typeDistribution,
        recent_logs: recentLogs.reverse(),
      };
    } catch {
      // Fallback
    }
  }

  const data = getJsonData();
  const batches = Object.values(data.batches || {});
  const totalLogs = batches.reduce((acc, b) => acc + (b.total_logs || 0), 0);
  const totalAnomalies = batches.reduce((acc, b) => acc + (b.anomalies_detected || 0), 0);

  return {
    total_batches: batches.length,
    total_logs: totalLogs,
    total_anomalies: totalAnomalies,
    anomaly_rate: totalLogs > 0 ? Number((totalAnomalies / totalLogs).toFixed(4)) : 0,
    type_distribution: {},
    recent_logs: [],
  };
}

module.exports = {
  hasBatch,
  saveBatch,
  getBatches,
  getBatch,
  getAnomalyHistory,
  getAnomalyById,
  saveAiExplanation,
  getAiExplanation,
  getGlobalStats,
};

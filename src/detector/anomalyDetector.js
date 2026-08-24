/**
 * Phase 2.1 - Deterministic Behavioral Anomaly Detector
 *
 * Signal Weights:
 * - IP / request frequency: 30%
 * - failure / error frequency: 25%
 * - status abnormality: 20%
 * - latency deviation: 15%
 * - error / message rarity: 10%
 *
 * Scoring:
 * Score = IP*0.30 + failure*0.25 + status*0.20 + latency*0.15 + errorRarity*0.10
 * Threshold:
 * score >= 0.70 -> ANOMALY
 * score < 0.70  -> NORMAL
 */

const ANOMALY_TYPES = {
  REQUEST_FLOOD: "REQUEST_FLOOD",
  AUTHENTICATION_ABUSE: "AUTHENTICATION_ABUSE",
  SERVER_ERROR_BURST: "SERVER_ERROR_BURST",
  LATENCY_SPIKE: "LATENCY_SPIKE",
  ERROR_PATTERN: "ERROR_PATTERN",
  GENERAL_ANOMALY: "GENERAL_ANOMALY",
};

const ANOMALY_THRESHOLD = 0.70;
const WINDOW_MS = 60 * 1000; // 60-second sliding time window

const WEIGHTS = {
  ip: 0.30,
  failure: 0.25,
  status: 0.20,
  latency: 0.15,
  errorRarity: 0.10,
};

function clamp01(val) {
  if (typeof val !== "number" || Number.isNaN(val) || !Number.isFinite(val)) return 0;
  return Math.min(1, Math.max(0, val));
}

function parseTime(timestamp) {
  if (!timestamp) return null;
  const t = new Date(timestamp).getTime();
  return Number.isNaN(t) ? null : t;
}

/**
 * Calculates dataset-wide metrics and precomputes sliding window statistics.
 */
function calculateDatasetStats(logs) {
  const totalLogs = logs.length;
  const ipTotalCounts = new Map();
  const sessionTotalCounts = new Map();
  const ipFailures = new Map();
  const sessionFailures = new Map();
  const ipAuth401Counts = new Map();
  const server500Counts = new Map();
  const errorCodeCounts = new Map();
  const exceptionTypeCounts = new Map();
  const messageCounts = new Map();
  const responseTimes = [];

  const indexedLogs = logs.map((log, idx) => {
    if (!log || typeof log !== "object") {
      return { log: {}, idx, time: null };
    }
    const time = parseTime(log.timestamp);
    const ip = log.ip_address || "unknown";
    const session = log.session_id || `sess-auto-${ip}`;
    const statusCode = Number(log.status_code);
    const severity = typeof log.severity === "string" ? log.severity.toUpperCase() : "INFO";
    const isFailure =
      statusCode >= 400 ||
      severity === "ERROR" ||
      severity === "CRITICAL" ||
      Boolean(log.error_code || log.exception_type);

    ipTotalCounts.set(ip, (ipTotalCounts.get(ip) || 0) + 1);
    sessionTotalCounts.set(session, (sessionTotalCounts.get(session) || 0) + 1);

    if (isFailure) {
      ipFailures.set(ip, (ipFailures.get(ip) || 0) + 1);
      sessionFailures.set(session, (sessionFailures.get(session) || 0) + 1);
    }

    if (statusCode === 401 || statusCode === 403) {
      ipAuth401Counts.set(ip, (ipAuth401Counts.get(ip) || 0) + 1);
    }

    if (statusCode >= 500 && statusCode <= 504) {
      server500Counts.set(ip, (server500Counts.get(ip) || 0) + 1);
    }

    if (log.response_time_ms !== undefined && log.response_time_ms !== null) {
      const rt = Number(log.response_time_ms);
      if (Number.isFinite(rt) && rt >= 0) {
        responseTimes.push(rt);
      }
    }

    if (log.error_code) {
      const code = String(log.error_code);
      errorCodeCounts.set(code, (errorCodeCounts.get(code) || 0) + 1);
    }

    if (log.exception_type) {
      const exc = String(log.exception_type);
      exceptionTypeCounts.set(exc, (exceptionTypeCounts.get(exc) || 0) + 1);
    }

    if (log.log_message) {
      const msg = String(log.log_message);
      messageCounts.set(msg, (messageCounts.get(msg) || 0) + 1);
    }

    return { log, idx, time, ip, session, statusCode, severity, isFailure };
  });

  let meanLatency = 0;
  let stdLatency = 0;
  let minLatency = 0;
  let maxLatency = 0;

  if (responseTimes.length > 0) {
    minLatency = Math.min(...responseTimes);
    maxLatency = Math.max(...responseTimes);
    const sum = responseTimes.reduce((acc, v) => acc + v, 0);
    meanLatency = sum / responseTimes.length;
    const variance =
      responseTimes.reduce((acc, v) => acc + Math.pow(v - meanLatency, 2), 0) /
      responseTimes.length;
    stdLatency = Math.sqrt(variance);
  }

  const windowMetrics = new Array(totalLogs);
  let maxWindowIpCount = 1;

  for (let i = 0; i < indexedLogs.length; i++) {
    const curr = indexedLogs[i];
    let ipWindowCount = 0;
    let sessionWindowCount = 0;
    let ipWindowFailures = 0;
    let sessionWindowFailures = 0;
    let ipWindowAuth401 = 0;
    let windowServer500 = 0;

    const currTime = curr.time;

    if (currTime !== null) {
      const windowStart = currTime - WINDOW_MS;
      const windowEnd = currTime + WINDOW_MS;

      for (let j = 0; j < indexedLogs.length; j++) {
        const other = indexedLogs[j];
        if (other.time !== null && other.time >= windowStart && other.time <= windowEnd) {
          if (other.ip === curr.ip) {
            ipWindowCount++;
            if (other.isFailure) ipWindowFailures++;
            if (other.statusCode === 401 || other.statusCode === 403) ipWindowAuth401++;
          }
          if (other.session === curr.session) {
            sessionWindowCount++;
            if (other.isFailure) sessionWindowFailures++;
          }
          if (other.statusCode >= 500 && other.statusCode <= 504) {
            windowServer500++;
          }
        }
      }
    } else {
      const startIdx = Math.max(0, i - 30);
      const endIdx = Math.min(indexedLogs.length - 1, i + 30);
      for (let j = startIdx; j <= endIdx; j++) {
        const other = indexedLogs[j];
        if (other.ip === curr.ip) {
          ipWindowCount++;
          if (other.isFailure) ipWindowFailures++;
          if (other.statusCode === 401 || other.statusCode === 403) ipWindowAuth401++;
        }
        if (other.session === curr.session) {
          sessionWindowCount++;
          if (other.isFailure) sessionWindowFailures++;
        }
        if (other.statusCode >= 500 && other.statusCode <= 504) {
          windowServer500++;
        }
      }
    }

    if (ipWindowCount > maxWindowIpCount) {
      maxWindowIpCount = ipWindowCount;
    }

    windowMetrics[i] = {
      ipWindowCount,
      sessionWindowCount,
      ipWindowFailures,
      sessionWindowFailures,
      ipWindowAuth401,
      windowServer500,
    };
  }

  let maxTotalIpCount = 1;
  for (const cnt of ipTotalCounts.values()) {
    if (cnt > maxTotalIpCount) maxTotalIpCount = cnt;
  }

  return {
    totalLogs,
    indexedLogs,
    windowMetrics,
    maxWindowIpCount,
    maxTotalIpCount,
    ipTotalCounts,
    sessionTotalCounts,
    ipFailures,
    sessionFailures,
    ipAuth401Counts,
    server500Counts,
    errorCodeCounts,
    exceptionTypeCounts,
    messageCounts,
    meanLatency,
    stdLatency,
    minLatency,
    maxLatency,
  };
}

/**
 * Extracts and normalizes signals to [0, 1] for an individual log.
 */
function extractSignals(log, index, stats) {
  if (!log || typeof log !== "object") {
    return { ip: 0, failure: 0, status: 0, latency: 0, errorRarity: 0 };
  }

  const ip = log.ip_address || "unknown";
  const session = log.session_id || `sess-auto-${ip}`;
  const statusCode = Number(log.status_code);
  const severity = typeof log.severity === "string" ? log.severity.toUpperCase() : "INFO";
  const rt = Number(log.response_time_ms);
  const exceptionType = log.exception_type ? String(log.exception_type) : null;
  const errorCode = log.error_code ? String(log.error_code) : null;
  const message = log.log_message ? String(log.log_message) : "";

  const win = stats.windowMetrics && stats.windowMetrics[index]
    ? stats.windowMetrics[index]
    : {
        ipWindowCount: stats.ipTotalCounts.get(ip) || 1,
        sessionWindowCount: 1,
        ipWindowFailures: 0,
        sessionWindowFailures: 0,
        ipWindowAuth401: (statusCode === 401 || statusCode === 403) ? 1 : 0,
        windowServer500: (statusCode >= 500) ? 1 : 0,
      };

  // --- 1. IP Signal (IP request frequency within 60s window) ---
  let ipSignal = 0;
  const ipCount = win.ipWindowCount;
  if (stats.maxWindowIpCount > 1) {
    const minMaxNorm = (ipCount - 1) / (stats.maxWindowIpCount - 1);
    const windowRatio = stats.totalLogs > 0 ? ipCount / stats.totalLogs : 0;
    ipSignal = Math.max(minMaxNorm, Math.min(1.0, windowRatio * 3.5));
  }
  if (ipCount >= 5) {
    ipSignal = Math.max(ipSignal, 0.85);
  } else if (ipCount >= 3) {
    ipSignal = Math.max(ipSignal, 0.50);
  }

  // --- 2. Failure Signal (failure rate per IP / session) ---
  let failureSignal = 0;
  const isStatusError = statusCode >= 400;
  const isSeverityError = severity === "ERROR" || severity === "CRITICAL";
  const hasExceptionOrCode = Boolean(errorCode || exceptionType);
  const isLogFailure = isStatusError || isSeverityError || hasExceptionOrCode;

  const ipFailureRate = ipCount > 0 ? win.ipWindowFailures / ipCount : 0;
  const sessionFailureRate = win.sessionWindowCount > 0 ? win.sessionWindowFailures / win.sessionWindowCount : 0;
  const combinedFailRate = Math.max(ipFailureRate, sessionFailureRate);

  if (isLogFailure) {
    let base = 0.50;
    if (statusCode >= 500 || severity === "CRITICAL") base += 0.20;
    if (combinedFailRate >= 0.8 && ipCount >= 3) base += 0.25;
    else if (combinedFailRate > 0) base += combinedFailRate * 0.15;
    failureSignal = Math.min(1.0, base);
  } else if (severity === "WARNING" || (Number.isFinite(rt) && rt >= 2000)) {
    failureSignal = 0.70;
  }

  // --- 3. Status Signal (frequency-based 401/403 and 500/503) ---
  let statusSignal = 0;
  const auth401Freq = win.ipWindowAuth401;
  const server500Freq = win.windowServer500;

  if (statusCode === 401 || statusCode === 403) {
    // Single isolated 401/403 produces low status signal (< 0.70 overall)
    if (auth401Freq >= 4) {
      statusSignal = 1.0;
    } else if (auth401Freq >= 2) {
      statusSignal = 0.60;
    } else {
      statusSignal = 0.30;
    }
  } else if (statusCode === 500 || statusCode === 502 || statusCode === 503 || statusCode === 504) {
    // Single isolated 500 produces moderate status signal (< 0.70 overall)
    if (server500Freq >= 3 || (exceptionType && exceptionType.includes("Database"))) {
      statusSignal = 1.0;
    } else {
      statusSignal = 0.40;
    }
  } else if (statusCode === 429) {
    statusSignal = 0.85;
  } else if (statusCode >= 400 && statusCode < 500) {
    statusSignal = 0.25;
  } else if (statusCode >= 200 && statusCode < 400) {
    if (severity === "WARNING" || (Number.isFinite(rt) && rt >= 2000)) {
      statusSignal = 0.75;
    } else {
      statusSignal = 0.0;
    }
  }

  // --- 4. Latency Signal (response-time deviation from dataset baseline) ---
  let latencySignal = 0;
  if (Number.isFinite(rt) && rt >= 0) {
    if (stats.stdLatency > 0) {
      const zScore = (rt - stats.meanLatency) / stats.stdLatency;
      if (zScore > 0) {
        latencySignal = Math.min(1.0, zScore / 2.5);
      }
    }
    if (stats.maxLatency > stats.minLatency) {
      const minMaxLatency = (rt - stats.minLatency) / (stats.maxLatency - stats.minLatency);
      latencySignal = Math.max(latencySignal, minMaxLatency);
    }
    if (rt >= 4000) {
      latencySignal = Math.max(latencySignal, 1.0);
    } else if (rt >= 2000) {
      latencySignal = Math.max(latencySignal, 0.85);
    } else if (rt >= 1000) {
      latencySignal = Math.max(latencySignal, 0.65);
    } else if (rt < 500) {
      latencySignal = Math.min(latencySignal, 0.15);
    }
  }

  // --- 5. Error / Message Signal (separate repeated-error frequency from error rarity) ---
  let errorRaritySignal = 0;
  if (isLogFailure || errorCode || exceptionType) {
    let base = 0.40;
    let repeatedErrSignal = 0;
    let raritySignal = 0;

    if (exceptionType) {
      const excCount = stats.exceptionTypeCounts.get(exceptionType) || 1;
      if (excCount >= 3) repeatedErrSignal = Math.max(repeatedErrSignal, 0.35);
      if (stats.totalLogs > 0 && excCount / stats.totalLogs <= 0.1) raritySignal = Math.max(raritySignal, 0.25);
    }

    if (errorCode) {
      const errCount = stats.errorCodeCounts.get(errorCode) || 1;
      if (errCount >= 3) repeatedErrSignal = Math.max(repeatedErrSignal, 0.25);
    }

    if (message && stats.totalLogs > 0) {
      const msgCount = stats.messageCounts.get(message) || 1;
      if (msgCount / stats.totalLogs <= 0.05) raritySignal = Math.max(raritySignal, 0.20);
    }

    errorRaritySignal = Math.min(1.0, base + repeatedErrSignal + raritySignal);
  } else if (severity === "WARNING" || (Number.isFinite(rt) && rt >= 2000)) {
    errorRaritySignal = 0.75;
  }

  // Correlation adjustments for correlated burst signatures
  if (statusCode >= 500 && (server500Freq >= 3 || (exceptionType && exceptionType.includes("Database")))) {
    if (ipSignal < 0.45) ipSignal = 0.45;
  }
  if (Number.isFinite(rt) && rt >= 3000) {
    if (ipSignal < 0.55) ipSignal = 0.55;
  }

  return {
    ip: clamp01(ipSignal),
    failure: clamp01(failureSignal),
    status: clamp01(statusSignal),
    latency: clamp01(latencySignal),
    errorRarity: clamp01(errorRaritySignal),
  };
}

/**
 * Classifies anomaly type based on the strongest contributing signal and domain context.
 */
function classifyAnomalyType(log, signals) {
  const statusCode = Number(log.status_code);
  const rt = Number(log.response_time_ms);
  const eventType = typeof log.event_type === "string" ? log.event_type.toLowerCase() : "";
  const endpoint = typeof log.endpoint === "string" ? log.endpoint.toLowerCase() : "";
  const exceptionType = log.exception_type ? String(log.exception_type).toLowerCase() : "";
  const errorCode = log.error_code ? String(log.error_code).toUpperCase() : "";

  const contrib = {
    ip: signals.ip * WEIGHTS.ip,
    failure: signals.failure * WEIGHTS.failure,
    status: signals.status * WEIGHTS.status,
    latency: signals.latency * WEIGHTS.latency,
    errorRarity: signals.errorRarity * WEIGHTS.errorRarity,
  };

  // 1. AUTHENTICATION_ABUSE
  if (
    (statusCode === 401 || statusCode === 403 || eventType.includes("login") || endpoint.includes("auth") || exceptionType.includes("auth")) &&
    (signals.status >= 0.5 || signals.ip >= 0.5)
  ) {
    return ANOMALY_TYPES.AUTHENTICATION_ABUSE;
  }

  // 2. SERVER_ERROR_BURST
  if (
    statusCode >= 500 ||
    exceptionType.includes("database") ||
    exceptionType.includes("connection") ||
    exceptionType.includes("server") ||
    errorCode.startsWith("ERR_5")
  ) {
    return ANOMALY_TYPES.SERVER_ERROR_BURST;
  }

  // 3. LATENCY_SPIKE
  if (
    contrib.latency >= 0.12 ||
    signals.latency >= 0.80 ||
    (Number.isFinite(rt) && rt >= 2500)
  ) {
    return ANOMALY_TYPES.LATENCY_SPIKE;
  }

  // 4. REQUEST_FLOOD
  if (contrib.ip >= 0.22 || (signals.ip >= 0.80 && statusCode < 400)) {
    return ANOMALY_TYPES.REQUEST_FLOOD;
  }

  // 5. ERROR_PATTERN
  if (contrib.errorRarity >= 0.08 || signals.errorRarity >= 0.80) {
    return ANOMALY_TYPES.ERROR_PATTERN;
  }

  return ANOMALY_TYPES.GENERAL_ANOMALY;
}

/**
 * Builds structured reasons and concrete evidence for explainability.
 */
function buildReasonsAndEvidence(log, index, signals, score, stats) {
  const reasons = [];
  const ip = log.ip_address || "unknown";
  const statusCode = log.status_code;
  const rt = log.response_time_ms;

  const win = stats.windowMetrics && stats.windowMetrics[index]
    ? stats.windowMetrics[index]
    : { ipWindowCount: 1, ipWindowFailures: 0, ipWindowAuth401: 0, windowServer500: 0 };

  if (signals.ip >= 0.6) {
    reasons.push(`High request rate from IP ${ip} (${win.ipWindowCount} requests in 60s window)`);
  }

  if (statusCode === 401 || statusCode === 403) {
    if (win.ipWindowAuth401 >= 3) {
      reasons.push(`Repeated authentication failures (HTTP ${statusCode}) on ${log.endpoint || "auth endpoint"} (${win.ipWindowAuth401} attempts in window)`);
    } else {
      reasons.push(`Authentication challenge HTTP ${statusCode} on ${log.endpoint || "auth endpoint"}`);
    }
  } else if (statusCode >= 500) {
    reasons.push(`Critical server error HTTP ${statusCode} on ${log.endpoint || "endpoint"}`);
  } else if (statusCode >= 400) {
    reasons.push(`Client error HTTP ${statusCode} on ${log.endpoint || "endpoint"}`);
  }

  if (win.ipWindowCount > 1 && win.ipWindowFailures > 1) {
    const rate = Math.round((win.ipWindowFailures / win.ipWindowCount) * 100);
    reasons.push(`High failure rate for IP ${ip} (${rate}% failures in window)`);
  }

  if (Number.isFinite(rt) && rt >= 1000) {
    reasons.push(`Excessive response latency (${rt}ms vs baseline mean ${Math.round(stats.meanLatency)}ms)`);
  } else if (signals.latency >= 0.7) {
    reasons.push(`Significant latency deviation (${rt}ms)`);
  }

  if (log.exception_type) {
    reasons.push(`Exception encountered: ${log.exception_type}`);
  }

  if (log.error_code) {
    reasons.push(`Error code: ${log.error_code}`);
  }

  if (reasons.length === 0) {
    reasons.push(`Anomaly score ${score.toFixed(2)} exceeded threshold (${ANOMALY_THRESHOLD})`);
  }

  const evidence = {
    timestamp: log.timestamp || null,
    ip_address: log.ip_address || null,
    request_type: log.request_type || null,
    endpoint: log.endpoint || null,
    status_code: log.status_code !== undefined ? log.status_code : null,
    severity: log.severity || null,
    event_type: log.event_type || null,
    user_agent: log.user_agent || null,
    session_id: log.session_id || null,
    location: log.location || null,
    error_code: log.error_code || null,
    exception_type: log.exception_type || null,
    log_message: log.log_message || null,
    response_time_ms: log.response_time_ms !== undefined ? log.response_time_ms : null,
  };

  return { reasons, evidence };
}

/**
 * Main Anomaly Detection engine function.
 *
 * @param {Array<object>} logs
 * @returns {object} Structured anomaly detection report
 */
function analyzeLogs(logs) {
  if (!Array.isArray(logs) || logs.length === 0) {
    return {
      total_logs: 0,
      anomalies_detected: 0,
      normal_count: 0,
      anomaly_rate: 0,
      anomalies_by_type: {
        [ANOMALY_TYPES.REQUEST_FLOOD]: 0,
        [ANOMALY_TYPES.AUTHENTICATION_ABUSE]: 0,
        [ANOMALY_TYPES.SERVER_ERROR_BURST]: 0,
        [ANOMALY_TYPES.LATENCY_SPIKE]: 0,
        [ANOMALY_TYPES.ERROR_PATTERN]: 0,
        [ANOMALY_TYPES.GENERAL_ANOMALY]: 0,
      },
      anomalies: [],
      analyzed_at: new Date().toISOString(),
    };
  }

  const stats = calculateDatasetStats(logs);
  const anomalies = [];
  const typeCounts = {
    [ANOMALY_TYPES.REQUEST_FLOOD]: 0,
    [ANOMALY_TYPES.AUTHENTICATION_ABUSE]: 0,
    [ANOMALY_TYPES.SERVER_ERROR_BURST]: 0,
    [ANOMALY_TYPES.LATENCY_SPIKE]: 0,
    [ANOMALY_TYPES.ERROR_PATTERN]: 0,
    [ANOMALY_TYPES.GENERAL_ANOMALY]: 0,
  };

  logs.forEach((log, index) => {
    const signals = extractSignals(log, index, stats);

    // Score: IP*0.30 + failure*0.25 + status*0.20 + latency*0.15 + errorRarity*0.10
    const rawScore =
      signals.ip * WEIGHTS.ip +
      signals.failure * WEIGHTS.failure +
      signals.status * WEIGHTS.status +
      signals.latency * WEIGHTS.latency +
      signals.errorRarity * WEIGHTS.errorRarity;

    const score = Number(rawScore.toFixed(4));
    const isAnomaly = score >= ANOMALY_THRESHOLD;

    if (isAnomaly) {
      const { reasons, evidence } = buildReasonsAndEvidence(log, index, signals, score, stats);
      const type = classifyAnomalyType(log, signals);
      typeCounts[type] = (typeCounts[type] || 0) + 1;

      anomalies.push({
        id: `log-${index}`,
        log_index: index,
        score,
        type,
        reasons,
        feature_values: {
          ip: Number(signals.ip.toFixed(4)),
          failure: Number(signals.failure.toFixed(4)),
          status: Number(signals.status.toFixed(4)),
          latency: Number(signals.latency.toFixed(4)),
          errorRarity: Number(signals.errorRarity.toFixed(4)),
        },
        relevant_evidence: evidence,
      });
    }
  });

  return {
    total_logs: logs.length,
    anomalies_detected: anomalies.length,
    normal_count: logs.length - anomalies.length,
    anomaly_rate: Number((anomalies.length / logs.length).toFixed(4)),
    anomalies_by_type: typeCounts,
    anomalies,
    analyzed_at: new Date().toISOString(),
  };
}

module.exports = {
  ANOMALY_TYPES,
  ANOMALY_THRESHOLD,
  WEIGHTS,
  WINDOW_MS,
  extractSignals,
  calculateDatasetStats,
  classifyAnomalyType,
  analyzeLogs,
};

const {
  REQUEST_TYPES,
  USER_AGENTS,
  LOCATIONS,
  NORMAL_STATUS_CODES,
  EVENT_TYPES,
  ENDPOINTS_BY_EVENT,
} = require("../models/logSchema");

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIp() {
  return `${randomInt(1, 223)}.${randomInt(0, 255)}.${randomInt(
    0,
    255
  )}.${randomInt(1, 254)}`;
}

function severityForStatus(status) {
  if (status >= 500) return "CRITICAL";
  if (status === 401 || status === 403) return "WARNING";
  if (status >= 400) return "ERROR";
  return "INFO";
}

function messageFor(eventType, endpoint, status) {
  const outcome = status < 400 ? "success" : "failed";
  return `${eventType} ${endpoint} - ${outcome} (status ${status})`;
}

/**
 * Builds one plausible, "normal" log entry at the given timestamp.
 */
function buildNormalLog(timestamp) {
  const eventType = pick(EVENT_TYPES);
  const endpoint = pick(ENDPOINTS_BY_EVENT[eventType]);
  const statusCode = pick(NORMAL_STATUS_CODES);
  const severity = severityForStatus(statusCode);
  const isError = statusCode >= 400;

  return {
    timestamp: timestamp.toISOString(),
    ip_address: randomIp(),
    request_type: pick(REQUEST_TYPES),
    endpoint,
    status_code: statusCode,
    severity,
    event_type: eventType,
    user_agent: pick(USER_AGENTS),
    session_id: `sess-${randomInt(1000, 9999)}`,
    location: pick(LOCATIONS),
    error_code: isError ? `ERR_${statusCode}` : null,
    exception_type: null,
    log_message: messageFor(eventType, endpoint, statusCode),
    response_time_ms: randomInt(20, 450),
  };
}

/**
 * Anomaly scenario: a burst of repeated 401 login failures from one IP
 * (credential stuffing / brute-force pattern).
 */
function buildLoginFailureBurst(startTime, maxCount = 8) {
  const ip = randomIp();
  const session = `sess-${randomInt(1000, 9999)}`;
  const burstSize = Math.min(maxCount, randomInt(5, 9));
  const logs = [];

  for (let i = 0; i < burstSize; i++) {
    const ts = new Date(startTime.getTime() + i * 2000);
    logs.push({
      timestamp: ts.toISOString(),
      ip_address: ip,
      request_type: "POST",
      endpoint: "/api/auth/login",
      status_code: 401,
      severity: "WARNING",
      event_type: "login",
      user_agent: pick(USER_AGENTS),
      session_id: session,
      location: pick(LOCATIONS),
      error_code: "ERR_401",
      exception_type: "AuthenticationFailedError",
      log_message: "login /api/auth/login - failed (status 401)",
      response_time_ms: randomInt(20, 200),
    });
  }
  return logs;
}

/**
 * Anomaly scenario: a burst of repeated 500 / database errors.
 */
function buildDatabaseErrorBurst(startTime, maxCount = 7) {
  const burstSize = Math.min(maxCount, randomInt(4, 7));
  const logs = [];
  const endpoint = pick(ENDPOINTS_BY_EVENT.db_query);

  for (let i = 0; i < burstSize; i++) {
    const ts = new Date(startTime.getTime() + i * 3000);
    logs.push({
      timestamp: ts.toISOString(),
      ip_address: randomIp(),
      request_type: pick(["GET", "POST"]),
      endpoint,
      status_code: 500,
      severity: "CRITICAL",
      event_type: "db_query",
      user_agent: pick(USER_AGENTS),
      session_id: `sess-${randomInt(1000, 9999)}`,
      location: pick(LOCATIONS),
      error_code: "ERR_500",
      exception_type: "DatabaseConnectionError",
      log_message: `db_query ${endpoint} - failed (status 500)`,
      response_time_ms: randomInt(500, 2000),
    });
  }
  return logs;
}

/**
 * Anomaly scenario: a single request with an unusually high response time.
 */
function buildSlowResponseLog(timestamp) {
  const eventType = pick(EVENT_TYPES);
  const endpoint = pick(ENDPOINTS_BY_EVENT[eventType]);
  const statusCode = 200;

  return {
    timestamp: timestamp.toISOString(),
    ip_address: randomIp(),
    request_type: pick(REQUEST_TYPES),
    endpoint,
    status_code: statusCode,
    severity: "WARNING",
    event_type: eventType,
    user_agent: pick(USER_AGENTS),
    session_id: `sess-${randomInt(1000, 9999)}`,
    location: pick(LOCATIONS),
    error_code: null,
    exception_type: null,
    log_message: messageFor(eventType, endpoint, statusCode),
    response_time_ms: randomInt(4000, 12000),
  };
}

/**
 * Anomaly scenario: high request frequency flood from single IP.
 */
function buildRequestFloodBurst(startTime, maxCount = 10) {
  const ip = randomIp();
  const session = `sess-${randomInt(1000, 9999)}`;
  const burstSize = Math.min(maxCount, randomInt(6, 12));
  const logs = [];

  for (let i = 0; i < burstSize; i++) {
    const ts = new Date(startTime.getTime() + i * 500);
    const eventType = pick(EVENT_TYPES);
    const endpoint = pick(ENDPOINTS_BY_EVENT[eventType]);
    logs.push({
      timestamp: ts.toISOString(),
      ip_address: ip,
      request_type: pick(REQUEST_TYPES),
      endpoint,
      status_code: 200,
      severity: "INFO",
      event_type: eventType,
      user_agent: "Bot/Scanner-v2",
      session_id: session,
      location: pick(LOCATIONS),
      error_code: null,
      exception_type: null,
      log_message: messageFor(eventType, endpoint, 200),
      response_time_ms: randomInt(15, 120),
    });
  }
  return logs;
}

const ANOMALY_BUILDERS = [
  { type: "login_failure_burst", build: buildLoginFailureBurst },
  { type: "database_error_burst", build: buildDatabaseErrorBurst },
  { type: "slow_response", build: (ts) => [buildSlowResponseLog(ts)] },
  { type: "request_flood", build: buildRequestFloodBurst },
];

/**
 * Generates a synthetic dataset of EXACTLY `count` logs.
 *
 * 1. Target count is exact (e.g. 1000 requested -> exactly 1000 returned).
 * 2. Reserves `anomalyRate` proportion for anomaly scenarios (e.g. ~100 logs).
 * 3. Fills the remaining records with normal traffic (e.g. ~900 logs).
 * 4. Combines them so that total === count exactly.
 *
 * @param {number} count - Exact total number of logs to generate (default 1000).
 * @param {number} anomalyRate - Proportion of logs for anomaly scenarios (default 0.10).
 * @returns {{ logs: object[], meta: { requested: number, totalGenerated: number, generated: number, normalCount: number, anomalousCount: number, scenarios: string[] } }}
 */
function generateLogs(count = 1000, anomalyRate = 0.10) {
  const targetTotal = Math.max(0, Math.floor(count));
  if (targetTotal === 0) {
    return {
      logs: [],
      meta: {
        requested: 0,
        totalGenerated: 0,
        generated: 0,
        normalCount: 0,
        anomalousCount: 0,
        anomaliesInjected: 0,
        scenarios: [],
      },
    };
  }

  const safeRate = Math.min(1, Math.max(0, anomalyRate));
  const targetAnomalyRecords = safeRate > 0 && targetTotal >= 5
    ? Math.min(targetTotal, Math.max(1, Math.round(targetTotal * safeRate)))
    : 0;

  const baseTime = new Date();
  const anomalyLogs = [];
  const scenariosUsed = [];

  // Generate anomaly logs up to targetAnomalyRecords
  while (anomalyLogs.length < targetAnomalyRecords) {
    const remaining = targetAnomalyRecords - anomalyLogs.length;
    const scenario = pick(ANOMALY_BUILDERS);
    const offsetSeconds = randomInt(0, Math.max(targetTotal - 1, 0));
    const anomalyStart = new Date(baseTime.getTime() - (targetTotal - offsetSeconds) * 1000);

    const generatedBurst = scenario.build(anomalyStart, remaining);
    const takeLogs = generatedBurst.slice(0, remaining);
    anomalyLogs.push(...takeLogs);
    scenariosUsed.push(scenario.type);
  }

  // Calculate exact number of normal logs needed
  const targetNormalRecords = targetTotal - anomalyLogs.length;
  const normalLogs = [];

  for (let i = 0; i < targetNormalRecords; i++) {
    const ts = new Date(baseTime.getTime() - (targetTotal - i) * 1000);
    normalLogs.push(buildNormalLog(ts));
  }

  // Combine and sort chronologically
  const logs = [...normalLogs, ...anomalyLogs];
  logs.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  return {
    logs,
    meta: {
      requested: targetTotal,
      totalGenerated: logs.length,
      generated: logs.length,
      normalCount: normalLogs.length,
      anomalousCount: anomalyLogs.length,
      anomaliesInjected: scenariosUsed.length,
      scenarios: scenariosUsed,
    },
  };
}

module.exports = { generateLogs };

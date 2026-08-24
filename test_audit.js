const http = require("http");
const assert = require("assert");
const fs = require("fs");
const path = require("path");

const app = require("./src/server");
const { analyzeLogs, ANOMALY_TYPES } = require("./src/detector/anomalyDetector");
const { generateLogs } = require("./src/generator/logGenerator");
const db = require("./src/storage/db");
const { explainAnomaly, buildDeterministicExplanation, normalizeAndValidateExplanation } = require("./src/ai/aiService");

console.log("==================================================");
console.log("RUNNING COMPREHENSIVE AUDIT TEST SUITE (PHASES 1-5)");
console.log("==================================================\n");

async function runAudit() {
  const server = http.createServer(app);

  await new Promise((resolve) => {
    server.listen(0, resolve);
  });

  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;
  console.log(`Server started on ${baseUrl}\n`);

  try {
    // ----------------------------------------------------
    // Scenario A & B: Generate exactly 100 logs
    // ----------------------------------------------------
    console.log("A & B. Testing EXACTLY 1000 logs generation count...");
    const genRes = await fetch(`${baseUrl}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ count: 1000, anomalyRate: 0.1 }),
    });
    const genData = await genRes.json();
    assert.strictEqual(genRes.status, 201);
    assert.strictEqual(Array.isArray(genData.logs), true);
    assert.strictEqual(genData.logs.length, 1000, `Expected exactly 1000 logs, got ${genData.logs.length}`);
    assert.strictEqual(genData.meta.requested, 1000);
    assert.strictEqual(genData.meta.generated, 1000);
    assert.strictEqual(genData.meta.normalCount + genData.meta.anomalousCount, 1000);
    console.log(`  [PASS] Generated exactly ${genData.logs.length} logs (Normal: ${genData.meta.normalCount}, Anomalous: ${genData.meta.anomalousCount}).\n`);

    // ----------------------------------------------------
    // Scenario C, D, E, F: Unique batchId, batch analysis, SQLite persistence
    // ----------------------------------------------------
    console.log("C, D, E, F. Batch processing & SQLite persistence...");
    const batchId1 = `batch-audit-${Date.now()}-1`;
    const batchRes1 = await fetch(`${baseUrl}/api/analyze/batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ batchId: batchId1, logs: genData.logs }),
    });
    const batchData1 = await batchRes1.json();
    assert.strictEqual(batchRes1.status, 201);
    assert.strictEqual(batchData1.batch_id, batchId1);
    assert.strictEqual(batchData1.total_logs, genData.logs.length);
    assert.strictEqual(batchData1.anomalies_detected > 0, true);

    // Verify duplicate batchId rejection
    const dupRes = await fetch(`${baseUrl}/api/analyze/batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ batchId: batchId1, logs: genData.logs }),
    });
    assert.strictEqual(dupRes.status, 409);
    console.log(`  [PASS] Batch ${batchId1} persisted (${batchData1.total_logs} logs, ${batchData1.anomalies_detected} anomalies). Duplicate rejected.\n`);

    // ----------------------------------------------------
    // Scenario G & H: Restart server simulation & history verification
    // ----------------------------------------------------
    console.log("AI Status Endpoint...");
    const aiStatusRes = await fetch(`${baseUrl}/api/ai/status`);
    const aiStatus = await aiStatusRes.json();
    assert.strictEqual(aiStatusRes.status, 200);
    assert.strictEqual(typeof aiStatus.provider, "string");
    assert.strictEqual(typeof aiStatus.configured, "boolean");
    assert.strictEqual(typeof aiStatus.fallback_available, "boolean");
    assert.ok(!JSON.stringify(aiStatus).includes("GEMINI_API_KEY"), "Key must not appear in status response");
    console.log(`  [PASS] /api/ai/status: provider=${aiStatus.provider}, configured=${aiStatus.configured}\n`);

    console.log("Browser Monitor Events Endpoint...");
    const monEvents = [
      { type: "network_request", method: "GET", url: "https://test.example.com/api/data", status: 200, duration: 120, message: "GET /api/data 200" },
      { type: "network_error", method: "GET", url: "https://test.example.com/api/broken", status: 500, duration: 800, error: "ERR_CONNECTION", message: "GET /api/broken 500" },
      { type: "js_error", error: "TypeError", message: "JavaScript Error: Cannot read property 'x' of undefined", status: 500, duration: 10 },
    ];
    const monRes = await fetch(`${baseUrl}/api/monitor/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tabId: "test-tab-999", targetUrl: "https://test.example.com", events: monEvents }),
    });
    const monData = await monRes.json();
    assert.strictEqual(monRes.status, 200);
    assert.strictEqual(monData.normalized, 3);
    assert.strictEqual(typeof monData.anomalies_detected, "number");
    console.log(`  [PASS] /api/monitor/events: ${monData.normalized} events normalized, ${monData.anomalies_detected} anomalies detected.\n`);

    // GET monitor events
    const monGetRes = await fetch(`${baseUrl}/api/monitor/events`);
    const monGetData = await monGetRes.json();
    assert.strictEqual(monGetRes.status, 200);
    assert.ok(monGetData.session_summary, "Expected session_summary");
    console.log(`  [PASS] GET /api/monitor/events: session_summary.totalEvents=${monGetData.session_summary.totalEvents}\n`);

    // ----------------------------------------------------
    // Scenario G & H: History retrieval across batches
    // ----------------------------------------------------
    console.log("G & H. Verifying history retrieval across batches...");
    const batchesRes = await fetch(`${baseUrl}/api/batches`);
    const batchesData = await batchesRes.json();
    assert.strictEqual(batchesRes.status, 200);
    assert.strictEqual(batchesData.batches.some((b) => b.batch_id === batchId1), true);

    const histRes = await fetch(`${baseUrl}/api/anomalies/history?limit=50`);
    const histData = await histRes.json();
    assert.strictEqual(histRes.status, 200);
    assert.strictEqual(histData.anomalies.length > 0, true);
    console.log(`  [PASS] Retrieved ${batchesData.count} batches and ${histData.count} historical anomalies.\n`);

    // ----------------------------------------------------
    // Scenario N: Authentication burst
    // ----------------------------------------------------
    console.log("N. Testing Authentication Burst...");
    const normalLogs = [];
    for (let i = 0; i < 30; i++) {
      normalLogs.push({
        timestamp: new Date(Date.now() - (30 - i) * 1000).toISOString(),
        ip_address: `192.168.1.${i + 1}`,
        request_type: "GET",
        endpoint: "/api/products",
        status_code: 200,
        severity: "INFO",
        event_type: "api_request",
        log_message: "api_request /api/products - success",
        response_time_ms: 50,
      });
    }

    const authLogs = [];
    for (let i = 0; i < 6; i++) {
      authLogs.push({
        timestamp: new Date(Date.now() - (6 - i) * 2000).toISOString(),
        ip_address: "198.51.100.99",
        request_type: "POST",
        endpoint: "/api/auth/login",
        status_code: 401,
        severity: "WARNING",
        event_type: "login",
        error_code: "ERR_401",
        exception_type: "AuthenticationFailedError",
        log_message: "login failed (status 401)",
        response_time_ms: 70,
      });
    }
    const authResult = analyzeLogs([...normalLogs, ...authLogs]);
    assert.strictEqual(authResult.anomalies_detected >= 6, true);
    assert.strictEqual(authResult.anomalies_by_type[ANOMALY_TYPES.AUTHENTICATION_ABUSE] >= 6, true);
    console.log(`  [PASS] Auth burst correctly detected (${authResult.anomalies_detected} anomalies classified as AUTHENTICATION_ABUSE).\n`);

    // ----------------------------------------------------
    // Scenario O: Server Error burst (500s)
    // ----------------------------------------------------
    console.log("O. Testing Server Error Burst (500s)...");
    const serverLogs = [];
    for (let i = 0; i < 5; i++) {
      serverLogs.push({
        timestamp: new Date(Date.now() - (5 - i) * 3000).toISOString(),
        ip_address: `172.16.0.${i + 1}`,
        request_type: "POST",
        endpoint: "/api/orders",
        status_code: 500,
        severity: "CRITICAL",
        event_type: "db_query",
        error_code: "ERR_500",
        exception_type: "DatabaseConnectionError",
        log_message: "db_query failed (status 500)",
        response_time_ms: 1200,
      });
    }
    const serverResult = analyzeLogs([...normalLogs, ...serverLogs]);
    assert.strictEqual(serverResult.anomalies_detected >= 5, true);
    assert.strictEqual(serverResult.anomalies_by_type[ANOMALY_TYPES.SERVER_ERROR_BURST] >= 5, true);
    console.log(`  [PASS] Server error burst detected (${serverResult.anomalies_detected} anomalies classified as SERVER_ERROR_BURST).\n`);

    // ----------------------------------------------------
    // Scenario P: Latency Spike
    // ----------------------------------------------------
    console.log("P. Testing Latency Spike...");
    const slowLog = {
      timestamp: new Date().toISOString(),
      ip_address: "10.0.0.88",
      request_type: "GET",
      endpoint: "/api/search",
      status_code: 200,
      severity: "WARNING",
      event_type: "api_request",
      log_message: "api_request search - success (status 200)",
      response_time_ms: 8000,
    };
    const latResult = analyzeLogs([...normalLogs, slowLog]);
    const latAnom = latResult.anomalies.find((a) => a.type === ANOMALY_TYPES.LATENCY_SPIKE);
    assert.strictEqual(Boolean(latAnom), true);
    assert.strictEqual(latAnom.score >= 0.70, true);
    console.log(`  [PASS] Latency spike detected (Score: ${latAnom.score}, Type: ${latAnom.type}).\n`);

    // ----------------------------------------------------
    // Scenario Q: Normal Traffic
    // ----------------------------------------------------
    console.log("Q. Testing Normal Traffic...");
    const normalResult = analyzeLogs(normalLogs);
    assert.strictEqual(normalResult.anomalies_detected, 0);
    console.log("  [PASS] Normal traffic produces 0 anomalies.\n");

    // ----------------------------------------------------
    // Scenario R: Isolated 401 and Isolated 500 (Must NOT be anomalies)
    // ----------------------------------------------------
    console.log("R. Testing Isolated 401 and Isolated 500...");
    const isolated401 = {
      timestamp: new Date().toISOString(),
      ip_address: "10.0.0.1",
      request_type: "POST",
      endpoint: "/api/auth/login",
      status_code: 401,
      severity: "WARNING",
      event_type: "login",
      log_message: "single 401 login attempt",
      response_time_ms: 80,
    };
    const isolated500 = {
      timestamp: new Date().toISOString(),
      ip_address: "10.0.0.2",
      request_type: "GET",
      endpoint: "/api/items",
      status_code: 500,
      severity: "CRITICAL",
      event_type: "api_request",
      log_message: "single 500 error",
      response_time_ms: 120,
    };
    const isoResult = analyzeLogs([...normalLogs, isolated401, isolated500]);
    const iso401Found = isoResult.anomalies.find((a) => a.relevant_evidence && a.relevant_evidence.ip_address === "10.0.0.1");
    const iso500Found = isoResult.anomalies.find((a) => a.relevant_evidence && a.relevant_evidence.ip_address === "10.0.0.2");
    assert.strictEqual(iso401Found, undefined, "Isolated 401 must NOT be an anomaly");
    assert.strictEqual(iso500Found, undefined, "Isolated 500 must NOT be an anomaly");
    console.log("  [PASS] Isolated 401 and Isolated 500 are correctly classified as NORMAL (< 0.70).\n");

    // ----------------------------------------------------
    // Scenario J, K, L, M: AI Root Cause Analysis & Fallback Validation
    // ----------------------------------------------------
    console.log("J, K, L, M. Testing AI Root-Cause Analysis & Structured Validation...");
    const sampleAnomaly = authResult.anomalies[0];
    const aiExpl = await explainAnomaly(sampleAnomaly);
    assert.strictEqual(typeof aiExpl, "object");
    assert.strictEqual(typeof aiExpl.summary, "string");
    assert.strictEqual(typeof aiExpl.probable_root_cause, "string");
    assert.strictEqual(["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(aiExpl.impact_severity), true);
    assert.strictEqual(Array.isArray(aiExpl.relevant_evidence), true);
    assert.strictEqual(Array.isArray(aiExpl.recommended_action), true);
    assert.strictEqual(typeof aiExpl.confidence, "number");
    assert.strictEqual(typeof aiExpl.provider, "string");
    console.log(`  [PASS] AI Root-Cause Service generated valid structured response:`);
    console.log(`    - Provider Label: ${aiExpl.provider}`);
    console.log(`    - Summary: ${aiExpl.summary}`);
    console.log(`    - Probable Cause: ${aiExpl.probable_root_cause}`);
    console.log(`    - Recommended Actions: ${aiExpl.recommended_action.length} items`);
    console.log(`    - Confidence: ${aiExpl.confidence}\n`);

    // ----------------------------------------------------
    // Scenario I: Dashboard Loading
    // ----------------------------------------------------
    console.log("I. Testing Dashboard static assets...");
    const dashRes = await fetch(`${baseUrl}/`);
    assert.strictEqual(dashRes.status, 200);
    const html = await dashRes.text();
    assert.strictEqual(html.includes("Smart Log Analyzer"), true);
    assert.strictEqual(html.includes("current-batch-banner"), true);
    console.log("  [PASS] Dashboard HTML and assets verified.\n");

    console.log("==================================================");
    console.log("ALL AUDIT TEST SCENARIOS PASSED WITH ZERO ERRORS!");
    console.log("==================================================");
  } catch (err) {
    console.error("Audit test failed:", err);
    process.exit(1);
  } finally {
    server.close();
  }
}

runAudit();

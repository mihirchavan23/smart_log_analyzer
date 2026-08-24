/**
 * Phase 4 - Real Provider-Based AI Root-Cause Analysis Service
 *
 * Supported Providers:
 * 1. Google Gemini via official @google/genai SDK (GEMINI_API_KEY)
 * 2. OpenAI via Chat Completions API (OPENAI_API_KEY)
 * 3. xAI Grok via xAI API (XAI_API_KEY)
 * 4. Deterministic Expert Rules Fallback (when credentials are absent/unavailable)
 *
 * Provider selection: AI_PROVIDER=gemini | openai | grok
 */

require("dotenv").config();

const { saveAiExplanation, getAiExplanation } = require("../storage/db");

let GoogleGenAI = null;
try {
  const genaiPkg = require("@google/genai");
  GoogleGenAI = genaiPkg.GoogleGenAI;
} catch {
  // @google/genai loaded dynamically if available
}

/**
 * Normalizes and strictly validates AI explanation structure.
 */
function normalizeAndValidateExplanation(rawJson, providerName) {
  if (!rawJson || typeof rawJson !== "object") {
    throw new Error("Invalid response format: expected JSON object.");
  }

  const summary =
    typeof rawJson.summary === "string" && rawJson.summary.trim().length > 0
      ? rawJson.summary.trim()
      : "Automated analysis completed for the detected anomaly.";

  const probableRootCause =
    typeof rawJson.probable_root_cause === "string" && rawJson.probable_root_cause.trim().length > 0
      ? rawJson.probable_root_cause.trim()
      : typeof rawJson.root_cause === "string"
      ? rawJson.root_cause.trim()
      : "Unidentified behavioral variance in request stream.";

  let impactSeverity = "HIGH";
  if (typeof rawJson.impact_severity === "string") {
    const s = rawJson.impact_severity.toUpperCase().trim();
    if (["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(s)) {
      impactSeverity = s;
    }
  }

  let relevantEvidence = [];
  if (Array.isArray(rawJson.relevant_evidence)) {
    relevantEvidence = rawJson.relevant_evidence.map((item) => String(item).trim());
  } else if (typeof rawJson.relevant_evidence === "string") {
    relevantEvidence = [rawJson.relevant_evidence.trim()];
  } else if (typeof rawJson.evidence_used === "object") {
    relevantEvidence = Object.entries(rawJson.evidence_used).map(
      ([k, v]) => `${k}: ${v}`
    );
  }

  let recommendedAction = [];
  if (Array.isArray(rawJson.recommended_action)) {
    recommendedAction = rawJson.recommended_action.map((item) => String(item).trim());
  } else if (typeof rawJson.recommended_action === "string") {
    recommendedAction = rawJson.recommended_action
      .split("\n")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  } else if (typeof rawJson.recommendations === "string") {
    recommendedAction = rawJson.recommendations.split("\n").map((s) => s.trim()).filter((s) => s.length > 0);
  }

  if (recommendedAction.length === 0) {
    recommendedAction = ["Investigate system logs for related anomalies.", "Monitor service latency and error rates."];
  }

  let confidence = 0.90;
  if (typeof rawJson.confidence === "number" && !Number.isNaN(rawJson.confidence)) {
    confidence = Math.min(1.0, Math.max(0.0, rawJson.confidence));
  }

  return {
    ai_status: "success",
    provider: providerName,
    summary,
    probable_root_cause: probableRootCause,
    impact_severity: impactSeverity,
    relevant_evidence: relevantEvidence,
    recommended_action: recommendedAction,
    confidence: Number(confidence.toFixed(2)),
  };
}

/**
 * Builds deterministic expert explanation when no live LLM key is configured.
 */
function buildDeterministicExplanation(anomaly, fallbackReason = null) {
  const type = anomaly.type || "GENERAL_ANOMALY";
  const evidence = anomaly.relevant_evidence || {};
  const score = anomaly.score || 0.75;
  const reasons = anomaly.reasons || [];

  let summary = `Detected anomalous behavior categorized as ${type} (Score: ${score}).`;
  let probableRootCause = "Unusual traffic pattern deviating from historical baseline.";
  let impactSeverity = score >= 0.85 ? "CRITICAL" : score >= 0.75 ? "HIGH" : "MEDIUM";
  let recommendedAction = [
    "Investigate application server logs and upstream service metrics.",
    "Monitor endpoint performance and active connection pools.",
  ];

  switch (type) {
    case "AUTHENTICATION_ABUSE":
      summary = `Authentication anomaly detected: repeated authorization failures from IP ${evidence.ip_address || "unknown"}.`;
      probableRootCause = `Brute-force credential stuffing or broken client authentication workflow targeting ${evidence.endpoint || "auth endpoint"}.`;
      impactSeverity = "HIGH";
      recommendedAction = [
        `Temporarily rate-limit or block offending IP ${evidence.ip_address || "origin"}.`,
        "Enforce multi-factor authentication (MFA) and CAPTCHA challenge.",
        "Audit authentication logs for concurrent targeted user accounts.",
      ];
      break;

    case "SERVER_ERROR_BURST":
      summary = `Server error burst: sudden spike in HTTP 5xx responses with ${evidence.exception_type || "critical exceptions"}.`;
      probableRootCause = `Database connection pool exhaustion, unhandled backend exception, or downstream dependency failure.`;
      impactSeverity = "CRITICAL";
      recommendedAction = [
        "Inspect database connection pool saturation and query locks.",
        `Review server error logs for exception '${evidence.exception_type || "ERR_500"}'.`,
        "Verify downstream service health and restart stalled worker pods if necessary.",
      ];
      break;

    case "LATENCY_SPIKE":
      summary = `Latency spike: response time reached ${evidence.response_time_ms || 4000}ms, severely exceeding normal baseline.`;
      probableRootCause = `Resource starvation (CPU/memory throttling), slow database query lock, or high upstream API response delay.`;
      impactSeverity = "MEDIUM";
      recommendedAction = [
        `Profile database query execution plans for ${evidence.endpoint || "endpoint"}.`,
        "Inspect container CPU and memory utilization thresholds.",
        "Enable response caching and tune HTTP keep-alive connection timeouts.",
      ];
      break;

    case "REQUEST_FLOOD":
      summary = `Request flood: excessive request volume from IP ${evidence.ip_address || "unknown"}.`;
      probableRootCause = `Unthrottled client scraper, distributed volumetric attack, or aggressive client retry loop.`;
      impactSeverity = "HIGH";
      recommendedAction = [
        "Apply IP-level rate limiting at the reverse proxy or API gateway.",
        `Inspect User-Agent '${evidence.user_agent || "unknown"}' and block malicious automated bot patterns.`,
      ];
      break;

    case "ERROR_PATTERN":
      summary = `Recurring error pattern: persistent failures with error code ${evidence.error_code || "client/server code"}.`;
      probableRootCause = `API contract mismatch, invalid payload schema, or expired client credentials.`;
      impactSeverity = "MEDIUM";
      recommendedAction = [
        "Validate client payload against API schema specifications.",
        "Check client SDK version compatibility and deprecation notices.",
      ];
      break;
  }

  const evidenceList = [
    `IP Address: ${evidence.ip_address || "unknown"}`,
    `Endpoint: ${evidence.endpoint || "unknown"} (Status ${evidence.status_code || 200})`,
    `Response Latency: ${evidence.response_time_ms !== undefined ? evidence.response_time_ms + "ms" : "N/A"}`,
    ...(evidence.exception_type ? [`Exception: ${evidence.exception_type}`] : []),
    ...(evidence.error_code ? [`Error Code: ${evidence.error_code}`] : []),
  ];

  return {
    ai_status: "fallback",
    provider: "Deterministic Expert Rules (fallback)",
    message: fallbackReason || "No live LLM API key configured. Utilizing deterministic rule-based analysis.",
    summary,
    probable_root_cause: probableRootCause,
    impact_severity: impactSeverity,
    relevant_evidence: evidenceList,
    reasons_considered: reasons,
    recommended_action: recommendedAction,
    confidence: Number(Math.min(0.95, Math.max(0.70, score)).toFixed(2)),
  };
}

/**
 * Calls Google Gemini using @google/genai SDK.
 */
async function callGemini(apiKey, anomaly) {
  if (!GoogleGenAI) {
    throw new Error("@google/genai SDK not available.");
  }

  const ai = new GoogleGenAI({ apiKey });
  const modelName = process.env.GEMINI_MODEL || "gemini-2.0-flash";

  const prompt = `You are an expert SRE and Security Operations Center (SOC) analyst. Analyze the following detected log anomaly and provide a structured root-cause explanation.

ANOMALY CONTEXT:
- Classification Type: ${anomaly.type}
- Deterministic Score: ${anomaly.score}
- Detection Reasons: ${JSON.stringify(anomaly.reasons || [])}
- Contributing Signals: ${JSON.stringify(anomaly.feature_values || {})}
- Evidence Log Data: ${JSON.stringify(anomaly.relevant_evidence || {})}

Return ONLY a valid JSON object with these exact keys:
{
  "summary": "1-2 sentence executive summary of the anomaly event",
  "probable_root_cause": "Detailed technical root cause",
  "impact_severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "relevant_evidence": ["Key evidence bullet point 1", "Key evidence bullet point 2"],
  "recommended_action": ["Actionable remediation step 1", "Actionable remediation step 2", "Actionable remediation step 3"],
  "confidence": 0.92
}`;

  const response = await ai.models.generateContent({
    model: modelName,
    contents: prompt,
    config: {
      responseMimeType: "application/json",
    },
  });

  const responseText = response.text;
  const parsed = JSON.parse(responseText);
  return normalizeAndValidateExplanation(parsed, `Google Gemini (${modelName})`);
}

/**
 * Calls OpenAI Chat Completions API.
 */
async function callOpenAI(apiKey, anomaly) {
  const endpoint = process.env.OPENAI_API_BASE || "https://api.openai.com/v1/chat/completions";
  const model = process.env.OPENAI_MODEL || "gpt-4o-mini";

  const prompt = `You are an expert SRE and Security Operations Center (SOC) analyst. Analyze the following detected log anomaly and provide a structured root-cause explanation.

ANOMALY CONTEXT:
- Classification Type: ${anomaly.type}
- Deterministic Score: ${anomaly.score}
- Detection Reasons: ${JSON.stringify(anomaly.reasons || [])}
- Contributing Signals: ${JSON.stringify(anomaly.feature_values || {})}
- Evidence Log Data: ${JSON.stringify(anomaly.relevant_evidence || {})}

Return ONLY a valid JSON object with these exact keys:
{
  "summary": "1-2 sentence executive summary of the anomaly event",
  "probable_root_cause": "Detailed technical root cause",
  "impact_severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "relevant_evidence": ["Key evidence bullet point 1", "Key evidence bullet point 2"],
  "recommended_action": ["Actionable remediation step 1", "Actionable remediation step 2"],
  "confidence": 0.90
}`;

  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: prompt }],
      response_format: { type: "json_object" },
      temperature: 0.2,
    }),
  });

  if (!res.ok) {
    throw new Error(`OpenAI API error HTTP ${res.status}: ${await res.text()}`);
  }

  const data = await res.json();
  const content = data.choices[0].message.content;
  const parsed = JSON.parse(content);
  return normalizeAndValidateExplanation(parsed, `OpenAI (${model})`);
}

/**
 * Calls xAI Grok API.
 */
async function callGrok(apiKey, anomaly) {
  const endpoint = process.env.XAI_API_BASE || "https://api.x.ai/v1/chat/completions";
  const model = process.env.XAI_MODEL || "grok-2-latest";

  const prompt = `You are an expert SRE and Security Operations Center (SOC) analyst. Analyze the following detected log anomaly and provide a structured root-cause explanation.

ANOMALY CONTEXT:
- Classification Type: ${anomaly.type}
- Deterministic Score: ${anomaly.score}
- Detection Reasons: ${JSON.stringify(anomaly.reasons || [])}
- Contributing Signals: ${JSON.stringify(anomaly.feature_values || {})}
- Evidence Log Data: ${JSON.stringify(anomaly.relevant_evidence || {})}

Return ONLY a valid JSON object with these exact keys:
{
  "summary": "1-2 sentence executive summary of the anomaly event",
  "probable_root_cause": "Detailed technical root cause",
  "impact_severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "relevant_evidence": ["Key evidence bullet point 1", "Key evidence bullet point 2"],
  "recommended_action": ["Actionable remediation step 1", "Actionable remediation step 2"],
  "confidence": 0.90
}`;

  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: prompt }],
      temperature: 0.2,
    }),
  });

  if (!res.ok) {
    throw new Error(`xAI Grok API error HTTP ${res.status}: ${await res.text()}`);
  }

  const data = await res.json();
  const content = data.choices[0].message.content;
  // Parse json from markdown code block if present
  let cleanJson = content.trim();
  if (cleanJson.startsWith("```")) {
    cleanJson = cleanJson.replace(/^```json|^```/, "").replace(/```$/, "").trim();
  }
  const parsed = JSON.parse(cleanJson);
  return normalizeAndValidateExplanation(parsed, `xAI Grok (${model})`);
}

/**
 * Main AI Explanation Entry Point.
 *
 * @param {object} anomaly - Anomaly record
 * @returns {Promise<object>} Explanation object
 */
async function explainAnomaly(anomaly) {
  if (!anomaly) {
    return {
      error: "No anomaly provided for explanation",
      status: "invalid_input",
    };
  }

  const anomalyId = anomaly.id || `log-${anomaly.log_index || 0}`;

  // Check persistent storage cache
  const cached = getAiExplanation(anomalyId);
  if (cached) {
    return cached;
  }

  const configuredProvider = (process.env.AI_PROVIDER || "").toLowerCase().trim();
  const geminiKey = process.env.GEMINI_API_KEY;
  const openaiKey = process.env.OPENAI_API_KEY;
  const xaiKey = process.env.XAI_API_KEY;

  let explanation = null;

  try {
    if (configuredProvider === "grok" && xaiKey) {
      explanation = await callGrok(xaiKey, anomaly);
    } else if (configuredProvider === "openai" && openaiKey) {
      explanation = await callOpenAI(openaiKey, anomaly);
    } else if (geminiKey) {
      // Default to Gemini if GEMINI_API_KEY is present
      explanation = await callGemini(geminiKey, anomaly);
    } else if (openaiKey) {
      explanation = await callOpenAI(openaiKey, anomaly);
    } else if (xaiKey) {
      explanation = await callGrok(xaiKey, anomaly);
    } else {
      explanation = buildDeterministicExplanation(
        anomaly,
        "No LLM API key configured in environment. Set GEMINI_API_KEY, OPENAI_API_KEY, or XAI_API_KEY."
      );
    }
  } catch (err) {
    // If live LLM call fails, fall back gracefully to deterministic expert rules
    explanation = buildDeterministicExplanation(
      anomaly,
      `Live LLM call encountered an error: ${err.message}. Showing deterministic expert analysis.`
    );
  }

  // Persist result in database
  saveAiExplanation(anomalyId, explanation);

  return explanation;
}

module.exports = {
  explainAnomaly,
  buildDeterministicExplanation,
  normalizeAndValidateExplanation,
};

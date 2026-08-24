# Smart Log Analyzer

A high-performance log analysis, anomaly detection, persistent batch processing, AI root-cause analysis, and monitoring dashboard engine.

---

## 🏛️ System Architecture

```
LOG GENERATION / INGESTION (Phase 1)
        ↓
BATCH PROCESSING & VALIDATION (Phase 3)
        ↓
SQLITE PERSISTENCE (Phase 3)
        ↓
FEATURE EXTRACTION & SLIDING WINDOW (Phase 2.1)
        ↓
DETERMINISTIC BEHAVIORAL ANOMALY DETECTOR (Phase 2.1)
        ↓
NORMAL (< 0.70) / ANOMALY (≥ 0.70)
        ↓
STRUCTURED EVIDENCE & SIGNALS (Phase 2.1)
        ↓
AI ROOT-CAUSE EXPLANATION (Phase 4 — Gemini / OpenAI / Grok / Fallback)
        ↓
INTERACTIVE MONITORING DASHBOARD (Phase 5)
```

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment (Optional)
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
*(Optional: Provide `GEMINI_API_KEY`, `OPENAI_API_KEY`, or `XAI_API_KEY` for live LLM explanations. If no API key is provided, the built-in deterministic expert reasoning engine activates automatically.)*

### 3. Run Application
```bash
npm start
```
- **Server**: `http://localhost:3000`
- **Dashboard**: `http://localhost:3000/` or `http://localhost:3000/dashboard`

### 4. Run Automated Tests
```bash
npm test
```

---

## 📊 Deterministic Anomaly Scoring (Phase 2.1)

Detection uses a pure deterministic formula without ML/LLM dependency:

$$\text{Score} = \text{IP} \times 0.30 + \text{failure} \times 0.25 + \text{status} \times 0.20 + \text{latency} \times 0.15 + \text{errorRarity} \times 0.10$$

- **Threshold**:
  - $\text{Score} \ge 0.70 \implies \mathbf{ANOMALY}$
  - $\text{Score} < 0.70 \implies \mathbf{NORMAL}$
- **Signals**:
  1. **IP / Request Frequency (30%)**: 60-second sliding time window request rate per IP.
  2. **Failure / Error Frequency (25%)**: Error rate per IP and session.
  3. **Status Abnormality (20%)**: Frequency-based 401/403 and 500/503 bursts (single isolated 401/500 remain Normal $< 0.70$).
  4. **Latency Deviation (15%)**: Response time deviation relative to dataset baseline mean/variance and high latency thresholds ($>2000\text{ms}, >4000\text{ms}$).
  5. **Error / Message Rarity (10%)**: Separated repeated error frequency vs rarity of exception types and error codes.
- **Classifications**:
  - `REQUEST_FLOOD`
  - `AUTHENTICATION_ABUSE`
  - `SERVER_ERROR_BURST`
  - `LATENCY_SPIKE`
  - `ERROR_PATTERN`
  - `GENERAL_ANOMALY`

---

## 📡 Complete API Reference

### Log Ingestion & Generation (Phase 1)
- `POST /api/generate` — Generates synthetic logs (`count`, `anomalyRate`).
- `POST /api/logs` — Ingests and validates log records.
- `GET /api/logs` — Retrieves in-memory logs.

### Detection & Analysis (Phase 2.1)
- `POST /api/analyze` — Analyzes stored logs or provided payload.
- `GET /api/anomalies` — Returns latest anomaly detection results.

### Batch Processing & Persistence (Phase 3)
- `POST /api/analyze/batch` — Ingests, validates, detects anomalies, and persists a batch to SQLite with duplicate `batchId` prevention (HTTP 409).
- `GET /api/batches` — Returns historical processed batches.
- `GET /api/batches/:batchId` — Returns batch details and all its anomalies.
- `GET /api/anomalies/history` — Returns persisted anomalies across all batches (newest first, with pagination `limit`/`offset`).

### AI Root-Cause Analysis (Phase 4)
- `POST /api/anomalies/:id/explain` — Generates structured root-cause analysis, impact assessment, and remediation steps.

### Dashboard Stats (Phase 5)
- `GET /api/stats` — Global metrics summary for dashboard visualization.
- `GET /` or `GET /dashboard` — Interactive monitoring frontend.

---

## 🤖 AI Root-Cause Analysis Providers (Phase 4)

Configure your preferred provider in `.env`:

```env
# Provider: gemini | openai | grok
AI_PROVIDER=gemini

# Google Gemini (Official @google/genai SDK)
GEMINI_API_KEY=your_gemini_key

# OpenAI
OPENAI_API_KEY=your_openai_key

# xAI Grok
XAI_API_KEY=your_xai_key
```

### Response Schema
```json
{
  "ai_status": "success",
  "provider": "Google Gemini (gemini-2.5-flash)",
  "summary": "Repeated authorization failures targeting /api/auth/login from IP 198.51.100.99.",
  "probable_root_cause": "Brute-force credential stuffing attack or broken client authentication loop.",
  "impact_severity": "HIGH",
  "relevant_evidence": [
    "IP Address: 198.51.100.99",
    "Endpoint: /api/auth/login (Status 401)",
    "Exception: AuthenticationFailedError"
  ],
  "recommended_action": [
    "Apply temporary rate-limiting or firewall block on IP 198.51.100.99.",
    "Enforce multi-factor authentication (MFA) and CAPTCHA."
  ],
  "confidence": 0.92
}
```

---

## 💻 Monitoring Dashboard (Phase 5)

- **Live KPI Metrics**: Total Cumulative Logs, Current Batch Logs, Total Anomalies, Healthy Traffic %, and Processed Batches.
- **Interactive Visualizations**:
  - Anomaly Trend Timeline Chart (grouped by chronological timestamp buckets).
  - Anomaly Types Distribution Chart.
  - Traffic Health Donut Chart.
- **Anomalies Explorer**: Full-text search and filtering by classification type.
- **Detailed Inspection Modal**: Visual score gauge, normalized signal contributions, concrete evidence grid, and one-click AI Root-Cause Analysis trigger.
- **Batch History**: Complete SQLite batch history explorer.

---

## 🧪 Testing

Run all unit, integration, persistence, and detector tests:
```bash
npm test
```

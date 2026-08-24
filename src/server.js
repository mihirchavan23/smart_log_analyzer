// Load environment variables from .env file (if present)
require("dotenv").config();

const express = require("express");
const path = require("path");
const logRoutes = require("./routes/logRoutes");
const anomalyRoutes = require("./routes/anomalyRoutes");
const batchRoutes = require("./routes/batchRoutes");
const monitorRoutes = require("./routes/monitorRoutes");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "10mb" }));

// Serve static frontend assets for Phase 5 Dashboard
const publicPath = path.join(__dirname, "../public");
app.use(express.static(publicPath));

// Safe AI provider status (never reveals keys)
app.get("/api/ai/status", (req, res) => {
  const geminiKey = process.env.GEMINI_API_KEY;
  const openaiKey = process.env.OPENAI_API_KEY;
  const xaiKey = process.env.XAI_API_KEY;
  const configuredProvider = (process.env.AI_PROVIDER || "").toLowerCase().trim();

  let activeProvider = "deterministic";
  let configured = false;

  if (configuredProvider === "grok" && xaiKey) {
    activeProvider = "grok"; configured = true;
  } else if (configuredProvider === "openai" && openaiKey) {
    activeProvider = "openai"; configured = true;
  } else if (geminiKey) {
    activeProvider = "gemini"; configured = true;
  } else if (openaiKey) {
    activeProvider = "openai"; configured = true;
  } else if (xaiKey) {
    activeProvider = "grok"; configured = true;
  }

  return res.json({
    provider: activeProvider,
    configured,
    model: activeProvider === "gemini"
      ? (process.env.GEMINI_MODEL || "gemini-2.5-flash")
      : activeProvider === "openai"
      ? (process.env.OPENAI_MODEL || "gpt-4o-mini")
      : activeProvider === "grok"
      ? (process.env.XAI_MODEL || "grok-2-latest")
      : null,
    fallback_available: true,
  });
});

// API Root Information
app.get("/api", (req, res) => {
  res.json({
    name: "Smart Log Analyzer - Phase 1 through 5",
    version: "5.0.0",
    endpoints: [
      "POST /api/generate",
      "POST /api/logs",
      "GET /api/logs",
      "POST /api/analyze",
      "GET /api/anomalies",
      "POST /api/analyze/batch",
      "GET /api/batches",
      "GET /api/batches/:batchId",
      "GET /api/anomalies/history",
      "POST /api/anomalies/:id/explain",
      "GET /api/ai/status",
      "POST /api/monitor/events",
      "GET /api/monitor/events",
      "GET /api/stats",
    ],
  });
});

// Mount Routes
app.use("/api", logRoutes);
app.use("/api", anomalyRoutes);
app.use("/api", batchRoutes);
app.use("/api", monitorRoutes);

// Dashboard HTML entrypoint
app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(publicPath, "index.html"));
});

// Basic error handler
app.use((err, req, res, next) => {
  if (err) {
    return res.status(400).json({ error: "Invalid request", details: err.message });
  }
  next();
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Smart Log Analyzer running on http://localhost:${PORT}`);
    console.log(`Dashboard available at http://localhost:${PORT}/`);
  });
}

module.exports = app;

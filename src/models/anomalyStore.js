/**
 * Phase 2: In-memory store for anomaly analysis results.
 */
let latestAnalysis = null;

function setLatestAnalysis(analysis) {
  latestAnalysis = analysis;
  return latestAnalysis;
}

function getLatestAnalysis() {
  return latestAnalysis;
}

function clear() {
  latestAnalysis = null;
}

module.exports = {
  setLatestAnalysis,
  getLatestAnalysis,
  clear,
};

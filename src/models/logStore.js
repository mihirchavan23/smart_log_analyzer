// Phase 1: in-memory only. No database persistence.
let logs = [];

function addLogs(newLogs) {
  logs.push(...newLogs);
  return logs.length;
}

function getLogs() {
  return logs;
}

function clear() {
  logs = [];
}

module.exports = { addLogs, getLogs, clear };

/**
 * Smart Log Analyzer - Extension Background Service Worker (Manifest V3)
 * Collects safe browser telemetry on the user-selected tab and sends to backend.
 */

let state = {
  isMonitoring: false,
  monitoredTabId: null,
  monitoredUrl: "",
  backendUrl: "http://localhost:3000/api/monitor/events",
  eventsCount: 0,
  errorsCount: 0,
  startTime: null,
};

// Queue for telemetry events to batch/send to backend
let eventQueue = [];
let flushTimer = null;

// Sanitize URLs to prevent capturing tokens/passwords in query parameters
function sanitizeUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    return `${parsed.protocol}//${parsed.hostname}${parsed.pathname}`;
  } catch {
    return rawUrl ? String(rawUrl).split("?")[0] : "unknown";
  }
}

function flushEvents() {
  if (eventQueue.length === 0 || !state.isMonitoring) return;

  const batch = [...eventQueue];
  eventQueue = [];

  fetch(state.backendUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      tabId: state.monitoredTabId,
      targetUrl: state.monitoredUrl,
      events: batch,
    }),
  }).catch((err) => {
    console.warn("[SmartLogAnalyzer Extension] Failed to send telemetry batch:", err.message);
  });
}

function queueEvent(event) {
  if (!state.isMonitoring) return;

  // Filter strictly to the monitored tab
  if (event.tabId && event.tabId !== state.monitoredTabId) {
    return;
  }

  state.eventsCount++;
  if (event.status >= 400 || event.type.includes("error")) {
    state.errorsCount++;
  }

  eventQueue.push({
    timestamp: new Date().toISOString(),
    tabId: state.monitoredTabId,
    ...event,
  });

  if (!flushTimer) {
    flushTimer = setTimeout(() => {
      flushTimer = null;
      flushEvents();
    }, 1000); // Flush every 1s
  }
}

// ----------------------------------------------------
// Web Request Telemetry Listeners
// ----------------------------------------------------

const requestStartTimes = new Map();

if (chrome.webRequest) {
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      if (details.tabId === state.monitoredTabId && state.isMonitoring) {
        requestStartTimes.set(details.requestId, Date.now());
      }
    },
    { urls: ["<all_urls>"] }
  );

  chrome.webRequest.onCompleted.addListener(
    (details) => {
      if (details.tabId === state.monitoredTabId && state.isMonitoring) {
        const start = requestStartTimes.get(details.requestId) || Date.now();
        requestStartTimes.delete(details.requestId);
        const duration = Math.max(1, Date.now() - start);

        queueEvent({
          type: "network_request",
          method: details.method || "GET",
          url: sanitizeUrl(details.url),
          status: details.statusCode || 200,
          duration,
          resourceType: details.type || "other",
          message: `${details.method || "GET"} ${sanitizeUrl(details.url)} - ${details.statusCode || 200} (${duration}ms)`,
        });
      }
    },
    { urls: ["<all_urls>"] }
  );

  chrome.webRequest.onErrorOccurred.addListener(
    (details) => {
      if (details.tabId === state.monitoredTabId && state.isMonitoring) {
        const start = requestStartTimes.get(details.requestId) || Date.now();
        requestStartTimes.delete(details.requestId);
        const duration = Math.max(1, Date.now() - start);

        queueEvent({
          type: "network_error",
          method: details.method || "GET",
          url: sanitizeUrl(details.url),
          status: 0,
          duration,
          error: details.error || "NET_ERROR",
          message: `Network failure on ${sanitizeUrl(details.url)}: ${details.error || "failed"}`,
        });
      }
    },
    { urls: ["<all_urls>"] }
  );
}

// ----------------------------------------------------
// Navigation Events
// ----------------------------------------------------
if (chrome.webNavigation) {
  chrome.webNavigation.onCompleted.addListener((details) => {
    if (details.tabId === state.monitoredTabId && state.isMonitoring && details.frameId === 0) {
      queueEvent({
        type: "page_navigation",
        method: "GET",
        url: sanitizeUrl(details.url),
        status: 200,
        duration: 50,
        message: `Page navigation completed to ${sanitizeUrl(details.url)}`,
      });
    }
  });

  chrome.webNavigation.onErrorOccurred.addListener((details) => {
    if (details.tabId === state.monitoredTabId && state.isMonitoring && details.frameId === 0) {
      queueEvent({
        type: "navigation_error",
        method: "GET",
        url: sanitizeUrl(details.url),
        status: 500,
        duration: 50,
        error: details.error || "NAV_ERROR",
        message: `Page navigation error on ${sanitizeUrl(details.url)}: ${details.error || "failed"}`,
      });
    }
  });
}

// ----------------------------------------------------
// Content Script Message Listener (Console / JS Errors)
// ----------------------------------------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "GET_STATE") {
    sendResponse({ ...state });
    return true;
  }

  if (message.action === "START_MONITORING") {
    state.isMonitoring = true;
    state.monitoredTabId = message.tabId;
    state.monitoredUrl = message.targetUrl || "";
    state.backendUrl = message.backendUrl || state.backendUrl;
    state.eventsCount = 0;
    state.errorsCount = 0;
    state.startTime = new Date().toISOString();

    // Send initial start event
    queueEvent({
      type: "session_start",
      method: "GET",
      url: sanitizeUrl(state.monitoredUrl),
      status: 200,
      duration: 10,
      message: `Monitoring started on tab ${state.monitoredTabId} (${sanitizeUrl(state.monitoredUrl)})`,
    });

    sendResponse({ success: true, state });
    return true;
  }

  if (message.action === "STOP_MONITORING") {
    if (state.isMonitoring) {
      queueEvent({
        type: "session_stop",
        method: "GET",
        url: sanitizeUrl(state.monitoredUrl),
        status: 200,
        duration: 10,
        message: `Monitoring stopped on tab ${state.monitoredTabId}`,
      });
      flushEvents();
    }

    state.isMonitoring = false;
    sendResponse({ success: true, state });
    return true;
  }

  // Handle client-side error from content.js
  if (message.action === "CLIENT_ERROR" && state.isMonitoring) {
    if (sender.tab && sender.tab.id === state.monitoredTabId) {
      queueEvent({
        type: message.errorType || "js_error",
        method: "EVENT",
        url: sanitizeUrl(sender.tab.url || state.monitoredUrl),
        status: 500,
        duration: 10,
        error: message.error || "ClientError",
        message: message.message || "Client JavaScript error encountered",
      });
    }
    sendResponse({ received: true });
    return true;
  }
});

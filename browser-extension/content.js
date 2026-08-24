/**
 * Smart Log Analyzer - Extension Content Script
 * Listens to client-side unhandled errors and console.error on the page.
 * Strictly captures safe error metadata (no passwords, form values, or private text).
 */

(function () {
  // Capture unhandled JavaScript exceptions
  window.addEventListener("error", (event) => {
    try {
      chrome.runtime.sendMessage({
        action: "CLIENT_ERROR",
        errorType: "js_error",
        error: event.message ? String(event.message).substring(0, 150) : "ScriptError",
        message: `JavaScript Error: ${event.message || "Unknown error"} at ${event.filename ? event.filename.split("/").pop() : "inline"}:${event.lineno || 0}`,
      });
    } catch {
      // Ignore extension disconnection errors
    }
  });

  // Capture unhandled promise rejections
  window.addEventListener("unhandledrejection", (event) => {
    try {
      const reason = event.reason;
      const errorMsg = reason instanceof Error ? reason.message : String(reason);
      chrome.runtime.sendMessage({
        action: "CLIENT_ERROR",
        errorType: "promise_rejection",
        error: "UnhandledPromiseRejection",
        message: `Unhandled Promise Rejection: ${errorMsg.substring(0, 150)}`,
      });
    } catch {
      // Ignore extension disconnection errors
    }
  });
})();

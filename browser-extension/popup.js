/**
 * Smart Log Analyzer Extension - Popup Logic
 */

const targetUrlInput = document.getElementById("target-url");
const backendUrlInput = document.getElementById("backend-url");
const btnUseActive = document.getElementById("btn-use-active");
const btnToggle = document.getElementById("btn-toggle-monitor");
const statusBadge = document.getElementById("status-badge");
const statusTab = document.getElementById("status-tab");
const statusEvents = document.getElementById("status-events");
const statusErrors = document.getElementById("status-errors");

function updateUI(state) {
  if (state.isMonitoring) {
    statusBadge.textContent = "ACTIVE";
    statusBadge.className = "badge badge-active";
    btnToggle.textContent = "⏹ Stop Monitoring";
    btnToggle.className = "btn btn-danger";
    statusTab.textContent = state.monitoredUrl
      ? state.monitoredUrl.replace(/^https?:\/\//, "").substring(0, 30)
      : `Tab ${state.monitoredTabId}`;
    statusEvents.textContent = String(state.eventsCount || 0);
    statusErrors.textContent = String(state.errorsCount || 0);
  } else {
    statusBadge.textContent = "IDLE";
    statusBadge.className = "badge badge-idle";
    btnToggle.textContent = "▶ Start Monitoring";
    btnToggle.className = "btn btn-primary";
    if (!state.monitoredTabId) {
      statusTab.textContent = "None";
    }
  }
}

// Restore saved state
chrome.runtime.sendMessage({ action: "GET_STATE" }, (response) => {
  if (response) {
    updateUI(response);
    if (response.monitoredUrl) targetUrlInput.value = response.monitoredUrl;
    if (response.backendUrl) backendUrlInput.value = response.backendUrl;
  }
});

// Load saved input values
chrome.storage.local.get(["lastTargetUrl", "lastBackendUrl"], (stored) => {
  if (stored.lastTargetUrl) targetUrlInput.value = stored.lastTargetUrl;
  if (stored.lastBackendUrl) backendUrlInput.value = stored.lastBackendUrl;
});

btnUseActive.addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0]) {
      const url = tabs[0].url || "";
      try {
        const parsed = new URL(url);
        targetUrlInput.value = `${parsed.protocol}//${parsed.hostname}`;
      } catch {
        targetUrlInput.value = url;
      }
    }
  });
});

btnToggle.addEventListener("click", () => {
  chrome.runtime.sendMessage({ action: "GET_STATE" }, (state) => {
    if (state && state.isMonitoring) {
      // Stop
      chrome.runtime.sendMessage({ action: "STOP_MONITORING" }, (resp) => {
        if (resp) updateUI(resp.state || { isMonitoring: false });
      });
    } else {
      // Start — find the tab matching the target URL
      const targetUrl = targetUrlInput.value.trim();
      const backendUrl = backendUrlInput.value.trim() || "http://localhost:3000/api/monitor/events";

      if (!targetUrl) {
        alert("Please enter a target URL or click 'Select Active Tab'.");
        return;
      }

      // Save last values
      chrome.storage.local.set({ lastTargetUrl: targetUrl, lastBackendUrl: backendUrl });

      chrome.tabs.query({}, (allTabs) => {
        let matchedTab = null;

        // Try to find a tab whose URL matches
        for (const tab of allTabs) {
          if (tab.url && tab.url.includes(targetUrl.replace(/^https?:\/\//, ""))) {
            matchedTab = tab;
            break;
          }
        }

        // Fallback: use active tab
        if (!matchedTab) {
          chrome.tabs.query({ active: true, currentWindow: true }, (activeTabs) => {
            const tab = activeTabs && activeTabs[0];
            if (!tab) {
              alert("Could not find a matching tab. Please open the target site first.");
              return;
            }
            startMonitoring(tab.id, targetUrl, backendUrl);
          });
          return;
        }

        startMonitoring(matchedTab.id, targetUrl, backendUrl);
      });
    }
  });
});

function startMonitoring(tabId, targetUrl, backendUrl) {
  chrome.runtime.sendMessage(
    { action: "START_MONITORING", tabId, targetUrl, backendUrl },
    (resp) => {
      if (resp && resp.state) {
        updateUI(resp.state);
      }
    }
  );
}

// Poll for state updates every 2 seconds while popup is open
setInterval(() => {
  chrome.runtime.sendMessage({ action: "GET_STATE" }, (response) => {
    if (response) updateUI(response);
  });
}, 2000);

# Smart Log Analyzer — Browser Extension

A lightweight **Manifest V3** Chrome extension that captures safe network telemetry from a user-selected browser tab and forwards it to the Smart Log Analyzer backend for anomaly detection.

---

## ⚠️ Important Security Constraints

A standard web page **cannot** inspect arbitrary browser tabs due to browser security restrictions.

This extension overcomes that limitation by running as a privileged Chrome extension that:
- Uses `webRequest` API to observe network traffic metadata on the selected tab
- Uses `webNavigation` API for page-load events
- Uses a `content_script` to capture unhandled JavaScript errors

**What is NOT captured:**
- Passwords, form values, request bodies
- Authentication tokens or cookies
- Private page content or DOM content
- Any sensitive user data

**What IS captured (safe metadata only):**
- Timestamp
- Hostname and URL path (query parameters are stripped)
- HTTP method, status code, response duration
- Network errors (ERR_NAME_NOT_RESOLVED, etc.)
- JavaScript errors (error message, file/line only)
- Unhandled promise rejection messages (truncated)
- Page navigation events

---

## 🛠️ Installation

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top right)
3. Click **Load unpacked**
4. Select the `browser-extension/` directory from this project
5. The "Smart Log Analyzer Monitor" extension appears in your toolbar

---

## 🚀 Usage

1. Start the Smart Log Analyzer backend:
   ```bash
   npm start
   ```
2. Open the target website (e.g., `http://localhost:8080`) in Chrome
3. Click the **Smart Log Analyzer Monitor** extension icon
4. Enter the target URL (or click **Select Active Tab**)
5. Confirm the backend URL (`http://localhost:3000/api/monitor/events`)
6. Click **▶ Start Monitoring**

Telemetry is now forwarded to the backend every second. The Smart Log Analyzer dashboard at `http://localhost:3000` will show detected anomalies from the monitored tab.

---

## Backend API

- `POST /api/monitor/events` — Receives browser telemetry batches
- `GET /api/monitor/events` — Returns recent events and session summary

---

## Files

| File | Purpose |
|------|---------|
| `manifest.json` | Manifest V3 extension definition |
| `background.js` | Service worker — telemetry collection and batching |
| `content.js` | Content script — JS error capture |
| `popup.html` | Extension popup UI |
| `popup.js` | Extension popup logic |
| `README.md` | This file |

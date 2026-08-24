// Reference value pools, informed by the sample CSV (request types, status
// codes, user agents, locations) plus additional realistic values needed for
// the extra fields this project requires.

const REQUEST_TYPES = ["GET", "POST", "PUT", "DELETE"];

const USER_AGENTS = ["Chrome", "Firefox", "Safari", "Edge", "Opera", "Bot"];

const LOCATIONS = [
  "USA",
  "Brazil",
  "China",
  "France",
  "Germany",
  "India",
  "Canada",
];

const NORMAL_STATUS_CODES = [200, 200, 200, 201, 301, 403, 404];

const SEVERITIES = ["INFO", "WARNING", "ERROR", "CRITICAL"];

const EVENT_TYPES = [
  "api_request",
  "login",
  "logout",
  "payment",
  "db_query",
  "admin_access",
  "file_upload",
];

const ENDPOINTS_BY_EVENT = {
  api_request: ["/api/users", "/api/orders", "/api/products", "/api/search"],
  login: ["/api/auth/login"],
  logout: ["/api/auth/logout"],
  payment: ["/api/payment", "/api/checkout"],
  db_query: ["/api/orders", "/api/users", "/api/reports"],
  admin_access: ["/admin", "/admin/users", "/admin/settings"],
  file_upload: ["/api/upload"],
};

// Required fields validated by the ingestion API.
const REQUIRED_FIELDS = [
  "timestamp",
  "ip_address",
  "event_type",
  "severity",
  "status_code",
  "log_message",
];

// Full field set every generated log carries.
const ALL_FIELDS = [
  "timestamp",
  "ip_address",
  "request_type",
  "endpoint",
  "status_code",
  "severity",
  "event_type",
  "user_agent",
  "session_id",
  "location",
  "error_code",
  "exception_type",
  "log_message",
  "response_time_ms",
];

module.exports = {
  REQUEST_TYPES,
  USER_AGENTS,
  LOCATIONS,
  NORMAL_STATUS_CODES,
  SEVERITIES,
  EVENT_TYPES,
  ENDPOINTS_BY_EVENT,
  REQUIRED_FIELDS,
  ALL_FIELDS,
};

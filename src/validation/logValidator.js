const { REQUIRED_FIELDS, SEVERITIES } = require("../models/logSchema");

// Simple IPv4 check (good enough for this assessment; doesn't validate IPv6).
const IP_REGEX =
  /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;

function isValidTimestamp(value) {
  if (typeof value !== "string" || value.trim() === "") return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime());
}

function isValidIp(value) {
  return typeof value === "string" && IP_REGEX.test(value.trim());
}

function isValidStatusCode(value) {
  const num = Number(value);
  return Number.isInteger(num) && num >= 100 && num <= 599;
}

function isValidSeverity(value) {
  return typeof value === "string" && SEVERITIES.includes(value.toUpperCase());
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

/**
 * Validates a single log record.
 * Returns { valid: boolean, errors: string[] }.
 */
function validateLog(record) {
  const errors = [];

  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    return { valid: false, errors: ["Record is not a valid object"] };
  }

  for (const field of REQUIRED_FIELDS) {
    if (record[field] === undefined || record[field] === null || record[field] === "") {
      errors.push(`Missing required field: ${field}`);
    }
  }

  if (record.timestamp !== undefined && record.timestamp !== null && record.timestamp !== "") {
    if (!isValidTimestamp(record.timestamp)) {
      errors.push("Invalid timestamp: must be a parseable date string");
    }
  }

  if (record.ip_address !== undefined && record.ip_address !== null && record.ip_address !== "") {
    if (!isValidIp(record.ip_address)) {
      errors.push("Invalid ip_address: must be a valid IPv4 address");
    }
  }

  if (record.event_type !== undefined && record.event_type !== null && record.event_type !== "") {
    if (!isNonEmptyString(record.event_type)) {
      errors.push("Invalid event_type: must be a non-empty string");
    }
  }

  if (record.severity !== undefined && record.severity !== null && record.severity !== "") {
    if (!isValidSeverity(record.severity)) {
      errors.push(
        `Invalid severity: must be one of ${SEVERITIES.join(", ")}`
      );
    }
  }

  if (record.status_code !== undefined && record.status_code !== null && record.status_code !== "") {
    if (!isValidStatusCode(record.status_code)) {
      errors.push("Invalid status_code: must be an integer between 100 and 599");
    }
  }

  if (record.log_message !== undefined && record.log_message !== null && record.log_message !== "") {
    if (!isNonEmptyString(record.log_message)) {
      errors.push("Invalid log_message: must be a non-empty string");
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validates a batch of records.
 * Returns { valid: object[], rejected: { record, errors }[] }.
 */
function validateBatch(records) {
  const valid = [];
  const rejected = [];

  for (const record of records) {
    const { valid: isValid, errors } = validateLog(record);
    if (isValid) {
      valid.push(record);
    } else {
      rejected.push({ record, errors });
    }
  }

  return { valid, rejected };
}

module.exports = { validateLog, validateBatch };

// ph-reqKO blocker: ETag/fetch decision helpers. No browser APIs here.

/**
 * Decides what to do with a rules-fetch response status.
 * "apply" (200, body changed), "unchanged" (304), "error" (anything else).
 */
export function classifyRulesResponse(status) {
  if (status === 200) return "apply";
  if (status === 304) return "unchanged";
  return "error";
}

/**
 * True when the stored etag matches an If-None-Match header value list.
 */
export function etagMatches(ifNoneMatchHeader, etag) {
  if (!ifNoneMatchHeader || !etag) return false;
  return ifNoneMatchHeader
    .split(",")
    .some((tag) => tag.trim() === etag);
}

/**
 * Normalizes the user-configured server URL: trims, strips a trailing
 * slash, requires http(s). Returns null for invalid input.
 */
export function normalizeServerUrl(raw) {
  if (typeof raw !== "string") return null;
  const value = raw.trim().replace(/\/+$/, "");
  if (!/^https?:\/\//.test(value)) return null;
  return value;
}

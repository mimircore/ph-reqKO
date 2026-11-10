// ph-reqKO blocker: pure rule-building logic. No browser APIs here so the
// module stays unit-testable (node:test / any ESM runner).

// Resource types blocked on protected pages. main_frame is deliberately NOT
// included: the extension never blocks page navigations.
export const BLOCKED_RESOURCE_TYPES = [
  "script",
  "image",
  "xmlhttprequest",
  "sub_frame",
  "ping",
  "media",
  "font",
  "stylesheet",
  "other",
];

export const BLOCK_RULE_PRIORITY = 1;
export const PAUSE_RULE_PRIORITY = 100;
// Dynamic rule id ranges: block rules count up from 1; pause rules live in
// a high, non-overlapping range derived from the domain hash.
export const PAUSE_RULE_ID_BASE = 1000000000;

// Domains are PACKED into rules via condition.requestDomains: one rule can
// carry many domains (Chrome 101+, no documented per-rule entry cap; the
// hard cap is on the NUMBER of rules: 30000 dynamic in Chrome 121+, and
// requestDomains matches subdomains too). 5000 domains per rule keeps each
// rule object small and yields <= 6 rules for a 30000-domain list.
export const DOMAINS_PER_RULE = 5000;

/**
 * Builds the declarativeNetRequest urlFilter for a plain domain.
 * `||domain^` matches the domain and every subdomain.
 */
export function domainToUrlFilter(domain) {
  return "||" + domain + "^";
}

/**
 * Validates that a server-supplied entry is a safe plain domain:
 * lowercase labels of [a-z0-9-], no scheme/path/wildcards. Returns the
 * normalized domain or null (caller counts it as skipped).
 */
export function sanitizeDomain(domain) {
  if (typeof domain !== "string") return null;
  const value = domain.trim().toLowerCase().replace(/\.$/, "");
  if (value.length === 0 || value.length > 253) return null;
  if (value.includes("/") || value.includes(":") || value.includes("*")) return null;
  const labels = value.split(".");
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) return null;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label)) return null;
  }
  return value;
}

/**
 * Validates a /api/v1/extension/rules payload.
 * Returns {version, count, domains, truncated, skipped} with sanitized
 * domains, or null when the payload shape is wrong.
 */
export function parseRulesPayload(payload) {
  if (payload === null || typeof payload !== "object") return null;
  if (typeof payload.version !== "number") return null;
  if (!Array.isArray(payload.domains)) return null;
  if (typeof payload.count !== "number") return null;
  if (typeof payload.truncated !== "boolean") return null;
  const domains = [];
  let skipped = typeof payload.skipped === "number" ? payload.skipped : 0;
  for (const raw of payload.domains) {
    const clean = sanitizeDomain(raw);
    if (clean === null) {
      skipped += 1;
    } else {
      domains.push(clean);
    }
  }
  return {
    version: payload.version,
    count: payload.count,
    domains,
    truncated: payload.truncated,
    skipped,
  };
}

/**
 * Builds declarativeNetRequest BLOCK rules for the domain list.
 * Deterministic: domains are sorted, ids assigned sequentially from startId.
 * resourceTypes cover sub-resources only — never main_frame.
 */
export function buildDnrRules(domains, startId = 1) {
  const sorted = [...domains].sort();
  return sorted.map((domain, index) => ({
    id: startId + index,
    priority: BLOCK_RULE_PRIORITY,
    action: { type: "block" },
    condition: {
      urlFilter: domainToUrlFilter(domain),
      resourceTypes: [...BLOCKED_RESOURCE_TYPES],
    },
  }));
}

/**
 * Packs domains into a SMALL number of rules using condition.requestDomains
 * (Chrome 101+ / Firefox, matches the domain and its subdomains). Chunks of
 * DOMAINS_PER_RULE domains per rule keep each rule object modest; no domain
 * is lost or duplicated (sorted dedupe). ids are sequential from startId.
 */
export function buildPackedRules(domains, startId = 1) {
  const unique = [...new Set(domains)].sort();
  const chunks = chunkArray(unique, DOMAINS_PER_RULE);
  return chunks.map((chunk, index) => ({
    id: startId + index,
    priority: BLOCK_RULE_PRIORITY,
    action: { type: "block" },
    condition: {
      requestDomains: [...chunk],
      resourceTypes: [...BLOCKED_RESOURCE_TYPES],
    },
  }));
}

/**
 * Splits an array into chunks of at most `size` (for updateDynamicRules
 * message-size safety).
 */
export function chunkArray(items, size) {
  const chunks = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}

/**
 * Atomic replace plan for updateDynamicRules: the ids of all currently
 * installed extension-managed rules to remove, and the new rules to add.
 */
export function replacePlan(oldRuleIds, newRules) {
  return {
    removeRuleIds: [...oldRuleIds],
    addRules: newRules,
  };
}

/**
 * Builds a dynamic ALLOW rule ("Pause on this site") with a priority high
 * enough to override every block rule, for the given site origin host.
 */
export function buildPauseRule(host, existingPauseIds) {
  const domain = sanitizeDomain(host);
  if (domain === null) return null;
  let id = PAUSE_RULE_ID_BASE + (hashToPositive(domain) % 1000000);
  // Avoid collisions with other paused sites
  while (existingPauseIds.includes(id)) {
    id += 1;
  }
  return {
    id,
    priority: PAUSE_RULE_PRIORITY,
    action: { type: "allow" },
    condition: {
      urlFilter: "||" + domain + "^",
      resourceTypes: [...BLOCKED_RESOURCE_TYPES, "main_frame"],
    },
  };
}

function hashToPositive(text) {
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    hash = (hash * 31 + text.charCodeAt(i)) >>> 0;
  }
  return hash;
}

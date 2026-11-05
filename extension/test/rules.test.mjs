// node:test unit tests for the pure logic modules.
// Run with: node --test extension/test/
// STATUS: NOT RUN on the development machine (Node.js is not installed
// there) - see docs/06-browser-extension.md verification table. The tests
// are shipped so they can be run anywhere Node.js >= 18 is available.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  domainToUrlFilter,
  sanitizeDomain,
  parseRulesPayload,
  buildDnrRules,
  chunkArray,
  replacePlan,
  buildPauseRule,
} from "../lib/rules.js";
import {
  aggregateMatchedRules,
  mergeQueue,
  buildReportBatch,
} from "../lib/report.js";
import {
  classifyRulesResponse,
  etagMatches,
  normalizeServerUrl,
} from "../lib/fetch.js";

// ── rules.js ───────────────────────────────────────────────────────────────────

test("domainToUrlFilter wraps domains in || ... ^", () => {
  assert.equal(domainToUrlFilter("ads.example.com"), "||ads.example.com^");
});

test("sanitizeDomain accepts plain domains and rejects junk", () => {
  assert.equal(sanitizeDomain("ADS.Example.COM."), "ads.example.com");
  assert.equal(sanitizeDomain("a-b.example.co"), "a-b.example.co");
  assert.equal(sanitizeDomain(""), null);
  assert.equal(sanitizeDomain("not a domain!"), null);
  assert.equal(sanitizeDomain("https://x.com"), null);
  assert.equal(sanitizeDomain("*.example.com"), null);
  assert.equal(sanitizeDomain("localhost"), null); // single label
  assert.equal(sanitizeDomain("a".repeat(300)), null);
});

test("parseRulesPayload validates shape and sanitizes domains", () => {
  const parsed = parseRulesPayload({
    version: 7,
    count: 3,
    domains: ["a.test", "BAD!", "b.test"],
    truncated: false,
    skipped: 1,
  });
  assert.deepEqual(parsed.domains, ["a.test", "b.test"]);
  assert.equal(parsed.skipped, 2); // 1 from payload + 1 sanitized out
  assert.equal(parseRulesPayload({ nope: true }), null);
  assert.equal(parseRulesPayload(null), null);
});

test("buildDnrRules sorts domains, assigns sequential ids, blocks sub-resources only", () => {
  const rules = buildDnrRules(["b.test", "a.test"], 1);
  assert.equal(rules.length, 2);
  assert.equal(rules[0].id, 1);
  assert.equal(rules[0].condition.urlFilter, "||a.test^");
  assert.equal(rules[1].id, 2);
  assert.deepEqual(rules[0].condition.resourceTypes.sort(), [
    "font", "image", "media", "other", "ping", "script", "stylesheet",
    "sub_frame", "xmlhttprequest",
  ]);
  assert.ok(!rules[0].condition.resourceTypes.includes("main_frame"));
  assert.equal(rules[0].action.type, "block");
});

test("chunkArray and replacePlan", () => {
  assert.deepEqual(chunkArray([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]]);
  const plan = replacePlan([10, 11], [{ id: 1 }]);
  assert.deepEqual(plan.removeRuleIds, [10, 11]);
  assert.deepEqual(plan.addRules, [{ id: 1 }]);
});

test("buildPauseRule allows main_frame with high priority", () => {
  const rule = buildPauseRule("example.com", []);
  assert.ok(rule.id >= 1000000000);
  assert.equal(rule.priority, 100);
  assert.equal(rule.action.type, "allow");
  assert.ok(rule.condition.resourceTypes.includes("main_frame"));
  const second = buildPauseRule("example.com", [rule.id]);
  assert.notEqual(second.id, rule.id);
});

// ── report.js ──────────────────────────────────────────────────────────────────

test("aggregateMatchedRules groups by http(s) host only", () => {
  const entries = [
    { request: { url: "http://ads.test/x.js" } },
    { request: { url: "http://ads.test/y.js" } },
    { request: { url: "https://tracker.test/pixel" } },
    { request: { url: "file:///etc/passwd" } },   // non-http: skipped
    { request: {} },                               // no url: skipped
    {},                                            // junk: skipped
  ];
  assert.deepEqual(aggregateMatchedRules(entries), [
    { domain: "ads.test", count: 2 },
    { domain: "tracker.test", count: 1 },
  ]);
});

test("mergeQueue sums same-domain counts and caps the queue", () => {
  const queue = [{ domain: "a.test", count: 5 }];
  const fresh = [
    { domain: "a.test", count: 2 },
    { domain: "b.test", count: 1 },
  ];
  assert.deepEqual(mergeQueue(queue, fresh), [
    { domain: "a.test", count: 7 },
    { domain: "b.test", count: 1 },
  ]);
  // Cap: 5001 distinct domains -> smallest dropped until 5000 remain
  let big = [];
  for (let i = 0; i < 5010; i++) big.push({ domain: "d" + i + ".test", count: 10 });
  const capped = mergeQueue([], big);
  assert.ok(capped.length <= 5000);
});

test("buildReportBatch caps and stamps", () => {
  const pending = Array.from({ length: 700 }, (_, i) => ({ domain: "d" + i, count: 1 }));
  const { batch, remaining } = buildReportBatch(pending, 12345);
  assert.equal(batch.length, 500);
  assert.equal(remaining.length, 200);
  assert.equal(batch[0].ts, 12345);
});

// ── fetch.js ───────────────────────────────────────────────────────────────────

test("classifyRulesResponse", () => {
  assert.equal(classifyRulesResponse(200), "apply");
  assert.equal(classifyRulesResponse(304), "unchanged");
  assert.equal(classifyRulesResponse(500), "error");
  assert.equal(classifyRulesResponse(404), "error");
});

test("etagMatches", () => {
  assert.equal(etagMatches('"abc", "def"', '"def"'), true);
  assert.equal(etagMatches('"abc"', '"xyz"'), false);
  assert.equal(etagMatches("", '"abc"'), false);
});

test("normalizeServerUrl", () => {
  assert.equal(normalizeServerUrl(" http://127.0.0.1:8080/ "), "http://127.0.0.1:8080");
  assert.equal(normalizeServerUrl("https://lan.example.com"), "https://lan.example.com");
  assert.equal(normalizeServerUrl("ftp://x"), null);
  assert.equal(normalizeServerUrl("127.0.0.1:8080"), null);
});

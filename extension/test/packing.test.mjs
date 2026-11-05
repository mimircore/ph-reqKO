// Packing tests for buildPackedRules (objective: requestDomains packing).
// STATUS: NOT RUN on the development machine (Node.js not installed) - see
// docs/06-browser-extension.md. Run with: node --test extension/test/

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildPackedRules,
  DOMAINS_PER_RULE,
  buildDnrRules,
} from "../lib/rules.js";

test("DOMAINS_PER_RULE is within documented limits", () => {
  // Chrome: 30000 dynamic rules max; no per-rule requestDomains entry cap is
  // documented. 5000 domains/rule -> <= 6 rules for a 30000-domain list.
  assert.equal(DOMAINS_PER_RULE, 5000);
  assert.ok(DOMAINS_PER_RULE > 0);
});

test("packing: chunk sizes, sorted, sequential ids", () => {
  const domains = Array.from({ length: 11000 }, (_, i) => "d" + i + ".test");
  const rules = buildPackedRules(domains, 1);
  // 11000 domains / 5000 per rule -> 3 rules (5000, 5000, 1000)
  assert.equal(rules.length, 3);
  assert.deepEqual(
    rules.map((r) => r.id),
    [1, 2, 3],
  );
  for (const rule of rules) {
    assert.equal(rule.action.type, "block");
    assert.equal(rule.priority, 1);
    assert.ok(rule.condition.requestDomains.length <= 5000);
    assert.ok(rule.condition.requestDomains.length > 0);
    assert.ok(!rule.condition.resourceTypes.includes("main_frame"));
    // requestDomains must NOT have urlFilter (mutually exclusive condition)
    assert.equal(rule.condition.urlFilter, undefined);
  }
});

test("packing: no domain lost or duplicated (round trip)", () => {
  const domains = [];
  for (let i = 0; i < 12345; i++) domains.push("d" + i + ".example.org");
  const rules = buildPackedRules(domains, 1);
  const packed = rules.flatMap((r) => r.condition.requestDomains).sort();
  const expected = [...new Set(domains)].sort();
  assert.deepEqual(packed, expected); // exact round trip: nothing lost/duplicated
  assert.equal(new Set(packed).size, packed.length); // no duplicates
});

test("packing: dedupes the input list", () => {
  const rules = buildPackedRules(["a.test", "a.test", "b.test"], 1);
  assert.equal(rules.length, 1);
  assert.deepEqual(rules[0].condition.requestDomains, ["a.test", "b.test"]);
});

test("packing: empty list -> no rules", () => {
  assert.deepEqual(buildPackedRules([], 1), []);
});

test("per-domain urlFilter rules still available for other uses", () => {
  const rules = buildDnrRules(["a.test"], 1);
  assert.equal(rules[0].condition.urlFilter, "||a.test^");
});

// ph-reqKO blocker: MV3 background (Chrome: service worker / Firefox: event
// page, both as ES module — see manifest "background" keys).
//
// Fail-open guarantees:
// - if the server is unreachable, the last good dynamic rules stay installed;
// - if metrics/reporting fails, blocking is unaffected;
// - every dynamic rule is replaced atomically in one updateDynamicRules call.

import {
  buildDnrRules,
  parseRulesPayload,
  replacePlan,
  buildPauseRule,
} from "./lib/rules.js";
import {
  aggregateMatchedRules,
  mergeQueue,
  buildReportBatch,
} from "./lib/report.js";
import { classifyRulesResponse } from "./lib/fetch.js";

const SYNC_ALARM = "ph-reqko-sync";
const REPORT_ALARM = "ph-reqko-report";
const SYNC_PERIOD_MINUTES = 30;
const REPORT_PERIOD_MINUTES = 30;
const RULES_CHUNK_SIZE = 5000; // well under Chrome's 30000 dynamic-rule cap

const DEFAULTS = {
  serverUrl: "http://127.0.0.1:8080",
  clientToken: "",
  etag: "",
  lastSync: 0,
  lastError: "",
  ruleIds: [],
  ruleCount: 0,
  truncated: false,
  blockedToday: { day: "", total: 0 },
  pendingReports: [],
  pausedSites: [],
};

// ── storage helpers (browser API, thin wrappers) ──────────────────────────────

async function getConfig() {
  const stored = await browser.storage.local.get(DEFAULTS);
  return { ...DEFAULTS, ...stored };
}

function saveConfig(patch) {
  return browser.storage.local.set(patch);
}

// ── rule sync ──────────────────────────────────────────────────────────────────

async function syncRules() {
  const cfg = await getConfig();
  if (!cfg.clientToken) {
    await saveConfig({ lastError: "No client token configured" });
    return;
  }
  try {
    const headers = { Authorization: "Bearer " + cfg.clientToken };
    if (cfg.etag) headers["If-None-Match"] = cfg.etag;
    const response = await fetch(cfg.serverUrl + "/api/v1/extension/rules", { headers });
    const kind = classifyRulesResponse(response.status);

    if (kind === "unchanged") {
      await saveConfig({ lastSync: Date.now(), lastError: "" });
      return;
    }
    if (kind === "error") {
      // Fail-open: keep the last good rules
      await saveConfig({ lastError: "HTTP " + response.status });
      return;
    }

    const payload = await response.json();
    const parsed = parseRulesPayload(payload);
    if (parsed === null) {
      await saveConfig({ lastError: "Malformed rules payload" });
      return;
    }

    const newRules = buildDnrRules(parsed.domains, 1);
    const plan = replacePlan(cfg.ruleIds, newRules);
    // Atomic replace: remove every rule we installed, add the new set
    await browser.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: plan.removeRuleIds,
      addRules: plan.addRules,
    });

    const etag = response.headers.get("ETag") || "";
    await saveConfig({
      etag,
      lastSync: Date.now(),
      lastError: "",
      ruleIds: newRules.map((rule) => rule.id),
      ruleCount: newRules.length,
      truncated: parsed.truncated,
    });
    await updateBadge();
  } catch (err) {
    // Fail-open: network down, server down, malformed JSON - keep old rules
    await saveConfig({ lastError: String(err) });
  }
}

// ── pause on this site ─────────────────────────────────────────────────────────

async function pauseOnSite(host) {
  const cfg = await getConfig();
  const rule = buildPauseRule(host, cfg.pausedSites.map((p) => p.id));
  if (rule === null) return false;
  await browser.declarativeNetRequest.updateDynamicRules({
    addRules: [rule],
  });
  const pausedSites = [...cfg.pausedSites, { host: rule.condition.urlFilter, id: rule.id }];
  await saveConfig({ pausedSites });
  return true;
}

async function resumeSite(host) {
  const cfg = await getConfig();
  const urlFilter = "||" + host.toLowerCase().replace(/\.$/, "") + "^";
  const remove = cfg.pausedSites.filter((p) => p.host === urlFilter).map((p) => p.id);
  if (remove.length === 0) return false;
  await browser.declarativeNetRequest.updateDynamicRules({ removeRuleIds: remove });
  await saveConfig({
    pausedSites: cfg.pausedSites.filter((p) => !remove.includes(p.id)),
  });
  return true;
}

// ── reporting ──────────────────────────────────────────────────────────────────

async function collectAndQueueReport() {
  const cfg = await getConfig();
  // getMatchedRules quota: 20 calls / 10 minutes (Chrome). One call per
  // 30-minute alarm plus manual sync is far below the quota.
  let entries;
  try {
    entries = await browser.declarativeNetRequest.getMatchedRules();
  } catch (err) {
    // Firefox: requires extensions.dnr.feedback=true; Chrome: permission
    // declarativeNetRequestFeedback. Absent -> reporting disabled, blocking
    // unaffected.
    return;
  }
  const fresh = aggregateMatchedRules(entries.rules || []);
  if (fresh.length === 0) return;
  const pending = mergeQueue(cfg.pendingReports, fresh);
  await saveConfig({ pendingReports: pending });
  await updateBadge();
}

async function sendReport() {
  const cfg = await getConfig();
  if (!cfg.clientToken || cfg.pendingReports.length === 0) return;
  const { batch, remaining } = buildReportBatch(cfg.pendingReports, Math.floor(Date.now() / 1000));
  if (batch.length === 0) return;
  try {
    const response = await fetch(cfg.serverUrl + "/api/v1/extension/report", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + cfg.clientToken,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ events: batch }),
    });
    if (response.status === 202) {
      await saveConfig({ pendingReports: remaining });
    }
    // On failure the queue stays; the next alarm retries (capped by
    // mergeQueue so it can never grow unbounded).
  } catch (err) {
    // Reporting failures must never affect blocking: queue kept, retried.
  }
}

// ── badge ──────────────────────────────────────────────────────────────────────

function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

async function updateBadge() {
  const cfg = await getConfig();
  const day = todayKey();
  const total = cfg.blockedToday.day === day ? cfg.blockedToday.total : 0;
  await browser.action.setBadgeText({ text: total > 0 ? String(total) : "" });
  await browser.action.setBadgeBackgroundColor({ color: "#d64545" });
}

async function bumpBlockedToday(delta) {
  const cfg = await getConfig();
  const day = todayKey();
  const total = (cfg.blockedToday.day === day ? cfg.blockedToday.total : 0) + delta;
  await saveConfig({ blockedToday: { day, total } });
  await updateBadge();
}

// ── message handling (popup/options) ──────────────────────────────────────────

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    switch (message && message.type) {
      case "getStatus": {
        const cfg = await getConfig();
        sendResponse({
          serverUrl: cfg.serverUrl,
          lastSync: cfg.lastSync,
          lastError: cfg.lastError,
          ruleCount: cfg.ruleCount,
          truncated: cfg.truncated,
          blockedToday: cfg.blockedToday,
          pausedSites: cfg.pausedSites,
          pendingReports: cfg.pendingReports.length,
          hasToken: Boolean(cfg.clientToken),
        });
        return;
      }
      case "syncNow":
        await syncRules();
        await collectAndQueueReport();
        await sendReport();
        sendResponse({ ok: true });
        return;
      case "pauseSite":
        sendResponse({ ok: await pauseOnSite(message.host) });
        return;
      case "resumeSite":
        sendResponse({ ok: await resumeSite(message.host) });
        return;
      case "thisTabBlocked": {
        // User-initiated popup open: one getMatchedRules call, far below
        // the 20-calls-per-10-minutes quota.
        try {
          const result = await browser.declarativeNetRequest.getMatchedRules({
            tabId: message.tabId,
          });
          sendResponse({ count: (result.rules || []).length });
        } catch (err) {
          sendResponse({ count: null }); // Firefox without dnr.feedback pref
        }
        return;
      }
      default:
        sendResponse({ ok: false });
    }
  })();
  return true; // async sendResponse
});

// ── lifecycle ──────────────────────────────────────────────────────────────────

browser.runtime.onInstalled.addListener(() => {
  browser.alarms.create(SYNC_ALARM, { periodInMinutes: SYNC_PERIOD_MINUTES });
  browser.alarms.create(REPORT_ALARM, { periodInMinutes: REPORT_PERIOD_MINUTES });
  syncRules();
});

browser.runtime.onStartup.addListener(() => {
  syncRules();
});

browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === SYNC_ALARM) syncRules();
  if (alarm.name === REPORT_ALARM) {
    collectAndQueueReport().then(sendReport);
  }
});

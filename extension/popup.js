// ph-reqKO blocker popup (ES module; all DOM writes via textContent).

import { sanitizeDomain } from "./lib/rules.js";

const el = (id) => document.getElementById(id);

function fmtTime(ms) {
  if (!ms) return "never";
  return new Date(ms).toLocaleTimeString();
}

async function currentTab() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
}

function siteHost(url) {
  try {
    return new URL(url).hostname;
  } catch (err) {
    return null;
  }
}

async function refresh() {
  const status = await browser.runtime.sendMessage({ type: "getStatus" });
  el("today-count").textContent = String(status.blockedToday.total || 0);
  el("rule-count").textContent = String(status.ruleCount);
  el("last-sync").textContent = fmtTime(status.lastSync);

  const errorNode = el("error");
  if (status.lastError) {
    errorNode.textContent = "Last error: " + status.lastError;
    errorNode.hidden = false;
  } else {
    errorNode.hidden = true;
  }
  if (!status.hasToken) {
    errorNode.textContent = "No client token configured — open Options.";
    errorNode.hidden = false;
  }

  const tab = await currentTab();
  const host = tab && tab.url ? siteHost(tab.url) : null;
  const paused = status.pausedSites.some((p) => p.host === "||" + host + "^");
  el("pause-site").hidden = paused || !host;
  el("resume-site").hidden = !paused;

  if (tab && typeof tab.id === "number") {
    const answer = await browser.runtime.sendMessage({
      type: "thisTabBlocked",
      tabId: tab.id,
    });
    el("tab-count").textContent =
      answer.count === null ? "n/a (Firefox pref)" : String(answer.count);
  } else {
    el("tab-count").textContent = "–";
  }
}

el("sync-now").addEventListener("click", async () => {
  await browser.runtime.sendMessage({ type: "syncNow" });
  await refresh();
});

el("pause-site").addEventListener("click", async () => {
  const tab = await currentTab();
  const host = siteHost(tab.url);
  if (host && sanitizeDomain(host) !== null) {
    await browser.runtime.sendMessage({ type: "pauseSite", host });
    await refresh();
  }
});

el("resume-site").addEventListener("click", async () => {
  const tab = await currentTab();
  const host = siteHost(tab.url);
  if (host) {
    await browser.runtime.sendMessage({ type: "resumeSite", host });
    await refresh();
  }
});

refresh();

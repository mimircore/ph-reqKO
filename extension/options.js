// ph-reqKO blocker options page (ES module; DOM writes via textContent).

import { normalizeServerUrl } from "./lib/fetch.js";

const el = (id) => document.getElementById(id);

function showStatus(text, isError) {
  const node = el("status");
  node.textContent = text;
  node.className = "status " + (isError ? "error" : "ok");
  node.hidden = false;
}

async function load() {
  const stored = await browser.storage.local.get({
    serverUrl: "http://127.0.0.1:8080",
    clientToken: "",
  });
  el("server-url").value = stored.serverUrl;
  el("client-token").value = stored.clientToken;
}

el("save").addEventListener("click", async () => {
  const serverUrl = normalizeServerUrl(el("server-url").value);
  if (serverUrl === null) {
    showStatus("Invalid server URL: must start with http:// or https://", true);
    return;
  }
  const clientToken = el("client-token").value.trim();
  if (!clientToken) {
    showStatus("Client token is required (REQKO_CLIENT_TOKEN of your server).", true);
    return;
  }
  await browser.storage.local.set({ serverUrl, clientToken });
  showStatus("Saved. Use Sync now in the popup to fetch rules.", false);
});

// Firefox: blocking works without host permissions (base DNR permission),
// but Chrome requires host access for the blocked domains. Grant broad
// optional host access with an explicit user action.
el("grant-hosts").addEventListener("click", async () => {
  const granted = await browser.permissions.request({
    origins: ["http://*/*", "https://*/*"],
  });
  showStatus(
    granted ? "Site access granted." : "Site access not granted.",
    !granted,
  );
});

load();

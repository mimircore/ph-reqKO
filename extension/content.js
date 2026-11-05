// ph-reqKO blocker: cosmetic filtering content script.
//
// Injects ONE <style> element at document_start hiding curated ad-container
// selectors read from browser.storage.local (synced from the ph-reqKO
// server via /api/v1/extension/cosmetic). Never executes remote code: the
// CSS text is validated server-side AND client-side before injection.
//
// Per-site pause: if the current hostname matches a paused site (managed by
// the background's pause/resume feature), the style is removed and not
// re-applied until the site is resumed.

const COSMETIC_SELECTORS_KEY = "cosmeticSelectors";
const COSMETIC_ENABLED_KEY = "cosmeticEnabled";
const PAUSED_SITES_KEY = "pausedSites";
const STYLE_ID = "ph-reqko-cosmetic-style";

function hostMatchesPaused(host, pausedSites) {
  // pausedSites entries are urlFilter strings: "||host^"
  for (const entry of pausedSites || []) {
    if (typeof entry !== "string") continue;
    const host2 = entry.replace(/^\|\|/, "").replace(/\^$/, "");
    if (!host2) continue;
    if (host === host2 || host.endsWith("." + host2)) return true;
  }
  return false;
}

function isSelectorSafe(selector) {
  if (typeof selector !== "string") return false;
  if (selector.length === 0 || selector.length > 256) return false;
  const lowered = selector.toLowerCase();
  for (const forbidden of ["{", "}", "<", ">", "@import", "url(", "expression", "javascript:", "behavior", "-moz-binding"]) {
    if (lowered.includes(forbidden)) return false;
  }
  return true;
}

function buildCss(selectors) {
  const safe = selectors.filter(isSelectorSafe);
  if (safe.length === 0) return "";
  // Escape nothing: every selector is validated to exclude braces and other
  // CSS-breaking/injection characters, so direct interpolation is safe.
  return safe.join(",\n") + " { display: none !important; }\n";
}

function injectStyle(css) {
  if (css.length === 0) return;
  const existing = document.getElementById(STYLE_ID);
  if (existing) existing.remove();
  const style = document.createElement("style");
  style.id = STYLE_ID;
  style.textContent = css;
  (document.head || document.documentElement).appendChild(style);
}

function removeStyle() {
  const existing = document.getElementById(STYLE_ID);
  if (existing) existing.remove();
}

async function apply() {
  const stored = await browser.storage.local.get({
    cosmeticSelectors: [],
    cosmeticEnabled: true,
    pausedSites: [],
  });
  const host = location.hostname;
  if (!stored.cosmeticEnabled || hostMatchesPaused(host, stored.pausedSites)) {
    removeStyle();
    return;
  }
  const css = buildCss(stored.cosmeticSelectors || []);
  if (css.length > 0) injectStyle(css);
  else removeStyle();
}

browser.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes.cosmeticSelectors || changes.cosmeticEnabled || changes.pausedSites)) {
    apply();
  }
});

apply();

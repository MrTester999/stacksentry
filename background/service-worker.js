import { analyzeEvidence, summarizeTechnologies } from "../shared/detector.js";
import { lookupTechnologyVulnerabilities, summarizeVulnerabilities, vulnerabilityCacheKey } from "../shared/vulnerabilities.js";

const RESULT_PREFIX = "scanResult:";
const HEADER_PREFIX = "responseHeaders:";
const SETTINGS_KEY = "settings";
const CACHE_KEY = "cveCache";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_CVE_LOOKUPS = 12;

async function settings() {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  return {
    enabled: stored[SETTINGS_KEY]?.enabled !== false,
    autoScan: stored[SETTINGS_KEY]?.autoScan !== false,
    checkCves: stored[SETTINGS_KEY]?.checkCves !== false,
    excludedHosts: Array.isArray(stored[SETTINGS_KEY]?.excludedHosts) ? stored[SETTINGS_KEY].excludedHosts : []
  };
}

async function saveSettings(next) {
  const clean = {
    enabled: next.enabled !== false,
    autoScan: next.autoScan !== false,
    checkCves: next.checkCves !== false,
    excludedHosts: [...new Set((next.excludedHosts || []).map((item) => String(item).toLowerCase()).filter(Boolean))].sort()
  };
  await chrome.storage.local.set({ [SETTINGS_KEY]: clean });
  return clean;
}

function isSupportedUrl(url = "") {
  return /^https?:\/\//i.test(url);
}

function hostname(url = "") {
  try { return new URL(url).hostname.toLowerCase(); }
  catch { return ""; }
}

function isExcluded(url, excludedHosts) {
  const host = hostname(url);
  return excludedHosts.some((entry) => host === entry || host.endsWith(`.${entry}`));
}

async function setBadge(tabId, result = null, state = "") {
  let text = "";
  let color = "#1c9f91";
  let title = "StackSentry";
  if (state === "scanning") {
    text = "…";
    color = "#4267d5";
    title = "StackSentry is analyzing this site";
  } else if (state === "excluded") {
    text = "×";
    color = "#667085";
    title = "StackSentry auto-scan is excluded on this site";
  } else if (result) {
    text = String(Math.min(99, result.summary.technologies.total));
    const vulnerable = result.summary.vulnerabilities.total;
    color = vulnerable ? "#e5485d" : "#1c9f91";
    title = vulnerable
      ? `StackSentry: ${result.summary.technologies.total} technologies · ${vulnerable} known vulnerabilities`
      : `StackSentry: ${result.summary.technologies.total} technologies detected`;
  }
  await Promise.all([
    chrome.action.setBadgeText({ tabId, text }).catch(() => {}),
    chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {}),
    chrome.action.setTitle({ tabId, title }).catch(() => {})
  ]);
}

function headerObject(responseHeaders = []) {
  const output = {};
  for (const header of responseHeaders) {
    const name = String(header.name || "").toLowerCase();
    if (!name || name === "set-cookie") continue;
    const value = String(header.value || "");
    output[name] = output[name] ? `${output[name]}, ${value}` : value;
  }
  return output;
}

chrome.webRequest.onHeadersReceived.addListener((details) => {
  if (details.tabId < 0 || details.type !== "main_frame") return;
  void chrome.storage.session.set({
    [`${HEADER_PREFIX}${details.tabId}`]: {
      url: details.url,
      statusCode: details.statusCode,
      headers: headerObject(details.responseHeaders),
      capturedAt: Date.now()
    }
  });
}, { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] }, ["responseHeaders"]);

async function collectDomEvidence(tabId) {
  const [{ result }] = await chrome.scripting.executeScript({
    target: { tabId },
    func: () => {
      const MAX_HTML = 1_500_000;
      const html = document.documentElement?.outerHTML || "";
      return {
        title: document.title,
        url: location.href,
        html: html.slice(0, MAX_HTML),
        htmlTruncated: html.length > MAX_HTML,
        scripts: [...document.scripts].slice(0, 600).map((script) => ({ src: script.src || "", type: script.type || "" })),
        links: [...document.querySelectorAll("link[href]")].slice(0, 600).map((link) => ({ href: link.href, rel: link.rel || "" })),
        resources: performance.getEntriesByType("resource").slice(0, 1200).map((entry) => ({
          name: entry.name || "",
          initiatorType: entry.initiatorType || ""
        })),
        meta: [...document.querySelectorAll("meta")].slice(0, 250).map((meta) => ({
          name: meta.name || "",
          property: meta.getAttribute("property") || "",
          httpEquiv: meta.httpEquiv || "",
          content: (meta.content || "").slice(0, 500)
        }))
      };
    }
  });
  return result;
}

async function collectGlobalEvidence(tabId) {
  const [{ result }] = await chrome.scripting.executeScript({
    target: { tabId },
    world: "MAIN",
    func: () => {
      const value = (reader) => {
        try {
          const found = reader();
          return typeof found === "string" || typeof found === "number" ? String(found) : found ? "true" : "";
        } catch { return ""; }
      };
      return {
        jquery: value(() => window.jQuery?.fn?.jquery),
        select2: value(() => window.jQuery?.fn?.select2),
        popper: value(() => window.Popper?.version || window.Popper?.Defaults),
        fontawesome: value(() => window.FontAwesome || document.querySelector("style[data-fa-i2svg], link[href*='font-awesome'], link[href*='fontawesome']")),
        react: value(() => window.React?.version || document.querySelector("[data-reactroot]")),
        nextjs: value(() => window.__NEXT_DATA__),
        vue: value(() => window.Vue?.version || document.querySelector("[data-v-app]")),
        nuxt: value(() => window.__NUXT__ || document.querySelector("#__nuxt")),
        angular: value(() => window.angular?.version?.full || document.querySelector("[ng-version]")),
        lodash: value(() => window._?.VERSION),
        axios: value(() => window.axios?.VERSION),
        moment: value(() => window.moment?.version),
        bootstrap: value(() => window.bootstrap?.Tooltip?.VERSION || window.jQuery?.fn?.tooltip?.Constructor?.VERSION),
        gsap: value(() => window.gsap?.version),
        alpine: value(() => window.Alpine?.version),
        requirejs: value(() => window.requirejs?.version),
        sentry: value(() => window.Sentry?.SDK_VERSION || window.__SENTRY__)
      };
    }
  });
  return result || {};
}

async function cachedLookup(technology) {
  const key = vulnerabilityCacheKey(technology);
  if (!key) return lookupTechnologyVulnerabilities(technology);
  const stored = await chrome.storage.local.get(CACHE_KEY);
  const cache = stored[CACHE_KEY] || {};
  const existing = cache[key];
  if (existing && Date.now() - existing.savedAt < CACHE_TTL_MS) return { ...existing.result, cached: true };
  const result = await lookupTechnologyVulnerabilities(technology);
  cache[key] = { savedAt: Date.now(), result };
  const entries = Object.entries(cache).sort((a, b) => b[1].savedAt - a[1].savedAt).slice(0, 300);
  await chrome.storage.local.set({ [CACHE_KEY]: Object.fromEntries(entries) });
  return result;
}

async function addVulnerabilities(technologies, enabled) {
  const candidates = technologies.filter((item) => item.version && (item.package || item.cpe)).slice(0, MAX_CVE_LOOKUPS);
  if (!enabled || !candidates.length) return technologies.map((item) => ({ ...item, vulnerabilityStatus: item.version ? "unsupported" : "version-unknown", vulnerabilities: [] }));
  const results = new Map();
  for (const technology of candidates) {
    try {
      results.set(technology.id, await cachedLookup(technology));
      if (technology.cpe) await new Promise((resolve) => setTimeout(resolve, 650));
    } catch (error) {
      results.set(technology.id, { status: "error", error: error?.message || String(error), vulnerabilities: [] });
    }
  }
  return technologies.map((technology) => {
    const result = results.get(technology.id);
    if (!result) return { ...technology, vulnerabilityStatus: technology.version ? "unsupported" : "version-unknown", vulnerabilities: [] };
    return { ...technology, vulnerabilityStatus: result.status, vulnerabilitySource: result.source || "", vulnerabilityError: result.error || "", vulnerabilities: result.vulnerabilities || [], cveCached: Boolean(result.cached) };
  });
}

async function scanTab(tabId, options = {}) {
  const tab = await chrome.tabs.get(tabId);
  if (!isSupportedUrl(tab.url)) throw new Error("Open a normal HTTP or HTTPS website first");
  const currentSettings = await settings();
  if (!currentSettings.enabled) throw new Error("StackSentry is turned off");
  if (!options.force && isExcluded(tab.url, currentSettings.excludedHosts)) {
    await setBadge(tabId, null, "excluded");
    throw new Error("This site is excluded from automatic scanning");
  }
  await setBadge(tabId, null, "scanning");
  const [dom, globals, headerState] = await Promise.all([
    collectDomEvidence(tabId),
    collectGlobalEvidence(tabId).catch(() => ({})),
    chrome.storage.session.get(`${HEADER_PREFIX}${tabId}`)
  ]);
  const captured = headerState[`${HEADER_PREFIX}${tabId}`];
  const headers = captured?.url === tab.url ? captured.headers : {};
  const detected = analyzeEvidence({ ...dom, globals, headers });
  const shouldCheckCves = options.checkCves ?? currentSettings.checkCves;
  const technologies = options.deferCves && shouldCheckCves
    ? detected.map((item) => ({ ...item, vulnerabilityStatus: item.version && (item.package || item.cpe) ? "pending" : item.version ? "unsupported" : "version-unknown", vulnerabilities: [] }))
    : await addVulnerabilities(detected, shouldCheckCves);
  const result = {
    tabId,
    url: dom.url,
    title: dom.title || tab.title || hostname(tab.url),
    host: hostname(dom.url),
    scannedAt: new Date().toISOString(),
    htmlTruncated: Boolean(dom.htmlTruncated),
    statusCode: captured?.statusCode || null,
    technologies,
    cveLookupPending: Boolean(options.deferCves && shouldCheckCves),
    summary: {
      technologies: summarizeTechnologies(technologies),
      vulnerabilities: summarizeVulnerabilities(technologies)
    }
  };
  await chrome.storage.session.set({ [`${RESULT_PREFIX}${tabId}`]: result });
  await setBadge(tabId, result);
  if (result.cveLookupPending) {
    void (async () => {
      const enriched = await addVulnerabilities(detected, true);
      const [latestTab, latestSettings] = await Promise.all([chrome.tabs.get(tabId).catch(() => null), settings()]);
      if (!latestTab || latestTab.url !== result.url || !latestSettings.enabled || isExcluded(result.url, latestSettings.excludedHosts)) return;
      result.technologies = enriched;
      result.cveLookupPending = false;
      result.summary.technologies = summarizeTechnologies(enriched);
      result.summary.vulnerabilities = summarizeVulnerabilities(enriched);
      await chrome.storage.session.set({ [`${RESULT_PREFIX}${tabId}`]: result });
      await setBadge(tabId, result);
    })().catch(() => {});
  }
  return result;
}

async function getResult(tabId) {
  const stored = await chrome.storage.session.get(`${RESULT_PREFIX}${tabId}`);
  return stored[`${RESULT_PREFIX}${tabId}`] || null;
}

async function openReport(tabId) {
  return chrome.tabs.create({ url: chrome.runtime.getURL(`report/index.html?tab=${encodeURIComponent(tabId)}`) });
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tab || null;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  void (async () => {
    try {
      const tabId = Number.isInteger(message.tabId) ? message.tabId : sender.tab?.id;
      let data;
      if (message.type === "getActive") {
        const tab = await activeTab();
        data = tab ? { tab: { id: tab.id, title: tab.title, url: tab.url }, result: await getResult(tab.id), settings: await settings() } : null;
      } else if (message.type === "scan") {
        const target = Number.isInteger(tabId) ? tabId : (await activeTab())?.id;
        data = await scanTab(target, { force: true, checkCves: message.checkCves !== false });
      } else if (message.type === "getResult") {
        data = await getResult(tabId);
      } else if (message.type === "openReport") {
        data = await openReport(tabId);
      } else if (message.type === "updateSettings") {
        data = await saveSettings({ ...(await settings()), ...message.settings });
        if (!data.enabled) {
          const tabs = await chrome.tabs.query({});
          await Promise.all(tabs.map((tab) => setBadge(tab.id)));
        }
      } else if (message.type === "toggleExclude") {
        const current = await settings();
        const host = hostname(message.url);
        const excluded = new Set(current.excludedHosts);
        if (excluded.has(host)) excluded.delete(host); else excluded.add(host);
        data = await saveSettings({ ...current, excludedHosts: [...excluded] });
        const target = Number.isInteger(tabId) ? tabId : (await activeTab())?.id;
        if (excluded.has(host)) await setBadge(target, null, "excluded"); else void scanTab(target, { force: true });
      } else {
        throw new Error("Unknown StackSentry request");
      }
      sendResponse({ ok: true, data });
    } catch (error) {
      sendResponse({ ok: false, error: error?.message || String(error) });
    }
  })();
  return true;
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !isSupportedUrl(tab.url)) return;
  void settings().then((current) => {
    if (!current.enabled) return setBadge(tabId);
    if (!current.autoScan) return setBadge(tabId);
    if (isExcluded(tab.url, current.excludedHosts)) return setBadge(tabId, null, "excluded");
    return scanTab(tabId, { deferCves: true }).catch(() => setBadge(tabId));
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void chrome.storage.session.remove([`${RESULT_PREFIX}${tabId}`, `${HEADER_PREFIX}${tabId}`]);
});

chrome.commands.onCommand.addListener((command) => {
  if (command !== "scan-current-site") return;
  void activeTab().then(async (tab) => {
    if (!tab) return;
    await scanTab(tab.id, { force: true });
    await openReport(tab.id);
  }).catch(() => {});
});

chrome.runtime.onInstalled.addListener(() => void settings().then(saveSettings));

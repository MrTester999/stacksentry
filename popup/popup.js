const $ = (id) => document.getElementById(id);
const elements = Object.fromEntries(["autoScan", "catalogCoverage", "checkCves", "cveCount", "excludeSite", "masterEnabled", "openReport", "scanSite", "siteState", "siteTitle", "siteUrl", "summary", "technologyCount", "technologyPreview", "toast", "versionCount"].map((id) => [id, $(id)]));
let active = null;
let result = null;
let currentSettings = null;
let timer = null;

async function call(type, payload = {}) {
  const response = await chrome.runtime.sendMessage({ type, ...payload });
  if (!response?.ok) throw new Error(response?.error || "StackSentry request failed");
  return response.data;
}

function notify(message, error = false) {
  clearTimeout(timer);
  elements.toast.textContent = message;
  elements.toast.classList.toggle("error", error);
  elements.toast.classList.add("show");
  timer = setTimeout(() => elements.toast.classList.remove("show"), 2600);
}

function hostFor(url) {
  try { return new URL(url).hostname; } catch { return ""; }
}

function render() {
  const host = hostFor(active?.url);
  const excluded = currentSettings?.excludedHosts?.some((item) => host === item || host.endsWith(`.${item}`));
  const enabled = currentSettings?.enabled !== false;
  elements.masterEnabled.checked = enabled;
  document.body.classList.toggle("tool-off", !enabled);
  elements.autoScan.checked = currentSettings?.autoScan !== false;
  elements.checkCves.checked = currentSettings?.checkCves !== false;
  elements.excludeSite.classList.toggle("excluded", Boolean(excluded));
  elements.excludeSite.querySelector("strong").textContent = excluded ? "Resume scanning this site" : "Exclude this site";
  elements.excludeSite.querySelector("small").textContent = excluded ? "Remove this hostname from the exclusion list" : "Pause automatic analysis for this hostname";
  elements.siteTitle.textContent = active?.title || "Unsupported page";
  elements.siteUrl.textContent = active?.url || "Open an HTTP or HTTPS website";
  const technologySummary = result?.summary?.technologies;
  const vulnerabilitySummary = result?.summary?.vulnerabilities;
  elements.technologyCount.textContent = technologySummary?.total ?? "—";
  elements.versionCount.textContent = technologySummary?.versioned ?? "—";
  elements.cveCount.textContent = vulnerabilitySummary?.total ?? "—";
  elements.catalogCoverage.textContent = result?.catalogSize ? `${result.catalogSize.toLocaleString()} maintained fingerprints` : "Maintained catalog ready";
  elements.siteState.className = `site-state${vulnerabilitySummary?.total ? " risk" : result ? " ready" : ""}`;
  elements.openReport.disabled = !result || !enabled;
  elements.scanSite.disabled = !enabled;
  elements.technologyPreview.replaceChildren();
  if (!result?.technologies?.length) {
    const empty = document.createElement("span");
    empty.textContent = result ? "No known technologies detected." : "No scan results for this page yet.";
    elements.technologyPreview.append(empty);
  } else {
    const grouped = Map.groupBy(result.technologies, (technology) => technology.category || "Other");
    for (const [category, technologies] of [...grouped].sort((a, b) => a[0].localeCompare(b[0]))) {
      const group = document.createElement("section");
      group.className = "technology-group";
      const heading = document.createElement("h2");
      heading.textContent = `${category} · ${technologies.length}`;
      const items = document.createElement("div");
      items.className = "technology-items";
      group.append(heading, items);
      for (const technology of technologies.sort((a, b) => a.name.localeCompare(b.name))) {
      const pill = document.createElement("span");
      pill.className = "technology-pill";
      const icon = document.createElement("img");
      icon.src = technology.source === "OpenWapp" ? `../icons/catalog/${technology.id}.svg` : `../icons/technologies/${technology.id}.svg`;
      icon.alt = "";
      pill.title = `${technology.name} · ${technology.category} · ${technology.confidence} confidence`;
      pill.append(icon, document.createTextNode(technology.name));
      if (technology.version) {
        const version = document.createElement("b");
        version.textContent = ` ${technology.version}`;
        pill.append(version);
      }
      items.append(pill);
      }
      elements.technologyPreview.append(group);
    }
  }
}

async function scan() {
  if (!active?.id) return notify("Open a normal website first", true);
  document.body.classList.add("loading");
  elements.scanSite.querySelector("strong").textContent = "Analyzing website…";
  elements.scanSite.querySelector("small").textContent = "Collecting local fingerprints and exact versions";
  try {
    result = await call("scan", { tabId: active.id, checkCves: elements.checkCves.checked });
    render();
    notify(`${result.summary.technologies.total} technologies · ${result.summary.vulnerabilities.total} known CVEs`);
  } catch (error) {
    notify(error.message, true);
  } finally {
    document.body.classList.remove("loading");
    elements.scanSite.querySelector("strong").textContent = "Analyze this website";
    elements.scanSite.querySelector("small").textContent = "Fingerprint stack, versions, and known CVEs";
  }
}

elements.scanSite.addEventListener("click", scan);
elements.masterEnabled.addEventListener("change", async () => {
  try {
    currentSettings = await call("updateSettings", { settings: { enabled: elements.masterEnabled.checked } });
    render();
    notify(currentSettings.enabled ? "StackSentry turned on" : "StackSentry turned off");
    if (currentSettings.enabled && currentSettings.autoScan && active?.id) void scan();
  } catch (error) {
    elements.masterEnabled.checked = !elements.masterEnabled.checked;
    notify(error.message, true);
  }
});
elements.openReport.addEventListener("click", async () => {
  try { await call("openReport", { tabId: active.id }); window.close(); }
  catch (error) { notify(error.message, true); }
});
elements.autoScan.addEventListener("change", async () => {
  try { currentSettings = await call("updateSettings", { settings: { autoScan: elements.autoScan.checked } }); render(); }
  catch (error) { notify(error.message, true); }
});
elements.checkCves.addEventListener("change", async () => {
  try { currentSettings = await call("updateSettings", { settings: { checkCves: elements.checkCves.checked } }); render(); }
  catch (error) { notify(error.message, true); }
});
elements.excludeSite.addEventListener("click", async () => {
  try {
    currentSettings = await call("toggleExclude", { tabId: active.id, url: active.url });
    render();
    notify(elements.excludeSite.classList.contains("excluded") ? "Site excluded from Auto Scan" : "Automatic scanning resumed");
  } catch (error) { notify(error.message, true); }
});

void (async () => {
  try {
    const data = await call("getActive");
    active = data?.tab || null;
    result = data?.result || null;
    currentSettings = data?.settings || { enabled: true, autoScan: true, checkCves: true, excludedHosts: [] };
    render();
  } catch (error) {
    elements.siteTitle.textContent = "StackSentry unavailable";
    elements.siteUrl.textContent = error.message;
    notify(error.message, true);
  }
})();

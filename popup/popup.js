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

function vulnerabilityLabel(technology) {
  const count = technology.vulnerabilities?.length || 0;
  if (count) return { text: `${count} confirmed CVE${count === 1 ? "" : "s"}`, className: "affected" };
  return {
    checked: { text: "0 CVEs returned", className: "checked" },
    pending: { text: "Checking exact version…", className: "pending" },
    "version-unknown": { text: "Version unknown", className: "unknown" },
    disabled: { text: "CVE check off", className: "muted" },
    "lookup-limit": { text: "Not checked · scan limit", className: "muted" },
    unsupported: { text: "No verified mapping", className: "muted" },
    error: { text: "Lookup failed", className: "error" }
  }[technology.vulnerabilityStatus] || { text: "Not checked", className: "muted" };
}

function technologyOrder(a, b) {
  return Number(Boolean(b.vulnerabilities?.length)) - Number(Boolean(a.vulnerabilities?.length))
    || Number(Boolean(b.version)) - Number(Boolean(a.version))
    || a.name.localeCompare(b.name);
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
      for (const technology of technologies.sort(technologyOrder)) {
        const card = document.createElement("article");
        card.className = `technology-item${technology.vulnerabilities?.length ? " affected" : ""}`;
        const icon = document.createElement("img");
        icon.src = technology.source === "OpenWapp" ? `../icons/catalog/${technology.id}.svg` : `../icons/technologies/${technology.id}.svg`;
        icon.alt = "";
        const identity = document.createElement("div");
        identity.className = "technology-identity";
        const name = document.createElement("strong");
        name.textContent = technology.name;
        const confidence = document.createElement("small");
        confidence.textContent = `${technology.score}% ${technology.confidence} confidence`;
        identity.append(name, confidence);
        const version = document.createElement("div");
        version.className = `technology-version${technology.version ? " exact" : ""}`;
        version.append(Object.assign(document.createElement("small"), { textContent: technology.version ? "CONFIRMED" : "VERSION" }), Object.assign(document.createElement("b"), { textContent: technology.version || "Unknown · not exposed" }));
        const statusData = vulnerabilityLabel(technology);
        const status = document.createElement("span");
        status.className = `technology-cve ${statusData.className}`;
        status.textContent = statusData.text;
        card.title = `${technology.name} · ${technology.version ? `exact version ${technology.version}` : "version unknown"} · ${statusData.text}`;
        card.append(icon, identity, version, status);
        if (technology.vulnerabilities?.length) {
          const ids = document.createElement("div");
          ids.className = "technology-cve-ids";
          ids.textContent = technology.vulnerabilities.slice(0, 3).map((item) => item.id).join(" · ");
          card.append(ids);
        }
        items.append(card);
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

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "session" || !active?.id) return;
  const updated = changes[`scanResult:${active.id}`]?.newValue;
  if (!updated) return;
  result = updated;
  render();
});

const $ = (id) => document.getElementById(id);
const elements = Object.fromEntries(["affectedTotal", "busy", "categoryNav", "clearFilters", "criticalCount", "exportReport", "highCount", "highRiskTotal", "lowCount", "mediumCount", "rescan", "resultCount", "scanMeta", "search", "siteIcon", "siteTitle", "siteUrl", "technologyList", "technologyTotal", "toast", "versionTotal", "viewFilter", "vulnerabilityList", "vulnerabilityTotal"].map((id) => [id, $(id)]));
const tabId = Number(new URL(location.href).searchParams.get("tab"));
let result = null;
let selectedCategory = "All";
let toastTimer = null;

async function call(type, payload = {}) {
  const response = await chrome.runtime.sendMessage({ type, ...payload });
  if (!response?.ok) throw new Error(response?.error || "StackSentry request failed");
  return response.data;
}

function notify(message, error = false) {
  clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.classList.toggle("error", error);
  elements.toast.classList.add("show");
  toastTimer = setTimeout(() => elements.toast.classList.remove("show"), 2600);
}

function initials(name) {
  return name.split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();
}

function textNode(tag, text, className = "") {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  return element;
}

function emptyState(title, detail) {
  const empty = document.createElement("div");
  empty.className = "empty";
  empty.append(textNode("b", title), textNode("span", detail));
  return empty;
}

function filteredTechnologies() {
  const search = elements.search.value.trim().toLowerCase();
  const view = elements.viewFilter.value;
  return (result?.technologies || []).filter((technology) => {
    if (selectedCategory !== "All" && technology.category !== selectedCategory) return false;
    if (view === "affected" && !technology.vulnerabilities?.length) return false;
    if (view === "versioned" && !technology.version) return false;
    if (view === "unknown" && technology.version) return false;
    if (!search) return true;
    const haystack = [technology.name, technology.category, technology.version, ...(technology.evidence || []).flatMap((item) => [item.type, item.detail]), ...(technology.vulnerabilities || []).flatMap((item) => [item.id, item.summary])].join(" ").toLowerCase();
    return haystack.includes(search);
  });
}

function renderCategories() {
  const counts = { All: result?.technologies?.length || 0 };
  for (const technology of result?.technologies || []) counts[technology.category] = (counts[technology.category] || 0) + 1;
  elements.categoryNav.replaceChildren();
  for (const [category, count] of Object.entries(counts).sort(([a], [b]) => a === "All" ? -1 : b === "All" ? 1 : a.localeCompare(b))) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = selectedCategory === category ? "active" : "";
    button.dataset.category = category;
    button.append(textNode("span", category), textNode("b", String(count)));
    elements.categoryNav.append(button);
  }
}

function renderTechnologies() {
  const technologies = filteredTechnologies();
  elements.resultCount.textContent = `${technologies.length} result${technologies.length === 1 ? "" : "s"}`;
  elements.technologyList.replaceChildren();
  if (!technologies.length) {
    elements.technologyList.append(emptyState("No matching technologies", "Change the category, view, or search filter."));
    return;
  }
  for (const technology of technologies) {
    const card = document.createElement("article");
    card.className = "technology-card";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "technology-main";
    button.style.setProperty("--tech", technology.color || "#39e2ca");
    const icon = textNode("span", initials(technology.name), "tech-icon");
    const name = document.createElement("div");
    name.className = "tech-name";
    name.append(textNode("strong", technology.name), textNode("span", technology.category));
    const version = document.createElement("div");
    version.className = "version";
    version.append(textNode("strong", technology.version || "Unknown", technology.version ? "" : "unknown"), textNode("span", "Version"));
    const confidence = document.createElement("div");
    confidence.className = "confidence";
    confidence.append(textNode("strong", `${technology.score}%`, technology.confidence), textNode("span", `${technology.confidence} confidence`));
    const cve = textNode("span", technology.vulnerabilities?.length ? `${technology.vulnerabilities.length} CVE${technology.vulnerabilities.length === 1 ? "" : "s"}` : technology.vulnerabilityStatus === "checked" ? "No known CVEs" : "Not verified", `cve-pill${technology.vulnerabilities?.length ? " risk" : ""}`);
    button.append(icon, name, version, confidence, cve, textNode("b", "›"));
    const details = document.createElement("div");
    details.className = "technology-details";
    const grid = document.createElement("div");
    grid.className = "detail-grid";
    const evidence = document.createElement("div");
    evidence.append(textNode("h4", "Detection evidence"));
    for (const item of technology.evidence || []) {
      const row = document.createElement("div");
      row.className = "evidence-item";
      row.append(textNode("b", `${item.type} · ${item.confidence}`), textNode("span", item.detail));
      evidence.append(row);
    }
    const verification = document.createElement("div");
    verification.append(textNode("h4", "Vulnerability status"));
    const note = document.createElement("div");
    note.className = "verification-note";
    const statusText = !technology.version ? "Version unknown — CVE matching skipped to avoid false attribution."
      : technology.vulnerabilityStatus === "pending" ? "Exact-version CVE lookup is still running in the background."
      : technology.vulnerabilityStatus === "checked" ? `${technology.vulnerabilitySource} checked the exact detected version.${technology.cveCached ? " Result loaded from the 24-hour local cache." : ""}`
      : technology.vulnerabilityStatus === "error" ? `Lookup failed: ${technology.vulnerabilityError}`
      : "No supported package or verified CPE mapping is available for this technology.";
    note.append(textNode("strong", technology.version ? `Version ${technology.version}` : "Version not confirmed"), document.createTextNode(statusText));
    verification.append(note);
    grid.append(evidence, verification);
    details.append(grid);
    card.append(button, details);
    elements.technologyList.append(card);
  }
}

function renderVulnerabilities() {
  const vulnerabilities = (result?.technologies || []).flatMap((technology) => (technology.vulnerabilities || []).map((item) => ({ ...item, technology: technology.name, version: technology.version })));
  elements.vulnerabilityList.replaceChildren();
  if (!vulnerabilities.length) {
    elements.vulnerabilityList.append(emptyState("No known CVEs matched", "Only exact detected versions are checked. Unknown versions are never guessed."));
    return;
  }
  for (const vulnerability of vulnerabilities) {
    const card = document.createElement("article");
    card.className = `vulnerability-card ${vulnerability.severity || "unknown"}`;
    const head = document.createElement("div");
    head.className = "vuln-head";
    head.append(textNode("strong", vulnerability.id), textNode("span", vulnerability.severity || "unknown"), textNode("em", vulnerability.score ? `CVSS ${vulnerability.score}` : vulnerability.source));
    const link = document.createElement("a");
    link.href = vulnerability.url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = `Open ${vulnerability.source} advisory ↗`;
    card.append(head, textNode("h4", `${vulnerability.technology} ${vulnerability.version}`), textNode("p", vulnerability.summary), link);
    elements.vulnerabilityList.append(card);
  }
}

function render() {
  if (!result) return;
  const tech = result.summary.technologies;
  const vuln = result.summary.vulnerabilities;
  elements.siteTitle.textContent = result.title;
  elements.siteUrl.textContent = result.url;
  elements.siteIcon.textContent = result.host?.[0]?.toUpperCase() || "S";
  elements.scanMeta.textContent = `Scanned ${new Date(result.scannedAt).toLocaleString()} · HTTP ${result.statusCode || "unknown"}${result.htmlTruncated ? " · large DOM sample truncated safely" : ""}`;
  elements.technologyTotal.textContent = tech.total;
  elements.versionTotal.textContent = tech.versioned;
  elements.vulnerabilityTotal.textContent = vuln.total;
  elements.affectedTotal.textContent = `${vuln.affectedTechnologies} affected product${vuln.affectedTechnologies === 1 ? "" : "s"}`;
  elements.highRiskTotal.textContent = vuln.critical + vuln.high;
  elements.criticalCount.textContent = vuln.critical;
  elements.highCount.textContent = vuln.high;
  elements.mediumCount.textContent = vuln.medium;
  elements.lowCount.textContent = vuln.low;
  renderCategories();
  renderTechnologies();
  renderVulnerabilities();
}

elements.categoryNav.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-category]");
  if (!button) return;
  selectedCategory = button.dataset.category;
  renderCategories();
  renderTechnologies();
});
elements.technologyList.addEventListener("click", (event) => {
  const button = event.target.closest(".technology-main");
  if (button) button.closest(".technology-card").classList.toggle("open");
});
elements.search.addEventListener("input", renderTechnologies);
elements.viewFilter.addEventListener("change", renderTechnologies);
elements.clearFilters.addEventListener("click", () => {
  elements.search.value = "";
  elements.viewFilter.value = "all";
  selectedCategory = "All";
  render();
});
elements.exportReport.addEventListener("click", () => {
  if (!result) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `stacksentry-${result.host || "report"}.json`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  notify("Report exported locally");
});
elements.rescan.addEventListener("click", async () => {
  elements.busy.classList.add("show");
  try { result = await call("scan", { tabId, checkCves: true }); render(); notify("Fresh scan completed"); }
  catch (error) { notify(error.message, true); }
  finally { elements.busy.classList.remove("show"); }
});

void (async () => {
  if (!Number.isInteger(tabId)) return notify("Invalid report tab", true);
  try {
    result = await call("getResult", { tabId });
    if (!result) throw new Error("No scan result found. Open the popup and analyze the site first.");
    render();
  } catch (error) {
    elements.siteTitle.textContent = "Report unavailable";
    elements.siteUrl.textContent = error.message;
    notify(error.message, true);
  }
})();

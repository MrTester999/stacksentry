const OSV_API = "https://api.osv.dev/v1/query";
const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";

function severityRank(value) {
  return { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 }[String(value || "").toLowerCase()] || 0;
}

function osvSeverity(record) {
  const direct = String(record.database_specific?.severity || "").toLowerCase();
  if (["critical", "high", "medium", "low"].includes(direct)) return direct;
  const ecosystem = record.ecosystem_specific?.severity;
  if (typeof ecosystem === "string" && ["critical", "high", "medium", "low"].includes(ecosystem.toLowerCase())) return ecosystem.toLowerCase();
  return "unknown";
}

function normalizeOsv(record) {
  const aliases = Array.isArray(record.aliases) ? record.aliases : [];
  const cve = aliases.find((item) => /^CVE-/i.test(item));
  return {
    id: cve || record.id,
    sourceId: record.id,
    summary: record.summary || record.details?.split("\n")[0] || "Known vulnerability",
    severity: osvSeverity(record),
    score: null,
    aliases,
    published: record.published || "",
    modified: record.modified || "",
    url: `https://osv.dev/vulnerability/${encodeURIComponent(record.id)}`,
    source: "OSV"
  };
}

function nvdMetric(cve) {
  const metrics = cve.metrics || {};
  const metric = metrics.cvssMetricV31?.[0] || metrics.cvssMetricV30?.[0] || metrics.cvssMetricV2?.[0] || null;
  const data = metric?.cvssData || {};
  return {
    score: Number.isFinite(data.baseScore) ? data.baseScore : null,
    severity: String(data.baseSeverity || metric?.baseSeverity || "unknown").toLowerCase()
  };
}

function normalizeNvd(item) {
  const cve = item.cve || {};
  const metric = nvdMetric(cve);
  const description = (cve.descriptions || []).find((entry) => entry.lang === "en")?.value || "Known vulnerability";
  return {
    id: cve.id,
    sourceId: cve.id,
    summary: description,
    severity: metric.severity,
    score: metric.score,
    aliases: [],
    published: cve.published || "",
    modified: cve.lastModified || "",
    url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`,
    source: "NVD"
  };
}

function uniqueVulnerabilities(records) {
  const unique = new Map();
  for (const record of records) {
    const key = String(record.id || record.sourceId || "").toUpperCase();
    if (!key) continue;
    const existing = unique.get(key);
    if (!existing || severityRank(record.severity) > severityRank(existing.severity)) unique.set(key, record);
  }
  return [...unique.values()].sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.id.localeCompare(b.id));
}

export function vulnerabilityCacheKey(technology) {
  if (!technology?.version) return "";
  if (technology.package) return `osv:${technology.package.ecosystem}:${technology.package.name}:${technology.version}`;
  if (technology.cpe) return `nvd:${technology.cpe.replace("{version}", technology.version)}`;
  return "";
}

export async function lookupTechnologyVulnerabilities(technology, fetchFn = fetch) {
  if (!technology?.version) return { status: "version-unknown", vulnerabilities: [] };
  const signal = typeof AbortSignal?.timeout === "function" ? AbortSignal.timeout(12_000) : undefined;
  if (technology.package) {
    const query = { basis: "exact-version", source: "OSV", version: technology.version, ecosystem: technology.package.ecosystem, package: technology.package.name };
    const response = await fetchFn(OSV_API, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        version: technology.version,
        package: { ecosystem: technology.package.ecosystem, name: technology.package.name }
      }),
      signal
    });
    if (!response.ok) throw new Error(`OSV returned HTTP ${response.status}`);
    const payload = await response.json();
    return {
      status: "checked",
      source: "OSV",
      checkedAt: new Date().toISOString(),
      query,
      vulnerabilities: uniqueVulnerabilities((payload.vulns || []).map(normalizeOsv))
    };
  }
  if (technology.cpe) {
    const cpeName = technology.cpe.replace("{version}", technology.version);
    const query = { basis: "exact-version", source: "NVD", version: technology.version, cpe: cpeName };
    const response = await fetchFn(`${NVD_API}?cpeName=${encodeURIComponent(cpeName)}&noRejected`, { headers: { accept: "application/json" }, signal });
    if (!response.ok) throw new Error(`NVD returned HTTP ${response.status}`);
    const payload = await response.json();
    return {
      status: "checked",
      source: "NVD",
      checkedAt: new Date().toISOString(),
      query,
      vulnerabilities: uniqueVulnerabilities((payload.vulnerabilities || []).map(normalizeNvd))
    };
  }
  return { status: "unsupported", vulnerabilities: [] };
}

export function summarizeVulnerabilities(technologies) {
  const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0, affectedTechnologies: 0 };
  for (const technology of technologies || []) {
    const findings = technology.vulnerabilities || [];
    if (findings.length) summary.affectedTechnologies += 1;
    for (const vulnerability of findings) {
      summary.total += 1;
      const severity = vulnerability.severity in summary ? vulnerability.severity : "unknown";
      summary[severity] += 1;
    }
  }
  return summary;
}

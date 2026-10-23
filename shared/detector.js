import { TECHNOLOGIES } from "../data/technologies.js";

const CONFIDENCE = { low: 35, medium: 65, high: 90 };

function safeRegex(pattern) {
  try { return new RegExp(pattern, "i"); }
  catch { return null; }
}

function cleanVersion(value) {
  const match = String(value || "").trim().match(/v?([0-9]+(?:\.[0-9A-Za-z-]+){1,4})/);
  return match?.[1]?.replace(/[),;]+$/, "") || "";
}

function pushEvidence(bucket, type, source, detail, confidence, version = "") {
  const key = `${type}\0${source}\0${detail}`;
  if (bucket.seen.has(key)) return;
  bucket.seen.add(key);
  bucket.evidence.push({ type, source, detail: String(detail).slice(0, 240), confidence });
  bucket.score = Math.min(100, bucket.score + (confidence === "high" ? 55 : confidence === "medium" ? 35 : 20));
  const normalized = cleanVersion(version);
  if (normalized) {
    const rank = CONFIDENCE[confidence] || 0;
    if (!bucket.version || rank > bucket.versionRank) {
      bucket.version = normalized;
      bucket.versionConfidence = confidence;
      bucket.versionRank = rank;
    }
  }
}

function testPattern(value, tuple) {
  const [pattern, versionGroup] = tuple;
  const regex = safeRegex(pattern);
  const match = regex?.exec(String(value || ""));
  return match ? { match: match[0], version: Number.isInteger(versionGroup) ? match[versionGroup] || "" : "" } : null;
}

export function analyzeEvidence(evidence, technologies = TECHNOLOGIES) {
  const headers = Object.fromEntries(Object.entries(evidence.headers || {}).map(([key, value]) => [key.toLowerCase(), String(value)]));
  const html = String(evidence.html || "");
  const scripts = (evidence.scripts || []).map((item) => typeof item === "string" ? item : item.src || "").filter(Boolean);
  const assets = [
    ...scripts,
    ...(evidence.links || []).map((item) => typeof item === "string" ? item : item.href || ""),
    ...(evidence.resources || []).map((item) => typeof item === "string" ? item : item.name || "")
  ].filter(Boolean);
  const metas = evidence.meta || [];
  const globals = evidence.globals || {};
  const output = [];

  for (const technology of technologies) {
    const bucket = { score: 0, evidence: [], seen: new Set(), version: "", versionConfidence: "", versionRank: 0 };
    for (const key of technology.globals || []) {
      const value = globals[key];
      if (!value) continue;
      const version = typeof value === "string" && value !== "true" ? value : "";
      pushEvidence(bucket, "global", key, version ? `${key} ${version}` : key, version ? "high" : "medium", version);
    }
    for (const [headerName, pattern, versionGroup] of technology.matchers?.headers || []) {
      const headerValue = headers[headerName.toLowerCase()];
      if (!headerValue) continue;
      const result = testPattern(headerValue, [pattern, versionGroup]);
      if (result) pushEvidence(bucket, "header", headerName, `${headerName}: ${headerValue}`, "high", result.version);
    }
    for (const [metaName, pattern, versionGroup] of technology.matchers?.meta || []) {
      for (const meta of metas) {
        if (String(meta.name || meta.property || meta.httpEquiv || "").toLowerCase() !== metaName.toLowerCase()) continue;
        const result = testPattern(meta.content, [pattern, versionGroup]);
        if (result) pushEvidence(bucket, "meta", metaName, `${metaName}: ${meta.content}`, "high", result.version);
      }
    }
    for (const tuple of technology.matchers?.scripts || []) {
      for (const script of scripts) {
        const result = testPattern(script, tuple);
        if (result) pushEvidence(bucket, "script", script, result.match, result.version ? "high" : "medium", result.version);
      }
    }
    for (const tuple of technology.matchers?.assets || []) {
      for (const asset of assets) {
        const result = testPattern(asset, tuple);
        if (result) pushEvidence(bucket, "asset", asset, result.match, result.version ? "high" : "medium", result.version);
      }
    }
    for (const tuple of technology.matchers?.html || []) {
      const result = testPattern(html, tuple);
      if (result) pushEvidence(bucket, "dom", "page", result.match, "medium", result.version);
    }
    if (!bucket.evidence.length) continue;
    const versionMajor = bucket.version.split(".")[0];
    const mappedPackage = technology.packages?.[versionMajor] || technology.package || null;
    output.push({
      id: technology.id,
      name: technology.name,
      category: technology.category,
      color: technology.color,
      website: technology.website,
      confidence: bucket.score >= 80 ? "high" : bucket.score >= 50 ? "medium" : "low",
      score: bucket.score,
      version: bucket.version,
      versionConfidence: bucket.versionConfidence,
      evidence: bucket.evidence,
      package: mappedPackage,
      cpe: technology.cpe || ""
    });
  }
  return output.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
}

export function summarizeTechnologies(technologies) {
  const categories = {};
  let versioned = 0;
  for (const technology of technologies) {
    categories[technology.category] = (categories[technology.category] || 0) + 1;
    if (technology.version) versioned += 1;
  }
  return { total: technologies.length, versioned, categories };
}

import fingerprints from "@openwapp/fingerprints";
import { Catalog, Matcher, Observation, Requirements } from "@openwapp/matcher";

const catalog = Catalog.decodeSync(fingerprints);
const requirements = Requirements.fromCatalog(catalog);
const PALETTE = ["#39e2ca", "#6389ff", "#f2b84b", "#ff6e83", "#9b8cff", "#50c878", "#ff914d", "#42b8d5"];

export const OPENWAPP_CATALOG_SIZE = catalog.technologies.size;
export const OPENWAPP_REQUIREMENTS = Object.freeze({
  cookie: [...requirements.cookie],
  js: [...requirements.js],
  domExists: [...requirements.domExists],
  domText: [...requirements.domText],
  domAttribute: [...requirements.domAttribute].map(([selector, names]) => [selector, [...names]]),
  domProperty: [...requirements.domProperty].map(([selector, names]) => [selector, [...names]])
});

function slug(value) {
  return String(value).toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 54) || "technology";
}

function hash(value) {
  let current = 2166136261;
  for (const char of String(value)) current = Math.imul(current ^ char.charCodeAt(0), 16777619);
  return (current >>> 0).toString(36);
}

export function openWappTechnologyId(name) {
  return `ow-${slug(name)}-${hash(name).slice(0, 7)}`;
}

function list(value) {
  return Array.isArray(value) ? value.map(String).filter(Boolean) : value ? [String(value)] : [];
}

function valuesMap(input = {}, lowercaseKeys = true) {
  return new Map(Object.entries(input).map(([key, value]) => [lowercaseKeys ? key.toLowerCase() : key, list(value)]).filter(([, values]) => values.length));
}

function metaMap(meta = []) {
  const output = new Map();
  for (const item of meta) {
    const key = String(item.name || item.property || item.httpEquiv || "").toLowerCase();
    const value = String(item.content || "");
    if (!key || !value) continue;
    output.set(key, [...(output.get(key) || []), value]);
  }
  return output;
}

function nestedValuesMap(input = {}) {
  return new Map(Object.entries(input).map(([selector, values]) => [selector, valuesMap(values, false)]).filter(([, values]) => values.size));
}

function safeCpeTemplate(cpe = "") {
  const parts = String(cpe).split(":");
  if (parts.length !== 13 || parts[0] !== "cpe" || parts[1] !== "2.3" || parts[5] !== "*") return "";
  parts[5] = "{version}";
  return parts.join(":");
}

function ruleValues(rule, observation) {
  if (rule._tag === "Header") return observation.header.get(rule.name) || [];
  if (rule._tag === "Cookie") {
    if (!rule.name.includes("*")) return observation.cookie.get(rule.name) || [];
    const glob = new RegExp(`^${rule.name.replaceAll(/[\\^$.+?()[\]{}|]/g, "\\$&").replaceAll("*", ".*")}$`, "s");
    return [...observation.cookie].filter(([name]) => glob.test(name)).flatMap(([, values]) => values);
  }
  if (rule._tag === "Meta") return observation.meta.get(rule.name) || [];
  if (rule._tag === "Js") return observation.js.get(rule.property) || [];
  if (rule._tag === "DomExists") return observation.domExists.has(rule.selector) ? [rule.selector] : [];
  if (rule._tag === "DomText") return observation.domText.get(rule.selector) || [];
  if (rule._tag === "DomAttribute") return observation.domAttribute.get(rule.selector)?.get(rule.attribute) || [];
  if (rule._tag === "DomProperty") return observation.domProperty.get(rule.selector)?.get(rule.property) || [];
  const key = { Url: "url", Html: "html", Text: "text", Css: "css", Script: "script", ScriptSrc: "scriptSrc", Xhr: "xhr" }[rule._tag];
  return key ? observation[key] || [] : [];
}

function evidenceType(tag) {
  return { Header: "header", Cookie: "cookie", Meta: "meta", Js: "global", ScriptSrc: "asset", Xhr: "resource", Url: "url", Css: "style", Script: "inline-script", Text: "text", Html: "dom", DomExists: "dom", DomText: "dom-text", DomAttribute: "dom-attribute", DomProperty: "dom-property" }[tag] || "catalog";
}

function evidenceDetail(rule, value) {
  if (rule._tag === "Header") return `${rule.name}: ${String(value).slice(0, 180)}`;
  if (rule._tag === "Cookie") return `Cookie present: ${rule.name}`;
  if (rule._tag === "Meta") return `${rule.name}: ${String(value).slice(0, 180)}`;
  if (rule._tag === "Js") return `${rule.property}: ${String(value).slice(0, 120)}`;
  if (rule._tag === "DomExists") return `Matched selector: ${rule.selector}`;
  if (rule._tag === "DomText") return `${rule.selector}: ${String(value).slice(0, 160)}`;
  if (rule._tag === "DomAttribute") return `${rule.selector} [${rule.attribute}]: ${String(value).slice(0, 160)}`;
  if (rule._tag === "DomProperty") return `${rule.selector} .${rule.property}: ${String(value).slice(0, 120)}`;
  if (["ScriptSrc", "Xhr", "Url"].includes(rule._tag)) return String(value).slice(0, 220);
  return `Maintained catalog ${evidenceType(rule._tag)} fingerprint matched`;
}

function matchedEvidence(technology, observation) {
  const found = [];
  const seen = new Set();
  for (const rule of technology.rules || []) {
    if (!rule.pattern?.regex) continue;
    for (const value of ruleValues(rule, observation)) {
      rule.pattern.regex.lastIndex = 0;
      if (!rule.pattern.regex.test(String(value))) continue;
      const type = evidenceType(rule._tag);
      const detail = evidenceDetail(rule, value);
      const key = `${type}\0${detail}`;
      if (!seen.has(key)) found.push({ type, source: rule._tag, detail, confidence: rule.pattern.confidence >= 80 ? "high" : rule.pattern.confidence >= 50 ? "medium" : "low" });
      seen.add(key);
      if (found.length >= 4) return found;
    }
  }
  return found.length ? found : [{ type: "catalog", source: "relationship", detail: "Detected through a maintained catalog relationship", confidence: "medium" }];
}

export function analyzeOpenWappEvidence(evidence = {}) {
  const scriptSources = [
    ...(evidence.scripts || []).map((item) => typeof item === "string" ? item : item.src || ""),
    ...(evidence.resources || []).filter((item) => !item.initiatorType || item.initiatorType === "script").map((item) => typeof item === "string" ? item : item.name || "")
  ].filter(Boolean);
  const styles = [
    ...list(evidence.styles),
    ...(evidence.links || []).filter((item) => !item.rel || /stylesheet|preload/i.test(item.rel)).map((item) => typeof item === "string" ? item : item.href || "")
  ].filter(Boolean);
  const resourceValues = (evidence.resources || []).map((item) => typeof item === "string" ? item : item.name || "").filter(Boolean);
  const xhr = resourceValues.flatMap((value) => {
    try { return [value, new URL(value).hostname]; } catch { return [value]; }
  });
  const observation = new Observation.Observation({
    url: list(evidence.url),
    html: list(evidence.html),
    text: list(evidence.text),
    css: styles,
    script: list(evidence.inlineScripts),
    scriptSrc: [...new Set(scriptSources)],
    xhr: [...new Set(xhr)],
    header: valuesMap(evidence.headers),
    cookie: valuesMap(evidence.cookies),
    meta: metaMap(evidence.meta),
    js: valuesMap(evidence.js, false),
    domExists: new Set(evidence.domExists || []),
    domText: valuesMap(evidence.domText),
    domAttribute: nestedValuesMap(evidence.domAttribute),
    domProperty: nestedValuesMap(evidence.domProperty)
  });

  return Matcher.match(catalog, observation).map((detection) => {
    const technology = detection.technology;
    const categories = technology.categories.map((id) => catalog.categories.get(id)).filter(Boolean).sort((a, b) => a.priority - b.priority);
    const category = categories[0];
    return {
      id: openWappTechnologyId(technology.name),
      name: technology.name,
      category: category?.name || "Other",
      color: PALETTE[(category?.id || 0) % PALETTE.length],
      website: technology.website || "",
      confidence: detection.confidence >= 80 ? "high" : detection.confidence >= 50 ? "medium" : "low",
      score: detection.confidence,
      version: detection.version || "",
      versionConfidence: detection.version ? (detection.confidence >= 80 ? "high" : "medium") : "",
      evidence: matchedEvidence(technology, observation),
      package: null,
      cpe: safeCpeTemplate(technology.cpe),
      source: "OpenWapp"
    };
  });
}

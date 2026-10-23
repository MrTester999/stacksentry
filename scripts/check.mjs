import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, readdir, stat } from "node:fs/promises";
import fingerprints from "@openwapp/fingerprints";
import { analyzeEvidence, mergeTechnologyDetections, summarizeTechnologies } from "../shared/detector.js";
import { lookupTechnologyVulnerabilities, summarizeVulnerabilities, vulnerabilityCacheKey } from "../shared/vulnerabilities.js";
import { collectCatalogProperties } from "../shared/safe-properties.js";
import { isExactVersion } from "../shared/version.js";
import { TECHNOLOGIES } from "../data/technologies.js";
import { analyzeOpenWappEvidence, OPENWAPP_CATALOG_SIZE, OPENWAPP_REQUIREMENTS, openWappTechnologyId } from "../vendor/openwapp-engine.js";

const root = new URL("../", import.meta.url);
const json = async (path) => JSON.parse(await readFile(new URL(path, root), "utf8"));
const manifest = await json("manifest.json");
const packageJson = await json("package.json");
assert.equal(manifest.manifest_version, 3);
assert.equal(manifest.version, packageJson.version);
assert.ok(manifest.permissions.includes("webRequest"));
assert.ok(manifest.permissions.includes("scripting"));

const required = [
  manifest.background.service_worker,
  manifest.action.default_popup,
  ...Object.values(manifest.icons),
  "data/technologies.js", "shared/detector.js", "shared/safe-properties.js", "shared/version.js", "shared/vulnerabilities.js",
  "popup/popup.css", "popup/popup.js", "report/index.html", "report/report.css", "report/report.js",
  "screenshots/stacksentry-popup.png", "screenshots/stacksentry-report.png",
  "vendor/openwapp-engine.js", "vendor/openwapp-fingerprints-LICENSE.txt", "vendor/openwapp-matcher-LICENSE.txt", "vendor/openwapp-upstream.json",
  "vendor/openwapp-source/index.js", "vendor/openwapp-source/data/categories.json", "vendor/openwapp-source/data/upstream.json",
  "README.md", "DOCUMENTATION.md", "DOCUMENTATION.txt", "CHANGELOG.md", "LICENSE", "THIRD_PARTY_NOTICES.md"
];
for (const path of new Set(required)) assert.ok((await stat(new URL(path, root))).size > 0, `${path} is empty`);
for (const technology of TECHNOLOGIES) {
  assert.ok((await stat(new URL(`icons/technologies/${technology.id}.svg`, root))).size > 0, `${technology.id} icon is missing`);
}
assert.ok((await stat(new URL("vendor/simple-icons-LICENSE.txt", root))).size > 0, "Simple Icons license is missing");
assert.equal(OPENWAPP_CATALOG_SIZE, Object.keys(fingerprints.technologies).length);
assert.ok(OPENWAPP_REQUIREMENTS.js.length >= 5_000, "full catalog JavaScript requirements are missing");
assert.ok(OPENWAPP_REQUIREMENTS.cookie.length >= 300, "full catalog cookie requirements are missing");
assert.ok(OPENWAPP_REQUIREMENTS.domExists.length >= 1_500, "full catalog DOM selector requirements are missing");
assert.ok(OPENWAPP_REQUIREMENTS.domAttribute.length >= 150, "full catalog DOM attribute requirements are missing");
const catalogIconFiles = new Set(await readdir(new URL("icons/catalog/", root)));
assert.equal(catalogIconFiles.size, OPENWAPP_CATALOG_SIZE, "catalog icon count does not match catalog size");
for (const name of Object.keys(fingerprints.technologies)) assert.ok(catalogIconFiles.has(`${openWappTechnologyId(name)}.svg`), `${name} catalog icon is missing`);
for (const path of ["background/service-worker.js", "data/technologies.js", "shared/detector.js", "shared/safe-properties.js", "shared/version.js", "shared/vulnerabilities.js", "popup/popup.js", "report/report.js", "scripts/audit-cve-live.mjs"]) {
  execFileSync(process.execPath, ["--check", new URL(path, root).pathname], { stdio: "pipe" });
}
for (const technology of TECHNOLOGIES) {
  for (const group of Object.values(technology.matchers || {})) {
    for (const [pattern] of group) assert.doesNotThrow(() => new RegExp(pattern, "i"), `${technology.id} has an invalid matcher`);
  }
  for (const mapping of [technology.package, ...Object.values(technology.packages || {})].filter(Boolean)) {
    assert.ok(["npm", "PyPI", "Packagist", "RubyGems"].includes(mapping.ecosystem), `${technology.id} has an unsupported OSV ecosystem mapping`);
    assert.ok(mapping.name && !/\s/.test(mapping.name), `${technology.id} has an invalid OSV package name`);
  }
  if (technology.cpe) {
    assert.equal((technology.cpe.match(/\{version\}/g) || []).length, 1, `${technology.id} CPE must contain one exact version placeholder`);
    assert.equal(technology.cpe.replace("{version}", "1.2.3").split(":").length, 13, `${technology.id} CPE is not CPE 2.3`);
  }
}

const evidence = {
  headers: {
    server: "nginx/1.24.0",
    "x-powered-by": "PHP/8.2.7, Express",
    "cf-ray": "synthetic-edge-id"
  },
  meta: [{ name: "generator", content: "WordPress 6.4.2" }],
  scripts: [
    { src: "https://cdn.example.test/jquery-3.4.1.min.js" },
    { src: "https://cdn.example.test/bootstrap-5.3.2.min.js" },
    { src: "https://cdn.example.test/axios-1.6.2.min.js" },
    { src: "https://www.googletagmanager.com/gtm.js?id=GTM-SYNTHETIC" }
  ],
  html: `<html ng-version="17.1.0"><head><link href="/wp-content/themes/synthetic/style.css"></head><body data-reactroot><div data-v-app></div><script>window.__NEXT_DATA__={};</script></body></html>`,
  globals: { jquery: "3.4.1", react: "18.2.0", vue: "3.4.0", nextjs: "true", angular: "17.1.0" }
};
const findings = analyzeEvidence(evidence);
const byId = Object.fromEntries(findings.map((item) => [item.id, item]));
for (const id of ["nginx", "php", "express", "cloudflare", "wordpress", "jquery", "bootstrap", "axios", "gtm", "react", "vue", "nextjs", "angular"]) {
  assert.ok(byId[id], `${id} was not detected`);
}
assert.equal(byId.nginx.version, "1.24.0");
assert.equal(byId.php.version, "8.2.7");
assert.equal(byId.wordpress.version, "6.4.2");
assert.equal(byId.jquery.version, "3.4.1");
assert.equal(byId.react.version, "18.2.0");
assert.equal(byId.angular.version, "17.1.0");
assert.equal(byId.wordpress.versionConfidence, "high");
assert.ok(byId.wordpress.evidence.some((item) => item.type === "meta"));
assert.ok(byId.nginx.evidence.some((item) => item.type === "header"));
assert.ok(byId.jquery.evidence.some((item) => item.type === "global"));
assert.ok(byId.bootstrap.evidence.some((item) => item.type === "script"));
assert.ok(byId.vue.evidence.some((item) => item.type === "dom" || item.type === "global"));

const negatives = analyzeEvidence({
  headers: { server: "synthetic" },
  meta: [{ name: "description", content: "A blog about WordPress and React" }],
  scripts: [{ src: "https://example.test/jquery-latest.js" }],
  html: `<p>We discuss nginx, Drupal, and CVEs here.</p>`,
  globals: {}
});
assert.equal(negatives.some((item) => ["wordpress", "react", "nginx", "drupal", "jquery"].includes(item.id)), false, "nearby plain text created a false positive");

const expandedEvidence = {
  headers: {
    server: "cloudflare",
    "cf-ray": "synthetic-edge-id",
    "x-turbo-charged-by": "LiteSpeed",
    "alt-svc": 'h3=":443"; ma=86400'
  },
  scripts: [
    { src: "https://static.cloudflareinsights.com/beacon.min.js/v-synthetic" },
    { src: "https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.min.js" },
    { src: "https://cdn.example.test/moment.js/2.29.4/moment.min.js" },
    { src: "https://cdn.example.test/popper.js/1.16.1/umd/popper.min.js" }
  ],
  links: [
    { href: "https://cdn.example.test/font-awesome/4.7.0/css/font-awesome.min.css" },
    { href: "https://cdn.example.test/select2/4.0.13/css/select2.min.css" },
    { href: "https://cdn.example.test/bootstrap/4.3.1/css/bootstrap.min.css" }
  ],
  resources: [{ name: "https://static.cloudflareinsights.com/beacon.min.js/v-synthetic" }],
  html: `<script data-cf-beacon='{"token":"synthetic"}'></script>`,
  globals: {}
};
const expanded = Object.fromEntries(analyzeEvidence(expandedEvidence).map((item) => [item.id, item]));
for (const id of ["cloudflare", "litespeed", "http3", "cloudflare-browser-insights", "font-awesome", "popper", "select2", "moment", "jquery", "bootstrap"]) {
  assert.ok(expanded[id], `${id} expanded fingerprint was not detected`);
}
assert.equal(expanded["font-awesome"].version, "4.7.0");
assert.equal(expanded.popper.version, "1.16.1");
assert.equal(expanded.select2.version, "4.0.13");
assert.equal(expanded.moment.version, "2.29.4");
assert.equal(expanded.jquery.version, "3.5.1");
assert.equal(expanded.bootstrap.version, "4.3.1");
assert.equal(expanded.popper.package.name, "popper.js");
assert.equal(expanded["font-awesome"].package.name, "font-awesome");
assert.ok(expanded["cloudflare-browser-insights"].evidence.some((item) => item.type === "asset"));

const expandedNegatives = analyzeEvidence({
  headers: { "x-turbo-charged-by": "Turbo", "alt-svc": 'h2=":443"' },
  scripts: [{ src: "https://example.test/popper-documentation.js" }],
  links: [{ href: "https://example.test/fonts.css" }, { href: "https://example.test/select2-guide.html" }],
  resources: [{ name: "https://example.test/cloudflare-insights-review.txt" }],
  html: `<meta name="csrf-token" content="generic-framework-token"><p>Font Awesome, LiteSpeed, HTTP/3, Select2 and Popper are discussed here.</p>`,
  globals: {}
});
assert.equal(expandedNegatives.some((item) => ["laravel", "litespeed", "http3", "cloudflare-browser-insights", "font-awesome", "popper", "select2"].includes(item.id)), false, "expanded nearby-negative fixture created a false positive");

const broadCatalog = analyzeOpenWappEvidence({
  url: "https://catalog.example.test/",
  headers: { server: "cloudflare", "x-powered-by": "PHP/8.2.7" },
  scripts: [{ src: "https://cdn.example.test/jquery-3.7.1.min.js" }],
  links: [{ href: "https://cdn.example.test/bootstrap/5.3.3/css/bootstrap.min.css", rel: "stylesheet" }],
  resources: [], meta: [], html: "<html><body>synthetic fixture</body></html>", text: "synthetic fixture", globals: {}, js: {}
});
const broadByName = Object.fromEntries(broadCatalog.map((item) => [item.name, item]));
for (const name of ["Cloudflare", "PHP", "jQuery"]) assert.ok(broadByName[name], `${name} maintained-catalog fingerprint was not detected`);
assert.equal(broadByName.PHP.version, "8.2.7");
assert.equal(broadByName.jQuery.version, "3.7.1");
assert.equal(broadByName.jQuery.source, "OpenWapp");
assert.ok(broadByName.jQuery.evidence.some((item) => item.type === "asset"));
const deepCatalog = analyzeOpenWappEvidence({
  domExists: ["section[class*='player30nama']"],
  domText: { ".doc-navigation footer, footer.catalog-footer": ["Powered by Bump"] },
  domAttribute: { "link[href*='bootstrap-icons']": { href: ["https://cdn.example.test/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"] } },
  domProperty: { "#app, .app, #root, .root, body, body > *, body > * > *, body > * > * > *": { __k: ["true"] } },
  js: { "LA.config.ck": ["true"] }
});
const deepNames = new Set(deepCatalog.map((item) => item.name));
for (const name of ["30namaPlayer", "Bump", "Bootstrap Icons", "Preact", "51.LA"]) assert.ok(deepNames.has(name), `${name} deep catalog signal was not detected`);
const deepNegatives = analyzeOpenWappEvidence({
  domExists: ["section[class*='player30nama-guide']"],
  domText: { ".doc-navigation footer, footer.catalog-footer": ["Built for a speed bump"] },
  domAttribute: { "link[href*='bootstrap-icons']": { href: ["https://example.test/bootstrap-guide.html"] } },
  js: { "LA.config": ["true"] }
});
assert.equal(deepNegatives.some((item) => ["30namaPlayer", "Bump", "Bootstrap Icons", "51.LA"].includes(item.name)), false, "nearby deep-signal fixture created a false positive");
const cookieCatalog = analyzeOpenWappEvidence({ cookies: { awsalb: ["synthetic-routing-cookie"], "_ga_synthetic": ["GS1.1.synthetic"] } });
const cookieNames = new Set(cookieCatalog.map((item) => item.name));
assert.ok(cookieNames.has("Amazon ALB"), "exact cookie-name fingerprint was not detected");
assert.ok(cookieNames.has("Google Analytics"), "wildcard cookie-name fingerprint was not detected");
assert.ok(cookieCatalog.find((item) => item.name === "Amazon ALB").evidence.some((item) => item.type === "cookie" && !item.detail.includes("synthetic-routing-cookie")), "cookie evidence leaked a cookie value");
const cookieNegatives = analyzeOpenWappEvidence({ cookies: { awsalbguide: ["synthetic-routing-cookie"], "ga_synthetic": ["GS1.1.synthetic"] } });
assert.equal(cookieNegatives.some((item) => ["Amazon ALB", "Google Analytics"].includes(item.name)), false, "nearby cookie names created a false positive");
let getterInvoked = false;
let callableInvoked = false;
const safeRoot = { Namespace: { version: "4.2.1" }, callable: Object.assign(() => { callableInvoked = true; }, { version: "8.1.0" }) };
Object.defineProperty(safeRoot, "danger", { get() { getterInvoked = true; throw new Error("getter must not run"); } });
const safeProperties = collectCatalogProperties(["Namespace.version", "callable", "callable.version", "danger.value"], safeRoot);
assert.equal(safeProperties["Namespace.version"], "4.2.1");
assert.equal(safeProperties.callable, "true");
assert.equal(safeProperties["callable.version"], "8.1.0");
assert.equal(getterInvoked, false, "catalog property collection invoked a getter");
assert.equal(callableInvoked, false, "catalog property collection invoked a function");
const combined = mergeTechnologyDetections(findings, broadCatalog);
assert.equal(combined.filter((item) => item.name === "jQuery").length, 1, "core and maintained catalog produced duplicate jQuery rows");
assert.equal(combined.find((item) => item.name === "jQuery").source, "Core + OpenWapp");
const popupSource = await readFile(new URL("popup/popup.js", root), "utf8");
assert.equal(/technologies\.slice\(/.test(popupSource), false, "popup still truncates the technology list");
assert.ok(popupSource.includes("technology-group"), "popup does not group the complete technology list");

const summary = summarizeTechnologies(findings);
assert.equal(summary.total, findings.length);
assert.ok(summary.versioned >= 7);
assert.equal(isExactVersion("3.4.1"), true);
assert.equal(isExactVersion("10.0"), true);
assert.equal(isExactVersion("4"), false, "major-only versions must not trigger CVE attribution");
assert.equal(isExactVersion("3.x"), false);
assert.equal(vulnerabilityCacheKey({ version: "4", package: { ecosystem: "npm", name: "font-awesome" } }), "");
assert.equal((await lookupTechnologyVulnerabilities({ version: "4", package: { ecosystem: "npm", name: "font-awesome" } }, () => { throw new Error("partial version must not fetch"); })).status, "version-inexact");

let osvRequest = null;
const osvResult = await lookupTechnologyVulnerabilities({ id: "jquery", version: "3.4.1", package: { ecosystem: "npm", name: "jquery" } }, async (url, options) => {
  osvRequest = { url, body: JSON.parse(options.body) };
  return { ok: true, json: async () => ({ vulns: [{ id: "GHSA-synthetic", aliases: ["CVE-2099-0001"], summary: "Synthetic advisory", database_specific: { severity: "HIGH" }, published: "2099-01-01T00:00:00Z" }] }) };
});
assert.equal(osvRequest.body.version, "3.4.1");
assert.equal(osvRequest.body.package.ecosystem, "npm");
assert.equal(osvResult.vulnerabilities[0].id, "CVE-2099-0001");
assert.equal(osvResult.vulnerabilities[0].severity, "high");
assert.deepEqual(osvResult.query, { basis: "exact-version", source: "OSV", version: "3.4.1", ecosystem: "npm", package: "jquery" });
assert.ok(!Number.isNaN(Date.parse(osvResult.checkedAt)));
assert.equal(vulnerabilityCacheKey({ version: "3.4.1", package: { ecosystem: "npm", name: "jquery" } }), "osv:npm:jquery:3.4.1");
const osvEmpty = await lookupTechnologyVulnerabilities({ id: "synthetic", version: "1.0.0", package: { ecosystem: "npm", name: "synthetic-safe-package" } }, async () => ({ ok: true, json: async () => ({ vulns: [] }) }));
assert.equal(osvEmpty.status, "checked");
assert.deepEqual(osvEmpty.vulnerabilities, []);
const osvDeduped = await lookupTechnologyVulnerabilities({ id: "synthetic", version: "1.0.0", package: { ecosystem: "npm", name: "synthetic-package" } }, async () => ({ ok: true, json: async () => ({ vulns: [
  { id: "GHSA-one", aliases: ["CVE-2099-0003"], summary: "First alias", database_specific: { severity: "MEDIUM" } },
  { id: "GHSA-two", aliases: ["CVE-2099-0003"], summary: "Duplicate alias", database_specific: { severity: "HIGH" } }
] }) }));
assert.equal(osvDeduped.vulnerabilities.length, 1, "duplicate CVE aliases were counted twice");
assert.equal(osvDeduped.vulnerabilities[0].severity, "high");

let nvdUrl = "";
const nvdResult = await lookupTechnologyVulnerabilities({ id: "nginx", version: "1.24.0", cpe: "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*" }, async (url) => {
  nvdUrl = url;
  return { ok: true, json: async () => ({ vulnerabilities: [{ cve: { id: "CVE-2099-0002", descriptions: [{ lang: "en", value: "Synthetic server advisory" }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }] } } }] }) };
});
assert.ok(decodeURIComponent(nvdUrl).includes("nginx:1.24.0"));
assert.equal(nvdResult.vulnerabilities[0].severity, "critical");
assert.equal(nvdResult.vulnerabilities[0].score, 9.8);
assert.equal(nvdResult.query.basis, "exact-version");
assert.equal(nvdResult.query.cpe, "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*");
assert.equal((await lookupTechnologyVulnerabilities({ id: "react", version: "", package: { ecosystem: "npm", name: "react" } }, () => { throw new Error("must not fetch"); })).status, "version-unknown");
assert.equal((await lookupTechnologyVulnerabilities({ id: "unknown", version: "1.2.3" }, () => { throw new Error("must not fetch"); })).status, "unsupported");
await assert.rejects(() => lookupTechnologyVulnerabilities({ id: "jquery", version: "3.4.1", package: { ecosystem: "npm", name: "jquery" } }, async () => ({ ok: false, status: 503 })), /OSV returned HTTP 503/);
assert.deepEqual(summarizeVulnerabilities([{ vulnerabilities: osvResult.vulnerabilities }, { vulnerabilities: nvdResult.vulnerabilities }]), { total: 2, critical: 1, high: 1, medium: 0, low: 0, unknown: 0, affectedTechnologies: 2 });

const listeners = {};
const localStore = new Map();
const sessionStore = new Map();
function storageArea(store) {
  return {
    async get(key) {
      if (typeof key === "string") return { [key]: store.get(key) };
      return Object.fromEntries((key || []).map((item) => [item, store.get(item)]));
    },
    async set(values) { for (const [key, value] of Object.entries(values)) store.set(key, value); },
    async remove(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) store.delete(key); }
  };
}
globalThis.chrome = {
  storage: { local: storageArea(localStore), session: storageArea(sessionStore) },
  action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setTitle: async () => {} },
  tabs: {
    async get(id) { return { id, title: "Synthetic App", url: "https://app.example.test/" }; },
    async query() { return [{ id: 7, title: "Synthetic App", url: "https://app.example.test/" }]; },
    async create(input) { return input; },
    onUpdated: { addListener(fn) { listeners.tabUpdated = fn; } },
    onRemoved: { addListener(fn) { listeners.tabRemoved = fn; } }
  },
  scripting: {
    async executeScript(input) {
      if (input.world !== "MAIN") assert.ok(input.args[0].includes("awsalb"), "cookie requirements were not passed to the page collector");
      return [{ result: input.world === "MAIN"
        ? { jquery: "3.4.1" }
        : { title: "Synthetic App", url: "https://app.example.test/", html: "<script src='jquery-3.4.1.min.js'></script>", htmlTruncated: false, scripts: [{ src: "https://app.example.test/jquery-3.4.1.min.js" }], links: [], meta: [], cookies: { awsalb: ["synthetic-routing-cookie"] } } }];
    }
  },
  runtime: {
    getURL(path) { return `chrome-extension://synthetic/${path}`; },
    onMessage: { addListener(fn) { listeners.message = fn; } },
    onInstalled: { addListener(fn) { listeners.installed = fn; } }
  },
  webRequest: { onHeadersReceived: { addListener(fn) { listeners.headers = fn; } } },
  commands: { onCommand: { addListener(fn) { listeners.command = fn; } } }
};
await import(`../background/service-worker.js?test=${Date.now()}`);
assert.ok(listeners.message && listeners.tabUpdated && listeners.headers, "service worker listeners not registered");
const message = (payload) => new Promise((resolve) => listeners.message(payload, {}, resolve));
let response = await message({ type: "updateSettings", settings: { enabled: false } });
assert.equal(response.ok, true);
assert.equal(response.data.enabled, false);
response = await message({ type: "scan", tabId: 7, checkCves: false });
assert.equal(response.ok, false);
assert.match(response.error, /turned off/i);
await message({ type: "updateSettings", settings: { enabled: true, autoScan: true, checkCves: false } });
response = await message({ type: "scan", tabId: 7, checkCves: false });
assert.equal(response.ok, true, response.error);
assert.equal(response.data.technologies.some((item) => item.id === "jquery"), true);
assert.equal(response.data.technologies.some((item) => item.name === "Amazon ALB"), true, "cookie evidence did not reach the scan result");
assert.equal(response.data.technologies.find((item) => item.id === "jquery").vulnerabilityStatus, "disabled");
assert.equal(response.data.summary.vulnerabilities.total, 0);

const updatedPopupSource = await readFile(new URL("popup/popup.js", root), "utf8");
const reportSource = await readFile(new URL("report/report.js", root), "utf8");
for (const status of ["checked", "pending", "version-unknown", "version-inexact", "disabled", "lookup-limit", "unsupported", "error"]) assert.ok(updatedPopupSource.includes(status), `popup is missing the ${status} CVE state`);
assert.ok(updatedPopupSource.includes("chrome.storage.onChanged"), "popup does not receive completed asynchronous CVE results");
assert.ok(reportSource.includes("Exact version match"), "report does not explain exact-version CVE attribution");
assert.ok(reportSource.includes("chrome.storage.onChanged"), "report does not receive completed asynchronous CVE results");

console.log(`✓ Manifest v${manifest.version} and ${new Set(required).size} required assets`);
console.log(`✓ ${findings.length} technology detections across header, meta, DOM, script, and global evidence`);
console.log(`✓ ${TECHNOLOGIES.length} technology definitions have valid matcher syntax`);
console.log("✓ Reviewed package ecosystems, generation mappings, CPE templates, and exact-version gate");
console.log(`✓ ${OPENWAPP_CATALOG_SIZE} maintained catalog fingerprints and local icons`);
console.log(`✓ ${OPENWAPP_REQUIREMENTS.js.length} safe JavaScript paths, ${OPENWAPP_REQUIREMENTS.cookie.length} cookie names, and ${OPENWAPP_REQUIREMENTS.domExists.length} DOM selectors wired into collection`);
console.log("✓ Positive and nearby-negative fingerprint fixtures");
console.log("✓ Descriptor-safe version collection without invoking getters or functions");
console.log("✓ Full popup technology list without result truncation");
console.log("✓ Core/catalog deduplication with catalog evidence and version extraction");
console.log("✓ OSV/NVD exact-version hits, empty results, deduplication, no-version skip, and HTTP failure handling");
console.log("✓ Distinct CVE states, exact-query provenance, and live asynchronous result rendering");
console.log("✓ Master switch, scan message, storage, and listener smoke tests");

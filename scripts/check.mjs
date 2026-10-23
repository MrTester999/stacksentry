import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { analyzeEvidence, summarizeTechnologies } from "../shared/detector.js";
import { lookupTechnologyVulnerabilities, summarizeVulnerabilities, vulnerabilityCacheKey } from "../shared/vulnerabilities.js";
import { TECHNOLOGIES } from "../data/technologies.js";

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
  "data/technologies.js", "shared/detector.js", "shared/vulnerabilities.js",
  "popup/popup.css", "popup/popup.js", "report/index.html", "report/report.css", "report/report.js",
  "screenshots/stacksentry-popup.png", "screenshots/stacksentry-report.png",
  "README.md", "DOCUMENTATION.md", "DOCUMENTATION.txt", "CHANGELOG.md"
];
for (const path of new Set(required)) assert.ok((await stat(new URL(path, root))).size > 0, `${path} is empty`);
for (const technology of TECHNOLOGIES) {
  assert.ok((await stat(new URL(`icons/technologies/${technology.id}.svg`, root))).size > 0, `${technology.id} icon is missing`);
}
assert.ok((await stat(new URL("vendor/simple-icons-LICENSE.txt", root))).size > 0, "Simple Icons license is missing");
for (const path of ["background/service-worker.js", "data/technologies.js", "shared/detector.js", "shared/vulnerabilities.js", "popup/popup.js", "report/report.js"]) {
  execFileSync(process.execPath, ["--check", new URL(path, root).pathname], { stdio: "pipe" });
}
for (const technology of TECHNOLOGIES) {
  for (const group of Object.values(technology.matchers || {})) {
    for (const [pattern] of group) assert.doesNotThrow(() => new RegExp(pattern, "i"), `${technology.id} has an invalid matcher`);
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

const summary = summarizeTechnologies(findings);
assert.equal(summary.total, findings.length);
assert.ok(summary.versioned >= 7);

let osvRequest = null;
const osvResult = await lookupTechnologyVulnerabilities({ id: "jquery", version: "3.4.1", package: { ecosystem: "npm", name: "jquery" } }, async (url, options) => {
  osvRequest = { url, body: JSON.parse(options.body) };
  return { ok: true, json: async () => ({ vulns: [{ id: "GHSA-synthetic", aliases: ["CVE-2099-0001"], summary: "Synthetic advisory", database_specific: { severity: "HIGH" }, published: "2099-01-01T00:00:00Z" }] }) };
});
assert.equal(osvRequest.body.version, "3.4.1");
assert.equal(osvRequest.body.package.ecosystem, "npm");
assert.equal(osvResult.vulnerabilities[0].id, "CVE-2099-0001");
assert.equal(osvResult.vulnerabilities[0].severity, "high");
assert.equal(vulnerabilityCacheKey({ version: "3.4.1", package: { ecosystem: "npm", name: "jquery" } }), "osv:npm:jquery:3.4.1");

let nvdUrl = "";
const nvdResult = await lookupTechnologyVulnerabilities({ id: "nginx", version: "1.24.0", cpe: "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*" }, async (url) => {
  nvdUrl = url;
  return { ok: true, json: async () => ({ vulnerabilities: [{ cve: { id: "CVE-2099-0002", descriptions: [{ lang: "en", value: "Synthetic server advisory" }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }] } } }] }) };
});
assert.ok(decodeURIComponent(nvdUrl).includes("nginx:1.24.0"));
assert.equal(nvdResult.vulnerabilities[0].severity, "critical");
assert.equal(nvdResult.vulnerabilities[0].score, 9.8);
assert.equal((await lookupTechnologyVulnerabilities({ id: "react", version: "", package: { ecosystem: "npm", name: "react" } }, () => { throw new Error("must not fetch"); })).status, "version-unknown");
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
      return [{ result: input.world === "MAIN"
        ? { jquery: "3.4.1" }
        : { title: "Synthetic App", url: "https://app.example.test/", html: "<script src='jquery-3.4.1.min.js'></script>", htmlTruncated: false, scripts: [{ src: "https://app.example.test/jquery-3.4.1.min.js" }], links: [], meta: [] } }];
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
assert.equal(response.data.summary.vulnerabilities.total, 0);

console.log(`✓ Manifest v${manifest.version} and ${new Set(required).size} required assets`);
console.log(`✓ ${findings.length} technology detections across header, meta, DOM, script, and global evidence`);
console.log(`✓ ${TECHNOLOGIES.length} technology definitions have valid matcher syntax`);
console.log("✓ Positive and nearby-negative fingerprint fixtures");
console.log("✓ OSV and NVD exact-version normalization with no-version skip");
console.log("✓ Master switch, scan message, storage, and listener smoke tests");

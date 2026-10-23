# Changelog

## 2.2.0

- Redesigned the popup inventory as category-grouped rows with icon,
  confidence, confirmed version, CVE status, and matched CVE IDs.
- Added exact-query provenance to completed vulnerability lookups: source,
  package or CPE, queried version, and check timestamp.
- Separated disabled, lookup-limit, unsupported, version-unknown, pending,
  checked, and error states so unqueried technologies are never presented as
  clean results.
- Made manual scans return local detections immediately while OSV/NVD checks
  continue asynchronously; popup and report update live when checks finish.
- Kept version reporting conservative: observable versions are displayed and
  missing versions remain unknown instead of being guessed.
- Unified all catalog JavaScript version reads through descriptor-only traversal
  and verified that throwing getters and callable values are never invoked.

## 2.1.0

- Expanded runtime inspection from a short hand-picked global list to all 5,606
  JavaScript property paths used by the maintained catalog.
- Preserved case-sensitive JavaScript property names during matching instead of
  lowercasing them like HTTP header names.
- Added catalog-driven evaluation for 1,572 DOM existence selectors, 55 DOM
  text selectors, 166 attribute selector groups, and two DOM properties.
- Kept runtime reads passive by inspecting data properties only; accessor
  getters are never invoked and page code is never executed by StackSentry.
- Added positive and nearby-negative fixtures for JavaScript, DOM existence,
  DOM text, DOM attribute, and DOM property detections.
- Replaced the three-item popup preview with a scrollable, category-grouped list
  that displays every technology found on the current page.
- Hardened CVE result accuracy by deduplicating advisory aliases, preserving the
  strongest severity, and testing exact-version hits, empty results, missing
  versions, unsupported mappings, and upstream HTTP failures.

## 2.0.0

- Expanded passive detection from 49 focused definitions to a combined catalog
  of 7,628 maintained technology fingerprints across 109 categories.
- Bundled the pinned OpenWapp matcher and WebAppAnalyzer-derived catalog locally;
  no detection rules are downloaded while browsing.
- Added bounded visible-text, inline-script, inline-style, resource, and selected
  safe global evidence without collecting cookies.
- Merged overlapping Core and OpenWapp detections to prevent duplicate rows while
  preserving exact-version OSV/NVD mappings.
- Added a deterministic local icon for every catalog technology and verified the
  complete icon set during builds.
- Increased popup and report typography, added catalog coverage and detection
  source labels, and clarified technology cards.
- Added GPL-3.0 licensing and complete third-party notices for the bundled catalog.

## 1.1.0

- Added detection for LiteSpeed, HTTP/3, Cloudflare Browser Insights, Select2,
  Popper, and Font Awesome.
- Added stylesheet and Performance Resource Timing evidence so technologies
  loaded outside ordinary script tags can be recognized.
- Expanded CDN-path version extraction for jQuery, Bootstrap, Moment.js,
  Select2, Popper, and Font Awesome.
- Added major-version-aware package mapping for Popper and Font Awesome so
  exact-version CVE queries use the correct npm package generation.
- Added a bundled local icon for every technology, using Simple Icons brand
  artwork where available and a deterministic product fallback elsewhere.
- Added positive and nearby-negative fixtures for every broadened fingerprint.

## 1.0.0

- Added automatic analysis for every visited HTTP or HTTPS website.
- Added master On/Off, Auto Scan, CVE lookup, and per-host exclusion controls.
- Added a local technology catalog spanning CMS, frameworks, libraries,
  backends, servers, CDNs, hosting, analytics, and APIs.
- Added evidence-backed version extraction from headers, metadata, DOM markers,
  assets, and selected runtime globals.
- Added exact-version OSV and NVD lookups with a bounded 24-hour local cache.
- Added a compact popup, full intelligence report, severity dashboard,
  evidence view, filters, and JSON export.
- Added positive and nearby-negative fingerprint fixtures plus mocked Chrome API,
  OSV, and NVD tests.

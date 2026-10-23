# Changelog

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

# StackSentry Documentation

## Overview

StackSentry is a Chromium Manifest V3 extension that automatically identifies
web technologies and their observable versions, then checks exact supported
versions against OSV.dev or the NIST NVD.

## Scan lifecycle

1. Chrome reports that an HTTP or HTTPS tab finished loading.
2. StackSentry checks the master switch, Auto Scan setting, and hostname
   exclusion list.
3. The extension collects an immediate bounded local fingerprint from metadata, HTML,
   visible text, inline scripts and styles, asset URLs, dynamic resource URLs,
   catalog-requested DOM signals, descriptor-safe JavaScript properties,
   page-readable cookie signals, and response headers.
4. A second bounded pass runs after a short settle window. Early and late DOM,
   scripts, styles, resources, cookies, metadata, and JavaScript evidence are
   deduplicated and merged.
5. StackSentry Core and the bundled 7,628-definition maintained catalog run
   locally. Overlapping results are merged with evidence, confidence, and any
   explicit version.
6. Exact supported versions are checked against the appropriate vulnerability
   service. Results are cached locally for 24 hours.
7. The per-tab badge and report are updated. Stale asynchronous CVE results are
   discarded when a newer scan has replaced them.

## Controls

- **Master switch:** disables all scanning and clears action badges.
- **Auto Scan:** enables or disables scanning after each website navigation.
- **Version-aware CVE checks:** enables or disables OSV/NVD lookups.
- **Exclude this site:** adds or removes the current hostname from the local
  exclusion list. Subdomains are also covered.
- **Analyze this website:** starts a manual scan when the extension is enabled.
- **Open full intelligence report:** opens the evidence and advisory workspace.

The popup itself also displays every detected technology, grouped by category.
Each row includes confidence, a confirmed version when observable, exact CVE
status, and matched CVE IDs. The list scrolls so large stacks are not truncated.

## Detection confidence

- **High:** an explicit runtime version, generator metadata, response header, or
  version-bearing asset matched.
- **Medium:** a specific DOM or asset fingerprint matched without an exact
  version.
- **Low:** a weaker single indicator matched and needs additional confirmation.

Multiple independent indicators increase the final confidence score.

## CVE statuses

- **Checked:** the exact version was queried successfully.
- **Version unknown:** the technology was detected but no reliable version was
  available, so no CVE claim was made.
- **Partial version:** a major-only or non-exact version was visible, but the
  CVE query was skipped to prevent false attribution.
- **Unsupported:** the technology lacks a reviewed package or CPE mapping.
- **Error:** the configured public service was temporarily unavailable.
- **Check disabled:** CVE enrichment was disabled for this scan.
- **Lookup limit:** a supported exact version was detected but was outside the
  bounded per-scan query set, so no vulnerability conclusion was made.

An empty checked result means no advisory was returned for that exact mapping at
the time of the query. It is not a guarantee that the product is vulnerability-free.
Duplicate advisory records that resolve to the same CVE ID are counted once.
Completed checks record the exact OSV package tuple or versioned NVD CPE and the
query time. Popup and report views update when asynchronous checks finish.

## Data handling

- DOM content is bounded to 1.5 MB and used only during local detection.
- Visible text, inline scripts, and inline styles use separate bounded samples.
- JavaScript inspection reads only own data-property descriptors. It does not
  call accessors, invoke functions, or execute page-provided code.
- DOM content and response headers are not stored in completed reports.
- Page-readable cookies are matched transiently in memory only. Cookie values
  are never stored in reports, shown as evidence, or sent remotely.
- `Set-Cookie` headers and HTTP-only cookies are excluded from collection.
- Temporary scan results use `chrome.storage.session` and disappear when the
  browser session ends.
- Settings, exclusions, and bounded CVE cache entries use local extension storage.
- Only package/product identifiers and exact versions leave the browser during a
  CVE query.

## Limits

Client-side browser inspection cannot discover every origin service. Technologies
may suppress versions, bundle dependencies, sit behind a CDN, or expose misleading
headers. DNS-only, certificate-issuer, active-probe, and robots-only catalog
signals are outside this passive browser scan. Always inspect the evidence and
validate high-impact findings manually.

## Install

1. Extract `dist/stacksentry-2.3.1.zip`.
2. Open `chrome://extensions`.
3. Enable Developer mode.
4. Select **Load unpacked** and choose the extracted directory.
5. Reload the extension card after updating local source files.

## Keyboard shortcut

`Alt+Shift+S` scans the active website and opens the full report.

## Responsible use

Use StackSentry only for development, defensive inventory, or security testing
that you are authorized to perform. The extension identifies public client-side
signals and does not include exploitation features.

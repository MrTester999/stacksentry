# StackSentry Documentation

## Overview

StackSentry is a Chromium Manifest V3 extension that automatically identifies
web technologies and their observable versions, then checks exact supported
versions against OSV.dev or the NIST NVD.

## Scan lifecycle

1. Chrome reports that an HTTP or HTTPS tab finished loading.
2. StackSentry checks the master switch, Auto Scan setting, and hostname
   exclusion list.
3. The extension collects a bounded local fingerprint from metadata, HTML,
   visible text, inline scripts and styles, asset URLs, dynamic resource URLs,
   selected safe globals, and response headers.
4. StackSentry Core and the bundled 7,628-definition maintained catalog run
   locally. Overlapping results are merged with evidence, confidence, and any
   explicit version.
5. Exact supported versions are checked against the appropriate vulnerability
   service. Results are cached locally for 24 hours.
6. The per-tab badge and report are updated.

## Controls

- **Master switch:** disables all scanning and clears action badges.
- **Auto Scan:** enables or disables scanning after each website navigation.
- **Version-aware CVE checks:** enables or disables OSV/NVD lookups.
- **Exclude this site:** adds or removes the current hostname from the local
  exclusion list. Subdomains are also covered.
- **Analyze this website:** starts a manual scan when the extension is enabled.
- **Open full intelligence report:** opens the evidence and advisory workspace.

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
- **Unsupported:** the technology lacks a reviewed package or CPE mapping.
- **Error:** the configured public service was temporarily unavailable.

An empty checked result means no advisory was returned for that exact mapping at
the time of the query. It is not a guarantee that the product is vulnerability-free.

## Data handling

- DOM content is bounded to 1.5 MB and used only during local detection.
- Visible text, inline scripts, and inline styles use separate bounded samples.
- DOM content and response headers are not stored in completed reports.
- `Set-Cookie` is excluded from collection.
- Temporary scan results use `chrome.storage.session` and disappear when the
  browser session ends.
- Settings, exclusions, and bounded CVE cache entries use local extension storage.
- Only package/product identifiers and exact versions leave the browser during a
  CVE query.

## Limits

Client-side browser inspection cannot discover every origin service. Technologies
may suppress versions, bundle dependencies, sit behind a CDN, or expose misleading
headers. Always inspect the evidence and validate high-impact findings manually.

## Install

1. Extract `dist/stacksentry-2.0.0.zip`.
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

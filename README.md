<div align="center">

  <img src="icons/icon128.png" width="112" alt="StackSentry icon">

  # StackSentry

  **Automatic web-stack fingerprinting with evidence, exact versions, and version-aware CVE intelligence.**

  [![Version](https://img.shields.io/badge/version-1.1.0-39cdb9?style=flat-square)](manifest.json)
  [![Chrome MV3](https://img.shields.io/badge/Chrome-Manifest%20V3-4285F4?style=flat-square&logo=googlechrome&logoColor=white)](manifest.json)
  [![Data](https://img.shields.io/badge/CVE%20data-OSV%20%2B%20NVD-5d84ff?style=flat-square)](#version-aware-vulnerability-intelligence)
  [![Privacy](https://img.shields.io/badge/page%20fingerprinting-local-29b99e?style=flat-square)](#privacy)

</div>

---

## What it does

StackSentry automatically analyzes each HTTP or HTTPS site after it loads. It
collects non-invasive fingerprints from the DOM, script and stylesheet URLs,
generator metadata, selected JavaScript globals, and observable response
headers. Every detection includes its evidence and confidence score.

When StackSentry finds an **exact version**, it can check that product version
against [OSV.dev](https://osv.dev/) or the
[NIST National Vulnerability Database](https://nvd.nist.gov/). Unknown versions
are never guessed and are never labeled vulnerable.

> [!IMPORTANT]
> A detected technology or advisory match is an investigation lead, not proof
> that a vulnerability is reachable or exploitable. Validate the finding in the
> target's authorized testing scope.

## Screenshots

### Automatic technology and CVE summary

![StackSentry popup](screenshots/stacksentry-popup.png)

### Full evidence-backed intelligence report

![StackSentry report](screenshots/stacksentry-report.png)

## Features

- **Automatic scanning:** analyzes every normal website after navigation.
- **Master On/Off:** stops both automatic and manual analysis and clears badges.
- **Site exclusions:** pauses Auto Scan for selected hostnames and subdomains.
- **Six evidence layers:** headers, metadata, DOM markers, script/stylesheet
  URLs, dynamically loaded resource URLs, and runtime globals.
- **Technology icons:** every detected product has a bundled local brand or
  category icon; no remote icon requests are made.
- **Version extraction:** records the version only when a fingerprint exposes it.
- **Evidence and confidence:** every detection shows why it matched.
- **Live CVE intelligence:** queries exact package versions through OSV and
  mapped server/CMS products through NVD CPE.
- **24-hour local CVE cache:** reduces duplicate requests and browsing overhead.
- **Severity dashboard:** critical, high, medium, and low advisory counts.
- **Local export:** downloads a structured JSON report for later review.
- **Professional dark UI:** compact popup plus a full responsive report workspace.

## Technology coverage

The initial catalog covers common technologies across:

- CMS and e-commerce: WordPress, WooCommerce, Elementor, Drupal, Joomla,
  Shopify, Wix, and Webflow.
- Frontend frameworks: React, Next.js, Vue, Nuxt, Angular, Svelte, Astro, and
  Alpine.js.
- JavaScript libraries: jQuery, Bootstrap, Lodash, Axios, Moment.js, GSAP,
  RequireJS, Select2, Popper, Font Awesome, and Sentry.
- Backends: PHP, ASP.NET, Express, Laravel, Django, and Ruby on Rails.
- Servers and infrastructure: nginx, Apache HTTP Server, IIS, Cloudflare,
  LiteSpeed, HTTP/3, Akamai, Fastly, Vercel, and Netlify.
- Analytics and APIs: Google Analytics, Google Tag Manager, Meta Pixel, Hotjar,
  Cloudflare Browser Insights, and GraphQL.

The rule catalog is deliberately extensible in [`data/technologies.js`](data/technologies.js).

## Version-aware vulnerability intelligence

StackSentry uses two authoritative sources:

1. **OSV.dev** for exact open-source package versions in ecosystems such as npm,
   PyPI, Packagist, and RubyGems.
2. **NVD 2.0** for exact products that have a reviewed local CPE mapping.

The extension does not send the page URL, DOM, headers, or browsing history to
either service. A request contains only the mapped package/product and exact
version needed for the query.

If a version is missing, ambiguous, or unsupported, the report says so instead
of performing a broad product-name lookup.

## Installation

1. Download and extract [`stacksentry-1.1.0.zip`](dist/stacksentry-1.1.0.zip).
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Choose the extracted `stacksentry` folder.
6. Pin StackSentry from Chrome's Extensions menu.

Chrome cannot load the ZIP directly with **Load unpacked**; extract it first.

## Usage

### Automatic mode

1. Keep the master switch and **Auto Scan** enabled.
2. Visit a normal HTTP or HTTPS website.
3. Wait for the page to finish loading.
4. The badge shows the number of detected technologies.
5. Open the popup for the summary or select **Open full intelligence report**.

### Manual scan

Open the popup and select **Analyze this website**, or press `Alt+Shift+S` to
scan and open the report.

### Pause the extension

- Use the top-right master switch to turn StackSentry completely off.
- Use **Auto Scan** to keep manual scans available while stopping navigation scans.
- Use **Exclude this site** to pause only the current hostname and its subdomains.

## Permissions

| Permission | Purpose |
|---|---|
| `activeTab`, `tabs` | Identify the current tab and maintain per-tab results |
| `scripting` | Collect page fingerprints after navigation or a manual scan |
| `webRequest` | Observe non-sensitive response headers without modifying traffic |
| `storage` | Save settings, exclusions, temporary reports, and the CVE cache |
| HTTP(S) host access | Analyze normal websites and query OSV/NVD |

StackSentry never blocks, redirects, or modifies network requests.

## Privacy

- Page fingerprinting runs inside the browser.
- Page HTML is sampled in memory and is not persisted in reports.
- Cookies and `Set-Cookie` headers are intentionally not collected.
- Only exact product/package names and versions are sent to OSV or NVD.
- CVE results are cached locally for 24 hours.
- No analytics, telemetry, account, or remote StackSentry service is used.

## Accuracy boundaries

- Websites can hide or remove version information.
- Reverse proxies may expose their own server header instead of the origin stack.
- Build tools can rename, bundle, or remove recognizable asset fingerprints.
- A CVE match means the reported version is listed as affected; it does not prove
  the vulnerable code path is enabled or reachable.
- Client-side inspection cannot reliably identify every backend component.

## Development

```bash
npm install --ignore-scripts
npm run check
npm run build
```

The check suite validates manifest assets, JavaScript syntax, positive and
nearby-negative fingerprints, exact-version OSV/NVD normalization, the master
switch, storage, and Chrome event registration.

## Documentation

- [Detailed documentation](DOCUMENTATION.md)
- [Plain-text guide](DOCUMENTATION.txt)
- [Changelog](CHANGELOG.md)
- [Release ZIP](dist/stacksentry-1.1.0.zip)

---

<div align="center">
  <strong>StackSentry v1.1.0</strong><br>
  Evidence first. Exact versions. Honest vulnerability intelligence.
</div>

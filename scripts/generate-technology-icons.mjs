import * as simpleIcons from "simple-icons";
import fingerprints from "@openwapp/fingerprints";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { TECHNOLOGIES } from "../data/technologies.js";

const slugByTechnology = {
  wordpress: "wordpress", woocommerce: "woocommerce", elementor: "elementor", drupal: "drupal", joomla: "joomla",
  shopify: "shopify", webflow: "webflow", wix: "wix", react: "react", nextjs: "nextdotjs", vue: "vuedotjs",
  nuxt: "nuxt", angular: "angular", svelte: "svelte", astro: "astro", alpinejs: "alpinedotjs", jquery: "jquery",
  bootstrap: "bootstrap", lodash: "lodash", axios: "axios", gsap: "greensock", "font-awesome": "fontawesome",
  php: "php", aspnet: "dotnet", express: "express", laravel: "laravel", django: "django", rails: "rubyonrails",
  nginx: "nginx", apache: "apache", cloudflare: "cloudflare", akamai: "akamai", fastly: "fastly", vercel: "vercel",
  netlify: "netlify", "google-analytics": "googleanalytics", gtm: "googletagmanager", "meta-pixel": "meta",
  hotjar: "hotjar", "cloudflare-browser-insights": "cloudflare", sentry: "sentry", graphql: "graphql"
};

const iconsBySlug = new Map(Object.values(simpleIcons).filter((icon) => icon?.slug).map((icon) => [icon.slug, icon]));
const normalize = (value) => String(value || "").toLowerCase().replace(/\.svg$/i, "").replace(/[^a-z0-9]+/g, "");
const iconsByName = new Map(Object.values(simpleIcons).filter((icon) => icon?.slug).flatMap((icon) => [[normalize(icon.slug), icon], [normalize(icon.title), icon]]));
const escapeXml = (value) => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[char]);
const initials = (name) => name.split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();
const slug = (value) => String(value).toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 54) || "technology";
const hash = (value) => {
  let current = 2166136261;
  for (const char of String(value)) current = Math.imul(current ^ char.charCodeAt(0), 16777619);
  return (current >>> 0).toString(36);
};
const catalogId = (name) => `ow-${slug(name)}-${hash(name).slice(0, 7)}`;
const palette = ["39e2ca", "6389ff", "f2b84b", "ff6e83", "9b8cff", "50c878", "ff914d", "42b8d5"];

function iconSvg(name, color, icon) {
  const rgb = color.match(/.{2}/g)?.map((part) => Number.parseInt(part, 16)) || [57, 226, 202];
  const luminance = 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
  const visible = luminance < 65 ? "aeb8c8" : color;
  return icon
    ? icon.svg.replace("<path ", `<path fill="#${visible}" `)
    : `<svg xmlns="http://www.w3.org/2000/svg" role="img" viewBox="0 0 24 24"><title>${escapeXml(name)}</title><path fill="#${visible}" d="M12 1.5 21 6v12l-9 4.5L3 18V6l9-4.5Zm0 2.23L5 7.23v9.54l7 3.5 7-3.5V7.23l-7-3.5Z"/><text x="12" y="14.65" fill="#${visible}" font-family="Arial,sans-serif" font-size="7" font-weight="700" text-anchor="middle">${escapeXml(initials(name))}</text></svg>`;
}

await mkdir("icons/technologies", { recursive: true });
for (const technology of TECHNOLOGIES) {
  const icon = iconsBySlug.get(slugByTechnology[technology.id]);
  const color = technology.color?.replace("#", "") || "39e2ca";
  const svg = iconSvg(technology.name, color, icon);
  await writeFile(`icons/technologies/${technology.id}.svg`, svg);
}

await rm("icons/catalog", { recursive: true, force: true });
await mkdir("icons/catalog", { recursive: true });
const catalogEntries = Object.entries(fingerprints.technologies);
for (let offset = 0; offset < catalogEntries.length; offset += 200) {
  await Promise.all(catalogEntries.slice(offset, offset + 200).map(async ([name, technology]) => {
    const icon = iconsByName.get(normalize(technology.icon)) || iconsByName.get(normalize(name));
    const category = Number(technology.cats?.[0] || 0);
    const color = icon?.hex?.toLowerCase() || palette[category % palette.length];
    await writeFile(`icons/catalog/${catalogId(name)}.svg`, iconSvg(name, color, icon));
  }));
}
await mkdir("vendor", { recursive: true });
await writeFile("vendor/simple-icons-LICENSE.txt", await readFile("node_modules/simple-icons/LICENSE.md"));
console.log(`Generated ${TECHNOLOGIES.length} core icons and ${catalogEntries.length} catalog icons.`);

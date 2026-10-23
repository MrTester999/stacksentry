import * as simpleIcons from "simple-icons";
import { mkdir, readFile, writeFile } from "node:fs/promises";
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
const escapeXml = (value) => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[char]);
const initials = (name) => name.split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();

await mkdir("icons/technologies", { recursive: true });
for (const technology of TECHNOLOGIES) {
  const icon = iconsBySlug.get(slugByTechnology[technology.id]);
  const rawColor = technology.color?.replace("#", "") || "39e2ca";
  const rgb = rawColor.match(/.{2}/g)?.map((part) => Number.parseInt(part, 16)) || [57, 226, 202];
  const luminance = 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
  const color = luminance < 65 ? "aeb8c8" : rawColor;
  const svg = icon
    ? icon.svg.replace("<path ", `<path fill="#${color}" `)
    : `<svg xmlns="http://www.w3.org/2000/svg" role="img" viewBox="0 0 24 24"><title>${escapeXml(technology.name)}</title><path fill="#${color}" d="M12 1.5 21 6v12l-9 4.5L3 18V6l9-4.5Zm0 2.23L5 7.23v9.54l7 3.5 7-3.5V7.23l-7-3.5Z"/><text x="12" y="14.65" fill="#${color}" font-family="Arial,sans-serif" font-size="7" font-weight="700" text-anchor="middle">${escapeXml(initials(technology.name))}</text></svg>`;
  await writeFile(`icons/technologies/${technology.id}.svg`, svg);
}
await mkdir("vendor", { recursive: true });
await writeFile("vendor/simple-icons-LICENSE.txt", await readFile("node_modules/simple-icons/LICENSE.md"));
console.log(`Generated ${TECHNOLOGIES.length} local technology icons.`);

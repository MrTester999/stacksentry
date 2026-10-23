import { build } from "esbuild";
import { cp, copyFile, mkdir, rm } from "node:fs/promises";

await mkdir("vendor", { recursive: true });
await build({
  entryPoints: ["shared/openwapp-entry.js"],
  outfile: "vendor/openwapp-engine.js",
  bundle: true,
  minify: true,
  format: "esm",
  platform: "browser",
  target: "chrome120",
  legalComments: "none",
  logLevel: "warning"
});
await copyFile("node_modules/@openwapp/fingerprints/LICENSE", "vendor/openwapp-fingerprints-LICENSE.txt");
await copyFile("node_modules/@openwapp/matcher/LICENSE", "vendor/openwapp-matcher-LICENSE.txt");
await copyFile("node_modules/@openwapp/fingerprints/data/upstream.json", "vendor/openwapp-upstream.json");
await rm("vendor/openwapp-source", { recursive: true, force: true });
await mkdir("vendor/openwapp-source", { recursive: true });
await cp("node_modules/@openwapp/fingerprints/data", "vendor/openwapp-source/data", { recursive: true });
for (const file of ["README.md", "index.js", "package.json"]) {
  await copyFile(`node_modules/@openwapp/fingerprints/${file}`, `vendor/openwapp-source/${file}`);
}
console.log("Bundled the maintained OpenWapp catalog and matcher locally.");

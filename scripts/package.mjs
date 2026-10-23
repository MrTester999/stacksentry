import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";

const manifest = JSON.parse(await readFile("manifest.json", "utf8"));
const archive = `dist/stacksentry-${manifest.version}.zip`;
execFileSync("zip", ["-q", "-r", "-FS", archive,
  "manifest.json", "background", "data", "shared", "popup", "report", "icons", "screenshots", "vendor",
  "README.md", "DOCUMENTATION.md", "DOCUMENTATION.txt", "CHANGELOG.md"
], { stdio: "inherit" });
execFileSync("unzip", ["-t", archive], { stdio: "inherit" });
console.log(`Created ${archive}`);

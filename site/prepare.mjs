// Build a static, allowlisted artifact for GitHub Pages or another static host.
import { copyFileSync, mkdirSync, existsSync, realpathSync, lstatSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = realpathSync(path.dirname(fileURLToPath(import.meta.url)));
const output = path.join(root, "dist");
// Only regenerate this project's exact dist directory; preserve unexpected links.
if (path.relative(root, output) !== "dist") throw Error("Invalid output directory");
if (existsSync(output) && (lstatSync(output).isSymbolicLink() || realpathSync(output) !== output)) throw Error("Refusing linked output directory");
rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });
for (const name of ["index.html", "styles.css", "script.js", "favicon.svg", ".nojekyll"]) {
  copyFileSync(path.join(root, name), path.join(output, name));
}
console.log("Prepared static assets in dist/");

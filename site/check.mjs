import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import vm from "node:vm";

const root = path.dirname(fileURLToPath(import.meta.url));
const html = readFileSync(path.join(root, "index.html"), "utf8");
const script = readFileSync(path.join(root, "script.js"), "utf8");
const allIds = [...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]);
const ids = new Set(allIds);
assert.equal(ids.size, allIds.length, "duplicate IDs");
for (const [, href] of html.matchAll(/href="#([^"]+)"/g)) assert(ids.has(href), `missing anchor ${href}`);
for (const [, file] of html.matchAll(/(?:src|href)="(\.\/[^\"]+)"/g)) assert(existsSync(path.join(root, file)), `missing asset ${file}`);
assert(!/(?:src|href)="\/(?!\/)/.test(html), "root-relative paths break project Pages hosting");
for (const [, id] of html.matchAll(/data-copy="([^"]+)"/g)) assert(id === "install" || ids.has(id), `missing copy target ${id}`);

function element(dataset = {}) {
  return {
    dataset, textContent: "", innerHTML: "Copy command", value: "", style: {}, attributes: {}, handlers: {}, disabled: false,
    addEventListener(event, fn) { this.handlers[event] = fn; },
    setAttribute(key, value) { this.attributes[key] = value; },
    classList: { toggle() {} }, focus() { this.focused = true; }, select() { this.selected = true; },
    querySelector() { return null; }, appendChild(child) { this.child = child; }
  };
}

for (const mode of ["success", "unavailable", "rejected"]) {
  const nodes = Object.fromEntries([...ids].map(id => [id, element()]));
  nodes["preset-command"].textContent = "proxycheck run -p youtube proxies.txt";
  nodes["install-platform"].value = "unix";
  nodes["install-platform"].selectedIndex = 0;
  nodes["install-platform"].options = [{ text: "Linux / macOS" }, { text: "Windows" }];
  const outcomes = [...html.matchAll(/data-outcome="([^"]+)"/g)].map(m => element({ outcome: m[1] }));
  const presets = [...html.matchAll(/data-preset="([^"]+)"/g)].map(m => element({ preset: m[1] }));
  const copies = [...html.matchAll(/data-copy="([^"]+)"/g)].map(m => {
    const button = element({ copy: m[1] }); button.parentElement = element(); return button;
  });
  let clipboard;
  const navigator = mode === "unavailable" ? {} : { clipboard: { async writeText(value) { if (mode === "rejected") throw Error("denied"); clipboard = value; } } };
  const document = {
    getElementById(id) { assert(nodes[id], `unknown DOM ID ${id}`); return nodes[id]; },
    querySelectorAll(selector) { return { "[data-outcome]": outcomes, "[data-preset]": presets, "[data-copy]": copies }[selector] ?? []; },
    createElement() { return element(); }
  };
  vm.runInNewContext(script, { document, navigator, setTimeout: () => 1, clearTimeout() {} });
  for (const button of outcomes) {
    button.handlers.click();
    const result = JSON.parse(nodes["result-json"].textContent);
    assert.equal(result.ok, button.dataset.outcome === "passed");
    if (!result.ok) assert.equal(result.error_class, button.dataset.outcome);
    assert.equal(button.attributes["aria-pressed"], "true");
  }
  for (const button of presets) {
    button.handlers.click();
    assert.equal(nodes["preset-command"].textContent, `proxycheck run -p ${button.dataset.preset} proxies.txt`);
    assert(nodes["preset-explanation"].textContent.length > 20);
  }
  nodes["install-platform"].value = "windows";
  nodes["install-platform"].selectedIndex = 1;
  nodes["install-platform"].handlers.change();
  assert.equal(nodes["run-command"].textContent, ".\\proxycheck.exe run -p basic proxies.txt");
  for (const button of copies) {
    await button.handlers.click();
    const expected = button.dataset.copy === "install" ? ".\\proxycheck.exe run -p basic proxies.txt" : nodes["preset-command"].textContent;
    if (mode === "success") { assert(clipboard.includes(expected)); assert.equal(button.textContent, "Copied ✓"); }
    else { assert.equal(button.textContent, "Select and copy"); assert(button.parentElement.child.value.includes(expected)); assert(button.parentElement.child.selected); }
    assert.equal(button.disabled, false);
  }
}
console.log("PASS: Pages-relative assets, anchors, preset/results controls, Windows commands and all clipboard paths");

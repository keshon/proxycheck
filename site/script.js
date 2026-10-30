"use strict";
(() => {
  const presets = {
    basic: { description: "Fetches api.ipify.org over HTTPS and requires an HTTP 200 response." },
    anonymity: { description: "Compares the exit IP with your direct origin IP and reports same, different or unknown. Forwarded-origin headers are outside this check." },
    youtube: { description: "Checks YouTube metadata and image delivery. It does not verify video playback." },
    telegram: { description: "Checks the Telegram Bot API with expected status and response markers. It does not test MTProto or every Telegram client feature." }
  };
  const outcomes = {
    passed: { ok: true, time: 284, verdict: "✓ Assertions passed", explanation: "The metadata request and image download met the configured checks." },
    timeout: { ok: false, time: 15000, verdict: "× Check timed out", error: "context deadline exceeded", explanation: "The check did not finish before its timeout." },
    target_block: { ok: false, time: 192, verdict: "× Response rejected", error: "Forbidden (403)", explanation: "The target returned HTTP 403, so the request did not pass this check." }
  };
  const announce = message => { document.getElementById("interaction-status").textContent = message; };
  document.querySelectorAll("[data-outcome]").forEach(button => {
    button.addEventListener("click", () => {
      const key = button.dataset.outcome;
      const outcome = outcomes[key];
      const result = { proxy: "http://192.0.2.10:8080", check: "youtube", ok: outcome.ok };
      if (!outcome.ok) { result.error_class = key; result.error = outcome.error; }
      result.total_ms = outcome.time;
      result.checked_at = "2026-10-30T12:00:00Z";
      document.getElementById("result-json").textContent = JSON.stringify(result, null, 2);
      document.getElementById("result-verdict").textContent = outcome.verdict;
      document.getElementById("result-time").textContent = `${outcome.time.toLocaleString("en-US")} ms`;
      document.getElementById("result-explanation").textContent = outcome.explanation;
      document.querySelectorAll("[data-outcome]").forEach(item => item.setAttribute("aria-pressed", String(item === button)));
      announce(`Illustrative result: ${outcome.verdict}. ${outcome.explanation}`);
    });
  });
  document.querySelectorAll("[data-preset]").forEach(button => {
    button.addEventListener("click", () => {
      const key = button.dataset.preset;
      document.getElementById("preset-command").textContent = `proxycheck run -p ${key} proxies.txt`;
      document.getElementById("preset-explanation").textContent = presets[key].description;
      document.querySelectorAll("[data-preset]").forEach(item => {
        item.setAttribute("aria-pressed", String(item === button));
        item.classList.toggle("active", item === button);
      });
      announce(`${key} selected. ${presets[key].description}`);
    });
  });
  const platform = document.getElementById("install-platform");
  function installCommands() {
    const windows = platform.value === "windows";
    return ["git clone https://github.com/keshon/proxycheck.git", "cd proxycheck", `go build -o ${windows ? "proxycheck.exe" : "proxycheck"} ./cmd/proxycheck`, `${windows ? ".\\proxycheck.exe" : "./proxycheck"} run -p basic proxies.txt`];
  }
  platform.addEventListener("change", () => {
    const commands = installCommands();
    document.getElementById("build-command").textContent = commands[2];
    document.getElementById("run-command").textContent = commands[3];
    announce(`Quick start updated for ${platform.options[platform.selectedIndex].text}. Add your own proxies.txt before running the final command.`);
  });
  document.querySelectorAll("[data-copy]").forEach(button => {
    const original = button.innerHTML;
    let reset;
    button.addEventListener("click", async () => {
      const target = button.dataset.copy === "install" ? null : document.getElementById(button.dataset.copy);
      const text = target ? target.textContent : installCommands().join("\n");
      button.disabled = true;
      clearTimeout(reset);
      try {
        if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
        await navigator.clipboard.writeText(text);
        button.textContent = "Copied ✓";
        announce(button.dataset.copy === "install" ? "Quick-start commands copied. Add your proxies.txt before running the check." : "Command copied.");
      } catch {
        // A visible, selectable value supports manual copying without claiming success.
        let field = button.parentElement.querySelector(".manual-copy-field");
        if (!field) {
          field = document.createElement("textarea");
          field.className = "manual-copy-field";
          field.setAttribute("aria-label", "Select these commands and copy manually");
          field.readOnly = true;
          field.style.cssText = "display:block;width:100%;min-height:90px;margin-top:12px;font:12px monospace;padding:10px;border:1px solid #214ce5;background:#f5f5f0;color:#20241f";
          button.parentElement.appendChild(field);
        }
        field.value = text;
        field.focus();
        field.select();
        button.textContent = "Select and copy";
        announce("Clipboard access is unavailable. The commands are selected below; use your keyboard or context menu to copy.");
      } finally {
        button.disabled = false;
        reset = setTimeout(() => { button.innerHTML = original; }, 2500);
      }
    });
  });
})();

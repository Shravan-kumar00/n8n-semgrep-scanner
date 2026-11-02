/**
 * n8n Workflow Scanner - front-end logic.
 *
 * Security note: every value coming from the API (which may echo parts of the
 * pasted workflow) is inserted with textContent, never innerHTML.
 */
(() => {
  "use strict";

  const MAX_BYTES = 2_000_000;          // keep in sync with MAX_PAYLOAD_BYTES
  const REQUEST_TIMEOUT_MS = 90_000;    // a bit above SCAN_TIMEOUT_SECONDS

  // Full class names are listed literally so Tailwind generates them.
  const RISK = {
    critical: { label: "Critical", badge: "bg-red-600 text-white",     border: "border-l-red-600",    tile: "bg-red-50 text-red-700 ring-red-200" },
    high:     { label: "High",     badge: "bg-orange-500 text-white",  border: "border-l-orange-500", tile: "bg-orange-50 text-orange-700 ring-orange-200" },
    medium:   { label: "Medium",   badge: "bg-amber-400 text-amber-950", border: "border-l-amber-400", tile: "bg-amber-50 text-amber-800 ring-amber-200" },
    low:      { label: "Low",      badge: "bg-sky-500 text-white",     border: "border-l-sky-500",    tile: "bg-sky-50 text-sky-700 ring-sky-200" },
    info:     { label: "Info",     badge: "bg-slate-400 text-white",   border: "border-l-slate-400",  tile: "bg-slate-50 text-slate-600 ring-slate-200" },
  };

  const $ = (id) => document.getElementById(id);
  const el = {
    input: $("workflow-input"),
    meta: $("input-meta"),
    scan: $("btn-scan"),
    scanLabel: $("scan-label"),
    spinner: $("scan-spinner"),
    sample: $("btn-sample"),
    format: $("btn-format"),
    clear: $("btn-clear"),
    exportBtn: $("btn-export"),
    error: $("error-box"),
    empty: $("empty-state"),
    results: $("results"),
    title: $("result-title"),
    resultMeta: $("result-meta"),
    summary: $("summary"),
    warnings: $("warnings"),
    findings: $("findings"),
    template: $("finding-template"),
    engine: $("engine-status"),
  };

  let lastResult = null;
  let activeFilter = null; // risk level or null for "all"

  // ----------------------------------------------------------------- helpers
  const byteLength = (s) => new TextEncoder().encode(s).length;

  function formatBytes(n) {
    if (n < 1024) return `${n} bytes`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(2)} MB`;
  }

  function updateMeta() {
    const value = el.input.value;
    const bytes = byteLength(value);
    const lines = value ? value.split("\n").length : 0;
    el.meta.textContent = `${lines} lines · ${formatBytes(bytes)}`;
    el.meta.classList.toggle("text-red-600", bytes > MAX_BYTES);
  }

  function showError(message) {
    el.error.textContent = message;
    el.error.classList.remove("hidden");
  }

  function clearError() {
    el.error.textContent = "";
    el.error.classList.add("hidden");
  }

  function setLoading(loading) {
    el.scan.disabled = loading;
    el.spinner.classList.toggle("hidden", !loading);
    el.scanLabel.textContent = loading ? "Scanning…" : "Scan Workflow";
  }

  /** Parse locally first for instant feedback; returns the object or null. */
  function parseInput() {
    const raw = el.input.value.trim();
    if (!raw) {
      showError("Paste an n8n workflow JSON first.");
      return null;
    }
    if (byteLength(raw) > MAX_BYTES) {
      showError(`Workflow is larger than the ${formatBytes(MAX_BYTES)} limit.`);
      return null;
    }
    try {
      const data = JSON.parse(raw);
      if (!data || typeof data !== "object" || Array.isArray(data) || !Array.isArray(data.nodes)) {
        showError('This does not look like an n8n workflow: expected an object with a "nodes" array.');
        return null;
      }
      return data;
    } catch (err) {
      showError(`Invalid JSON: ${err.message}`);
      return null;
    }
  }

  /** Pretty-print with the same layout the server uses so line numbers match. */
  function formatInput(data) {
    el.input.value = JSON.stringify(data, null, 2) + "\n";
    updateMeta();
  }

  /** Select a line range in the textarea and scroll it into view. */
  function revealLines(start, end) {
    const lines = el.input.value.split("\n");
    let from = 0;
    for (let i = 0; i < start - 1 && i < lines.length; i++) from += lines[i].length + 1;
    let to = from;
    for (let i = start - 1; i < end && i < lines.length; i++) to += lines[i].length + 1;
    el.input.focus();
    el.input.setSelectionRange(from, Math.max(from, to - 1));
    const lineHeight = parseFloat(getComputedStyle(el.input).lineHeight) || 20;
    el.input.scrollTop = Math.max(0, (start - 4) * lineHeight);
    if (window.innerWidth < 1024) el.input.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  // ------------------------------------------------------------------- scan
  async function scan() {
    clearError();
    const data = parseInput();
    if (!data) return;
    formatInput(data);

    setLoading(true);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ workflow: el.input.value }),
        signal: controller.signal,
      });
      let body = null;
      try { body = await response.json(); } catch { /* non-JSON error page */ }
      if (!response.ok) {
        const detail = body && typeof body.detail === "string" ? body.detail : `HTTP ${response.status}`;
        throw new Error(detail);
      }
      lastResult = body;
      activeFilter = null;
      render(body);
    } catch (err) {
      showError(err.name === "AbortError" ? "The scan took too long and was cancelled." : `Scan failed: ${err.message}`);
    } finally {
      clearTimeout(timer);
      setLoading(false);
    }
  }

  // ----------------------------------------------------------------- render
  function render(result) {
    el.empty.classList.add("hidden");
    el.results.classList.remove("hidden");
    el.results.classList.add("flex");

    el.title.textContent = result.workflow_name || "Untitled workflow";
    el.resultMeta.textContent =
      `${result.node_count} nodes · ${result.summary.total} findings · ` +
      `${result.duration_ms} ms · ${result.semgrep_version ? "semgrep " + result.semgrep_version : ""}`;

    renderSummary(result.summary);
    renderWarnings(result.warnings || []);
    renderFindings(result.findings);
  }

  function renderSummary(summary) {
    el.summary.replaceChildren();
    const tiles = [["all", "Total", summary.total, "bg-white text-slate-800 ring-slate-200"]];
    for (const [key, cfg] of Object.entries(RISK)) tiles.push([key, cfg.label, summary[key] || 0, cfg.tile]);

    for (const [key, label, count, cls] of tiles) {
      const btn = document.createElement("button");
      btn.type = "button";
      const selected = (activeFilter ?? "all") === key;
      btn.className = `rounded-lg px-2 py-2 text-center ring-1 ring-inset transition hover:brightness-95 ${cls} ${selected ? "ring-2 ring-indigo-500" : ""}`;
      btn.setAttribute("aria-pressed", String(selected));
      const n = document.createElement("div");
      n.className = "text-xl font-bold leading-none";
      n.textContent = String(count);
      const l = document.createElement("div");
      l.className = "mt-1 text-[11px] font-medium uppercase tracking-wide";
      l.textContent = label;
      btn.append(n, l);
      btn.addEventListener("click", () => {
        activeFilter = key === "all" || activeFilter === key ? null : key;
        renderSummary(summary);
        renderFindings(lastResult.findings);
      });
      el.summary.append(btn);
    }
  }

  function renderWarnings(warnings) {
    el.warnings.replaceChildren();
    el.warnings.classList.toggle("hidden", warnings.length === 0);
    if (!warnings.length) return;
    const head = document.createElement("p");
    head.className = "font-semibold";
    head.textContent = "Scanner warnings (results may be incomplete):";
    const list = document.createElement("ul");
    list.className = "mt-1 list-disc pl-5";
    for (const w of warnings) {
      const li = document.createElement("li");
      li.textContent = w;
      list.append(li);
    }
    el.warnings.append(head, list);
  }

  function renderFindings(findings) {
    el.findings.replaceChildren();
    const visible = activeFilter ? findings.filter((f) => f.risk === activeFilter) : findings;

    if (!visible.length) {
      const li = document.createElement("li");
      li.className = "rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-6 text-center text-sm text-emerald-800";
      li.textContent = findings.length
        ? "No findings at this severity."
        : "No issues found by the current rule set. Still review the workflow manually before deploying.";
      el.findings.append(li);
      return;
    }

    for (const f of visible) {
      const node = el.template.content.firstElementChild.cloneNode(true);
      const field = (name) => node.querySelector(`[data-field="${name}"]`);
      const cfg = RISK[f.risk] || RISK.info;

      node.classList.add(cfg.border);
      field("risk").textContent = cfg.label;
      field("risk").className += ` ${cfg.badge}`;
      field("title").textContent = f.title;
      field("node").textContent = f.node_name
        ? `Node: ${f.node_name}${f.node_type ? ` (${f.node_type.replace(/^n8n-nodes-base\./, "")})` : ""}`
        : "Workflow-level";
      field("lines").textContent = f.start_line === f.end_line ? `Line ${f.start_line}` : `Lines ${f.start_line}–${f.end_line}`;
      field("lines").addEventListener("click", (e) => {
        e.preventDefault();
        revealLines(f.start_line, f.end_line);
      });
      field("rule").textContent = f.rule_id;
      field("message").textContent = f.message;
      field("snippet").textContent = f.snippet;
      field("remediation").textContent = f.remediation;
      field("refs").textContent = [f.cwe, f.owasp].filter(Boolean).join(" · ");
      el.findings.append(node);
    }
  }

  function exportReport() {
    if (!lastResult) return;
    const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `n8n-scan-${lastResult.scan_id.slice(0, 8)}.json`;
    document.body.append(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function loadSample() {
    clearError();
    try {
      const res = await fetch("/static/samples/vulnerable-workflow.json");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      formatInput(await res.json());
    } catch (err) {
      showError(`Could not load sample: ${err.message}`);
    }
  }

  async function loadEngineStatus() {
    try {
      const res = await fetch("/api/health");
      if (!res.ok) return;
      const h = await res.json();
      el.engine.textContent = `Semgrep ${h.semgrep_version} · ${h.rules_loaded} rules`;
      el.engine.classList.remove("hidden");
    } catch { /* status badge is optional */ }
  }

  // ----------------------------------------------------------------- wiring
  el.scan.addEventListener("click", scan);
  el.sample.addEventListener("click", loadSample);
  el.format.addEventListener("click", () => {
    clearError();
    const data = parseInput();
    if (data) formatInput(data);
  });
  el.clear.addEventListener("click", () => {
    el.input.value = "";
    updateMeta();
    clearError();
    el.input.focus();
  });
  el.exportBtn.addEventListener("click", exportReport);
  el.input.addEventListener("input", updateMeta);
  el.input.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      if (!el.scan.disabled) scan();
    }
  });

  updateMeta();
  loadEngineStatus();
})();

/**
 * Security Scanner - front-end logic.
 *
 * Security note: every value coming from the API (which may echo parts of the
 * scanned file) is inserted with textContent, never innerHTML. The
 * downloadable HTML report escapes every value with escapeHtml().
 */
(() => {
  "use strict";

  const MAX_BYTES = 2_000_000;          // keep in sync with MAX_PAYLOAD_BYTES
  const REQUEST_TIMEOUT_MS = 90_000;    // a bit above SCAN_TIMEOUT_SECONDS
  const TOP_PRIORITIES = 5;

  // Full class names are listed literally so Tailwind generates them.
  const RISK = {
    critical: { label: "Critical", badge: "bg-red-600 text-white",       border: "border-l-red-600",    tile: "bg-red-50 text-red-700 ring-red-200",       verdict: "bg-gradient-to-r from-red-700 to-red-600",       hex: "#dc2626" },
    high:     { label: "High",     badge: "bg-orange-500 text-white",    border: "border-l-orange-500", tile: "bg-orange-50 text-orange-700 ring-orange-200", verdict: "bg-gradient-to-r from-orange-600 to-orange-500", hex: "#ea580c" },
    medium:   { label: "Medium",   badge: "bg-amber-400 text-amber-950", border: "border-l-amber-400",  tile: "bg-amber-50 text-amber-800 ring-amber-200",  verdict: "bg-gradient-to-r from-amber-600 to-amber-500",   hex: "#d97706" },
    low:      { label: "Low",      badge: "bg-sky-500 text-white",       border: "border-l-sky-500",    tile: "bg-sky-50 text-sky-700 ring-sky-200",        verdict: "bg-gradient-to-r from-sky-700 to-sky-600",       hex: "#0284c7" },
    info:     { label: "Info",     badge: "bg-slate-400 text-white",     border: "border-l-slate-400",  tile: "bg-slate-50 text-slate-600 ring-slate-200",  verdict: "bg-gradient-to-r from-slate-700 to-slate-600",   hex: "#64748b" },
  };
  const RISK_KEYS = Object.keys(RISK);

  // Report areas, in display order. Keys are rule metadata.category values.
  const AREAS = {
    "secrets":        { label: "Secrets & credentials",        blurb: "Passwords, tokens and keys stored in the file" },
    "ai-agent":       { label: "AI agents",                    blurb: "Prompt injection, data leaks and over-powered agent tools" },
    "integrations":   { label: "Outlook, Teams & monday.com",  blurb: "Mailbox, chat and board data leaving or entering unsafely" },
    "injection":      { label: "Injection",                    blurb: "Untrusted data inside SQL, shell commands or HTML" },
    "code-execution": { label: "Code execution",               blurb: "eval, unsafe deserialisation and remote scripts" },
    "crypto":         { label: "Cryptography",                 blurb: "Weak hashes, ciphers and unverified tokens" },
    "transport":      { label: "Transport security",           blurb: "Unencrypted or unverified connections" },
    "configuration":  { label: "Insecure configuration",       blurb: "Root containers, public resources, debug mode" },
    "access-control": { label: "Access control",               blurb: "Endpoints anyone can call" },
    "data-exposure":  { label: "Data exposure",                blurb: "Sample data saved in the export" },
  };
  const areaOf = (f) => (AREAS[f.category] ? f.category : "other");
  const areaLabel = (key) => (AREAS[key] ? AREAS[key].label : "Other");
  const AREA_KEYS = [...Object.keys(AREAS), "other"];

  // Colours per language group (chip badge on light background / editor badge on dark).
  const GROUP_STYLE = {
    "Automation":              { chip: "bg-rose-100 text-rose-700",   dark: "bg-rose-500/20 text-rose-300" },
    "Application code":        { chip: "bg-indigo-100 text-indigo-700", dark: "bg-indigo-500/20 text-indigo-300" },
    "Infrastructure & config": { chip: "bg-teal-100 text-teal-700",   dark: "bg-teal-500/20 text-teal-300" },
    "Other":                   { chip: "bg-slate-200 text-slate-700", dark: "bg-slate-500/20 text-slate-300" },
  };
  const groupStyle = (lang) => GROUP_STYLE[lang?.group] || GROUP_STYLE.Other;

  const FLOW_VERB = { sends: "Sends data to", reads: "Reads data from", receives: "Receives data from" };

  const $ = (id) => document.getElementById(id);
  const el = {
    input: $("workflow-input"),
    gutter: $("gutter"),
    lineHighlight: $("line-highlight"),
    includeSecrets: $("include-secrets"),
    meta: $("input-meta"),
    scan: $("btn-scan"),
    scanLabel: $("scan-label"),
    spinner: $("scan-spinner"),
    sample: $("btn-sample"),
    format: $("btn-format"),
    clear: $("btn-clear"),
    error: $("error-box"),
    empty: $("empty-state"),
    report: $("report"),
    verdict: $("verdict"),
    verdictLabel: $("verdict-label"),
    verdictText: $("verdict-text"),
    title: $("report-title"),
    reportBadge: $("report-badge"),
    reportMeta: $("report-meta"),
    summary: $("summary"),
    warnings: $("warnings"),
    priorities: $("priorities"),
    areas: $("areas"),
    flowsCard: $("flows-card"),
    flows: $("flows"),
    filterNote: $("filter-note"),
    groupBy: $("group-by"),
    groupByNode: $("group-by-node"),
    findings: $("findings"),
    template: $("finding-template"),
    engine: $("engine-status"),
    statLanguages: $("stat-languages"),
    statRules: $("stat-rules"),
    picker: $("language-picker"),
    detectNote: $("detect-note"),
    editorBadge: $("editor-badge"),
    btnPdf: $("btn-pdf"),
    btnPdfLabel: $("btn-pdf-label"),
    btnHtml: $("btn-html"),
    btnMd: $("btn-md"),
    btnJson: $("btn-json"),
    fileInput: $("file-input"),
    upload: $("btn-upload"),
    dropZone: $("drop-zone"),
    dropOverlay: $("drop-overlay"),
    fileName: $("file-name"),
  };

  const PROFILE_LABEL = { full: "All checks", credentials: "Credentials only" };
  const selectedProfile = () => document.querySelector('input[name="profile"]:checked')?.value || "full";

  /** @type {Array<{id:string,label:string,group:string,short:string,extensions:string[],filenames:string[],sample:string|null,rules:number}>} */
  let languages = [];
  let language = null;      // selected language object
  let fileName = null;      // name of the uploaded / sample file, if any
  let lastResult = null;
  let lastRequest = null;   // request that produced lastResult (re-used for the PDF)
  let scannedAt = null;
  let filter = { risk: null, area: null };
  let highlighted = null;   // { start, end } lines shown by "Show line N"
  let gutterLines = 0;

  // ----------------------------------------------------------------- helpers
  const byteLength = (s) => new TextEncoder().encode(s).length;

  function formatBytes(n) {
    if (n < 1024) return `${n} bytes`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(2)} MB`;
  }

  function h(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
  const shortType = (t) => (t || "").replace(/^n8n-nodes-base\./, "").replace(/^@n8n\/n8n-nodes-langchain\./, "AI · ");
  const findingDomId = (index) => `finding-${index}`;
  const isWorkflow = () => language?.id === "n8n";
  const linesLabel = (f) => (f.start_line === f.end_line ? `Line ${f.start_line}` : `Lines ${f.start_line}–${f.end_line}`);
  const reportIsWorkflow = () => lastResult?.language === "n8n";

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
    el.scanLabel.textContent = loading ? "Scanning…" : isWorkflow() ? "Scan workflow" : "Scan file";
  }

  // ------------------------------------------------------------- languages
  async function loadLanguages() {
    try {
      const res = await fetch("/api/languages");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      languages = await res.json();
    } catch (err) {
      showError(`Could not load the list of languages: ${err.message}`);
      languages = [{ id: "n8n", label: "n8n workflow", group: "Automation", short: "n8n", extensions: [".json"], filenames: [], sample: null, rules: 0 }];
    }
    el.statLanguages.textContent = String(languages.length);
    renderPicker();
    selectLanguage("n8n", { quiet: true });
  }

  function renderPicker() {
    el.picker.replaceChildren();
    const groups = [...new Set(languages.map((l) => l.group))];
    for (const group of groups) {
      el.picker.append(h("p", "pt-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400 lg:w-44", group));
      const row = h("div", "flex flex-wrap gap-2");
      for (const lang of languages.filter((l) => l.group === group)) {
        const btn = h("button", "group flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-left text-xs font-medium text-slate-700 transition hover:border-indigo-300 hover:bg-indigo-50/50");
        btn.type = "button";
        btn.dataset.lang = lang.id;
        btn.setAttribute("role", "radio");
        btn.title = `${lang.label} · ${plural(lang.rules, "rule")}${lang.extensions.length ? ` · ${lang.extensions.slice(0, 4).join(" ")}` : ""}`;
        btn.append(h("span", `min-w-[2rem] rounded px-1 py-0.5 text-center font-mono text-[10px] font-bold ${groupStyle(lang).chip}`, lang.short),
          h("span", "", lang.label.replace(/ \(.*\)$/, "")));
        btn.addEventListener("click", () => selectLanguage(lang.id));
        row.append(btn);
      }
      el.picker.append(row);
    }
  }

  function selectLanguage(id, { quiet = false, detectedFrom = null } = {}) {
    const lang = languages.find((l) => l.id === id) || languages[0];
    language = lang;
    for (const btn of el.picker.querySelectorAll("button[data-lang]")) {
      const on = btn.dataset.lang === lang.id;
      btn.setAttribute("aria-checked", String(on));
      btn.classList.toggle("ring-2", on);
      btn.classList.toggle("ring-indigo-500", on);
      btn.classList.toggle("border-indigo-500", on);
      btn.classList.toggle("bg-indigo-50", on);
    }
    el.editorBadge.textContent = lang.short;
    el.editorBadge.className = `ml-2 rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${groupStyle(lang).dark}`;
    el.format.classList.toggle("hidden", lang.id !== "n8n");
    el.sample.disabled = !lang.sample;
    el.sample.classList.toggle("opacity-50", !lang.sample);
    el.input.placeholder = placeholderFor(lang);
    el.scanLabel.textContent = lang.id === "n8n" ? "Scan workflow" : "Scan file";
    if (detectedFrom) {
      el.detectNote.textContent = `Detected ${lang.label.replace(/ \(.*\)$/, "")} from ${detectedFrom}`;
      el.detectNote.classList.remove("hidden");
    } else if (!quiet) {
      el.detectNote.classList.add("hidden");
    }
  }

  function placeholderFor(lang) {
    if (lang.id === "n8n") {
      return 'Paste an n8n workflow export, click "Upload file", or drag a file here…\n\n{\n  "name": "My workflow",\n  "nodes": [ … ],\n  "connections": { … }\n}';
    }
    const ext = lang.filenames[0] || lang.extensions.slice(0, 3).join(", ");
    return `Paste ${lang.label} here, click "Upload file", or drag a file onto this box…\n\nAccepted: ${ext}`;
  }

  /** Pick a language for an uploaded file: exact names, then extension, then sniffing. */
  function detectLanguage(name, text) {
    const base = name.split(/[\\/]/).pop();
    const lower = base.toLowerCase();
    const byName = languages.find((l) => l.filenames.some((f) => f.toLowerCase() === lower));
    if (byName) return byName.id;
    if (/^(docker|container)file(\..+)?$/i.test(base)) return "dockerfile";
    const ext = lower.includes(".") ? lower.slice(lower.lastIndexOf(".")) : "";
    if (ext === ".json") {
      try {
        const data = JSON.parse(text);
        if (data && typeof data === "object" && !Array.isArray(data) && Array.isArray(data.nodes)) return "n8n";
      } catch { /* not JSON: fall through */ }
      return "generic";
    }
    const byExt = languages.find((l) => l.id !== "n8n" && l.id !== "generic" && l.extensions.includes(ext));
    if (byExt) return byExt.id;
    if (/^#!.*\b(ba|z)?sh\b/.test(text)) return "bash";
    if (/^#!.*\bpython/.test(text)) return "python";
    if (/^#!.*\bnode\b/.test(text)) return "javascript";
    return "generic";
  }

  // ---------------------------------------------------------- editor bits
  function updateMeta() {
    const value = el.input.value;
    const bytes = byteLength(value);
    const lines = value ? value.split("\n").length : 0;
    el.meta.textContent = `${lines} lines · ${formatBytes(bytes)}`;
    el.meta.classList.toggle("text-red-400", bytes > MAX_BYTES);
    renderGutter(Math.max(lines, 1));
  }

  function setFileName(name) {
    fileName = name;
    el.fileName.textContent = name || "untitled";
  }

  function renderGutter(lines) {
    if (lines !== gutterLines) {
      gutterLines = lines;
      // Extra blank rows let the gutter scroll as far as the textarea when a
      // horizontal scrollbar is showing.
      el.gutter.textContent = Array.from({ length: lines }, (_, i) => i + 1).join("\n") + "\n\n\n";
    }
    syncEditorScroll();
  }

  const editorLineHeight = () => parseFloat(getComputedStyle(el.input).lineHeight) || 20;
  const editorPaddingTop = () => parseFloat(getComputedStyle(el.input).paddingTop) || 16;

  function syncEditorScroll() {
    el.gutter.scrollTop = el.input.scrollTop;
    positionHighlight();
  }

  function positionHighlight() {
    if (!highlighted) {
      el.lineHighlight.classList.add("hidden");
      return;
    }
    const lh = editorLineHeight();
    el.lineHighlight.style.top = `${editorPaddingTop() + (highlighted.start - 1) * lh - el.input.scrollTop}px`;
    el.lineHighlight.style.height = `${(highlighted.end - highlighted.start + 1) * lh}px`;
    el.lineHighlight.classList.remove("hidden");
  }

  function clearHighlight() {
    highlighted = null;
    positionHighlight();
  }

  /** Scroll the editor to a line range, highlight it and put the cursor there. */
  function revealLines(start, end) {
    const lines = el.input.value.split("\n");
    start = Math.min(Math.max(1, start), lines.length);
    end = Math.min(Math.max(start, end), lines.length);
    let from = 0;
    for (let i = 0; i < start - 1; i++) from += lines[i].length + 1;

    el.input.scrollIntoView({ behavior: "smooth", block: "center" });
    el.input.focus({ preventScroll: true });
    el.input.setSelectionRange(from, from);
    const lh = editorLineHeight();
    const rangeHeight = (end - start + 1) * lh;
    el.input.scrollTop = Math.max(0, (start - 1) * lh + editorPaddingTop() - (el.input.clientHeight - rangeHeight) / 2);
    el.input.scrollLeft = 0;

    highlighted = { start, end };
    syncEditorScroll();
  }

  function setEditorText(text) {
    clearHighlight();
    el.input.value = text;
    el.input.scrollTop = 0;
    updateMeta();
  }

  /** n8n only: parse locally first for instant feedback; returns the object or null. */
  function parseWorkflow(raw) {
    try {
      const data = JSON.parse(raw);
      if (!data || typeof data !== "object" || Array.isArray(data) || !Array.isArray(data.nodes)) {
        showError('This does not look like an n8n workflow (expected an object with a "nodes" array). If it is source code or a config file, pick its language in step 1.');
        return null;
      }
      return data;
    } catch (err) {
      showError(`Invalid JSON: ${err.message}. If this is not an n8n workflow, pick its language in step 1.`);
      return null;
    }
  }

  // ------------------------------------------------------------- derivations
  function verdictFor(summary) {
    const c = summary.critical || 0, hi = summary.high || 0, m = summary.medium || 0;
    if (c) return { key: "critical", label: "Critical risk", text: `Do not deploy yet: fix ${plural(c, "critical issue")}${hi ? ` and ${plural(hi, "high issue")}` : ""} first.` };
    if (hi) return { key: "high", label: "High risk", text: `Fix ${plural(hi, "high-severity issue")} before deploying.` };
    if (m) return { key: "medium", label: "Moderate risk", text: `No critical or high issues. Review ${plural(m, "medium issue")}.` };
    if (summary.total) return { key: "low", label: "Low risk", text: "Only minor findings. Review them when convenient." };
    return { key: "none", label: "No issues found", text: "The rule set found nothing. Still review it manually before deploying." };
  }

  const VERDICT_BG = { critical: RISK.critical.verdict, high: RISK.high.verdict, medium: RISK.medium.verdict, low: RISK.low.verdict, none: "bg-gradient-to-r from-emerald-700 to-emerald-600" };
  const VERDICT_HEX = { critical: "#b91c1c", high: "#c2410c", medium: "#b45309", low: "#0369a1", none: "#047857" };

  /** Where a finding is: node (n8n) or line + area (code). */
  function locationLabel(f) {
    if (reportIsWorkflow()) {
      if (!f.node_name) return "Workflow-level";
      return `${f.node_name}${f.node_type ? ` (${shortType(f.node_type)})` : ""}`;
    }
    return `${linesLabel(f)} · ${areaLabel(areaOf(f))}`;
  }

  function groupFindings(findings, mode) {
    const groups = new Map();
    const keyOf = mode === "risk" ? (f) => f.risk : mode === "node" ? (f) => f.node_name || "Workflow-level" : areaOf;
    for (const f of findings) {
      const k = keyOf(f);
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(f);
    }
    const order = mode === "risk" ? RISK_KEYS : mode === "area" ? AREA_KEYS : null;
    const entries = [...groups.entries()];
    if (order) entries.sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0]));
    else entries.sort((a, b) => worstIndex(a[1]) - worstIndex(b[1]) || a[0].localeCompare(b[0]));
    const label = mode === "risk" ? (k) => RISK[k]?.label || k : mode === "area" ? areaLabel : (k) => k;
    return entries.map(([k, items]) => ({ key: k, label: label(k), items }));
  }

  const worstIndex = (items) => Math.min(...items.map((f) => RISK_KEYS.indexOf(f.risk)));

  // ------------------------------------------------------------------- scan
  async function scan() {
    clearError();
    const raw = el.input.value;
    if (!raw.trim()) {
      showError("Paste, upload or drop a file first.");
      return;
    }
    if (byteLength(raw) > MAX_BYTES) {
      showError(`The file is larger than the ${formatBytes(MAX_BYTES)} limit.`);
      return;
    }
    let content = raw;
    if (isWorkflow()) {
      const data = parseWorkflow(raw);
      if (!data) return;
      // Same layout as the server so line numbers match.
      content = JSON.stringify(data, null, 2) + "\n";
      if (content !== raw) setEditorText(content);
    }

    setLoading(true);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const request = { content, language: language.id, filename: fileName, profile: selectedProfile() };
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
        signal: controller.signal,
      });
      let body = null;
      try { body = await response.json(); } catch { /* non-JSON error page */ }
      if (!response.ok) {
        const detail = body && typeof body.detail === "string" ? body.detail : `HTTP ${response.status}`;
        throw new Error(detail);
      }
      lastResult = body;
      lastRequest = request;
      scannedAt = new Date();
      filter = { risk: null, area: null };
      render();
      el.report.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      showError(err.name === "AbortError" ? "The scan took too long and was cancelled." : `Scan failed: ${err.message}`);
    } finally {
      clearTimeout(timer);
      setLoading(false);
    }
  }

  // ----------------------------------------------------------------- render
  function render() {
    const r = lastResult;
    el.empty.classList.add("hidden");
    el.report.classList.remove("hidden");
    el.report.classList.add("flex");

    const v = verdictFor(r.summary);
    el.verdict.className = `flex flex-wrap items-center justify-between gap-4 px-5 py-5 text-white ${VERDICT_BG[v.key]}`;
    el.verdictLabel.textContent = v.label;
    el.verdictText.textContent = v.text;

    const lang = languages.find((l) => l.id === r.language);
    el.reportBadge.textContent = lang?.short || r.language;
    el.reportBadge.className = `rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${groupStyle(lang).chip}`;
    el.title.textContent = r.target_name || r.workflow_name || (r.language === "n8n" ? "Untitled workflow" : `${r.language_label} file`);
    el.reportMeta.textContent = [
      r.language_label,
      r.node_count != null ? plural(r.node_count, "node") : plural(r.line_count, "line"),
      PROFILE_LABEL[r.profile] || "All checks",
      `scanned ${scannedAt.toLocaleString()}`,
      `${r.duration_ms} ms`,
    ].join(" · ");

    el.groupByNode.hidden = !reportIsWorkflow();
    if (!reportIsWorkflow() && el.groupBy.value === "node") el.groupBy.value = "area";

    renderSummary();
    renderWarnings(r.warnings || []);
    renderPriorities();
    renderAreas();
    renderFlows();
    renderFindings();
  }

  function renderSummary() {
    const summary = lastResult.summary;
    el.summary.replaceChildren();
    const tiles = [["all", "Total", summary.total, "bg-white text-slate-800 ring-slate-200"]];
    for (const key of RISK_KEYS) tiles.push([key, RISK[key].label, summary[key] || 0, RISK[key].tile]);

    for (const [key, label, count, cls] of tiles) {
      const selected = (filter.risk ?? "all") === key;
      const btn = h("button", `rounded-xl px-2 py-2.5 text-center ring-1 ring-inset transition hover:brightness-95 ${cls} ${selected ? "ring-2 ring-indigo-500" : ""}`);
      btn.type = "button";
      btn.setAttribute("aria-pressed", String(selected));
      btn.append(h("div", "text-2xl font-bold leading-none", String(count)), h("div", "mt-1 text-[11px] font-medium uppercase tracking-wide", label));
      btn.addEventListener("click", () => {
        filter.risk = key === "all" || filter.risk === key ? null : key;
        renderSummary();
        renderFindings();
      });
      el.summary.append(btn);
    }
  }

  function renderWarnings(warnings) {
    el.warnings.replaceChildren();
    el.warnings.classList.toggle("hidden", warnings.length === 0);
    if (!warnings.length) return;
    const list = h("ul", "mt-1 list-disc pl-5");
    for (const w of warnings) list.append(h("li", "", w));
    el.warnings.append(h("p", "font-semibold", "Scanner warnings (results may be incomplete):"), list);
  }

  function renderPriorities() {
    el.priorities.replaceChildren();
    const top = lastResult.findings
      .map((f, i) => [f, i])
      .filter(([f]) => f.risk === "critical" || f.risk === "high")
      .slice(0, TOP_PRIORITIES);
    if (!top.length) {
      el.priorities.append(h("li", "rounded-md bg-emerald-50 px-3 py-2 text-sm text-emerald-800", "Nothing critical or high."));
      return;
    }
    for (const [f, index] of top) {
      const li = h("li");
      const btn = h("button", "flex w-full items-start gap-2 rounded-lg px-2 py-1.5 text-left hover:bg-slate-50");
      btn.type = "button";
      const text = h("span", "min-w-0");
      text.append(h("span", "block text-sm font-medium", f.title), h("span", "block text-xs text-slate-500", locationLabel(f)));
      btn.append(h("span", `mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${RISK[f.risk].badge}`, RISK[f.risk].label), text);
      btn.addEventListener("click", () => jumpToFinding(index));
      li.append(btn);
      el.priorities.append(li);
    }
    const rest = lastResult.findings.filter((f) => f.risk === "critical" || f.risk === "high").length - top.length;
    if (rest > 0) el.priorities.append(h("li", "px-2 text-xs text-slate-500", `+ ${rest} more critical/high below`));
  }

  function renderAreas() {
    el.areas.replaceChildren();
    const groups = groupFindings(lastResult.findings, "area");
    if (!groups.length) {
      el.areas.append(h("p", "text-sm text-slate-500", "No findings in any area."));
      return;
    }
    for (const g of groups) {
      const worst = RISK_KEYS[worstIndex(g.items)];
      const selected = filter.area === g.key;
      const btn = h("button", `flex items-start justify-between gap-2 rounded-xl border px-3 py-2 text-left hover:bg-slate-50 ${selected ? "border-indigo-500 ring-1 ring-indigo-500" : "border-slate-200"}`);
      btn.type = "button";
      btn.setAttribute("aria-pressed", String(selected));
      const text = h("span", "min-w-0");
      text.append(h("span", "block text-sm font-medium", g.label), h("span", "block text-xs text-slate-500", AREAS[g.key]?.blurb || ""));
      const count = h("span", `shrink-0 rounded-full px-2 py-0.5 text-xs font-bold ${RISK[worst].badge}`, String(g.items.length));
      count.title = `Worst: ${RISK[worst].label}`;
      btn.append(text, count);
      btn.addEventListener("click", () => {
        filter.area = selected ? null : g.key;
        renderAreas();
        renderFindings();
      });
      el.areas.append(btn);
    }
  }

  function renderFlows() {
    const flows = lastResult.data_flows || [];
    // Only n8n workflows have a data-flow inventory.
    el.flowsCard.classList.toggle("hidden", !reportIsWorkflow() || lastResult.profile === "credentials");
    el.flows.replaceChildren();
    if (!flows.length) {
      const tr = h("tr");
      const td = h("td", "py-3 text-sm text-slate-500", "No external services detected.");
      td.colSpan = 5;
      tr.append(td);
      el.flows.append(tr);
      return;
    }
    for (const f of flows) {
      const tr = h("tr", "align-top");
      const service = h("td", "py-2 pr-3 font-medium");
      service.append(document.createTextNode(f.service));
      if (!f.external) service.append(h("span", "ml-1 rounded bg-emerald-50 px-1 text-[10px] font-semibold text-emerald-700", "internal"));
      const dirClass = f.direction === "sends" ? "text-orange-700" : "text-slate-600";
      tr.append(
        service,
        h("td", `py-2 pr-3 text-xs ${dirClass}`, FLOW_VERB[f.direction] || f.direction),
        h("td", "py-2 pr-3", f.node_name),
        h("td", "py-2 pr-3 text-xs text-slate-500", f.via),
        h("td", "py-2 font-mono text-xs text-slate-500", f.detail),
      );
      el.flows.append(tr);
    }
  }

  function visibleFindings() {
    return lastResult.findings
      .map((f, i) => [f, i])
      .filter(([f]) => (!filter.risk || f.risk === filter.risk) && (!filter.area || areaOf(f) === filter.area));
  }

  function renderFindings() {
    el.findings.replaceChildren();
    const all = lastResult.findings;
    const visible = visibleFindings();

    const parts = [];
    if (filter.risk) parts.push(RISK[filter.risk].label);
    if (filter.area) parts.push(areaLabel(filter.area));
    el.filterNote.textContent = parts.length
      ? `Showing ${visible.length} of ${all.length} · filtered by ${parts.join(" + ")} (click again to clear)`
      : `${plural(all.length, "finding")}`;

    if (!visible.length) {
      el.findings.append(h("div", "rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-6 text-center text-sm text-emerald-800",
        all.length
          ? "No findings match this filter."
          : lastResult.profile === "credentials"
            ? "No hardcoded passwords, tokens or keys found."
            : "No issues found by the current rule set. Still review it manually before deploying."));
      return;
    }

    const indexOf = new Map(visible.map(([f, i]) => [f, i]));
    for (const group of groupFindings(visible.map(([f]) => f), el.groupBy.value)) {
      const section = h("section", "flex flex-col gap-3");
      const head = h("h4", "flex items-baseline gap-2 border-b border-slate-200 pb-1 text-sm font-semibold text-slate-700", group.label);
      head.append(h("span", "text-xs font-normal text-slate-400", plural(group.items.length, "finding")));
      section.append(head);
      for (const f of group.items) section.append(findingCard(f, indexOf.get(f)));
      el.findings.append(section);
    }
  }

  function findingCard(f, index) {
    const card = el.template.content.firstElementChild.cloneNode(true);
    const field = (name) => card.querySelector(`[data-field="${name}"]`);
    const cfg = RISK[f.risk] || RISK.info;

    card.id = findingDomId(index);
    card.classList.add(cfg.border);
    field("risk").textContent = cfg.label;
    field("risk").className += ` ${cfg.badge}`;
    field("title").textContent = f.title;
    field("brief").textContent = f.brief;
    field("node").textContent = reportIsWorkflow()
      ? `${locationLabel(f)} · ${areaLabel(areaOf(f))}`
      : `${lastResult.target_name || lastResult.language_label} · ${areaLabel(areaOf(f))}`;
    field("message").textContent = f.message;
    field("remediation").textContent = f.remediation;
    field("snippet").textContent = f.snippet;
    if (f.exposed_value) {
      field("exposed").textContent = f.exposed_value;
      field("exposed-wrap").classList.remove("hidden");
    }
    field("jump").textContent = `${linesLabel(f)} ↗`;
    field("jump").title = "Show in editor";
    field("jump").addEventListener("click", () => revealLines(f.start_line, f.end_line));
    field("source").textContent = f.source === "workflow-graph" ? "Found by: workflow connection analysis" : "Found by: Semgrep rule";
    field("rule").textContent = f.rule_id;
    field("refs").textContent = [f.cwe, f.owasp].filter(Boolean).join(" · ");
    return card;
  }

  function jumpToFinding(index) {
    if (!document.getElementById(findingDomId(index))) {
      filter = { risk: null, area: null };
      renderSummary();
      renderAreas();
      renderFindings();
    }
    const card = document.getElementById(findingDomId(index));
    if (!card) return;
    card.scrollIntoView({ behavior: "smooth", block: "start" });
    card.classList.add("ring-2", "ring-indigo-500");
    setTimeout(() => card.classList.remove("ring-2", "ring-indigo-500"), 1600);
  }

  // ----------------------------------------------------------------- export
  function download(content, type, filename) {
    const url = URL.createObjectURL(content instanceof Blob ? content : new Blob([content], { type }));
    const a = h("a");
    a.href = url;
    a.download = filename;
    document.body.append(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function reportFilename(ext) {
    const name = lastResult.target_name || lastResult.workflow_name || lastResult.language;
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 50) || "scan";
    return `security-report-${slug}-${scannedAt.toISOString().slice(0, 10)}.${ext}`;
  }

  const reportName = (r) => r.target_name || r.workflow_name || (r.language === "n8n" ? "Untitled workflow" : `${r.language_label} file`);
  const reportScope = (r) => `${r.language_label} · ${r.node_count != null ? plural(r.node_count, "node") : plural(r.line_count, "line")}`;

  /** The result as exported: exposed secret values only when the user opts in. */
  function exportResult() {
    if (el.includeSecrets.checked) return lastResult;
    return { ...lastResult, findings: lastResult.findings.map(({ exposed_value, ...f }) => f) };
  }

  /** The server re-scans the same content and renders the findings as a PDF. */
  async function downloadPdf() {
    if (!lastRequest) return;
    el.btnPdf.disabled = true;
    el.btnPdfLabel.textContent = "Preparing PDF…";
    clearError();
    try {
      const response = await fetch("/api/report.pdf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...lastRequest, include_secrets: el.includeSecrets.checked }),
      });
      if (!response.ok) {
        let detail = `HTTP ${response.status}`;
        try { detail = (await response.json()).detail || detail; } catch { /* not JSON */ }
        throw new Error(detail);
      }
      download(await response.blob(), "application/pdf", reportFilename("pdf"));
    } catch (err) {
      showError(`Could not create the PDF: ${err.message}`);
    } finally {
      el.btnPdf.disabled = false;
      el.btnPdfLabel.textContent = "Download PDF";
    }
  }

  const escapeHtml = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function buildHtmlReport() {
    const r = exportResult();
    const v = verdictFor(r.summary);
    const findings = r.findings;
    const top = findings.filter((f) => f.risk === "critical" || f.risk === "high").slice(0, TOP_PRIORITIES);
    const pill = (risk) => `<span class="pill" style="background:${RISK[risk].hex}">${escapeHtml(RISK[risk].label)}</span>`;

    const summaryCells = RISK_KEYS.map((k) =>
      `<div class="tile"><b style="color:${RISK[k].hex}">${r.summary[k] || 0}</b><span>${RISK[k].label}</span></div>`).join("");

    const areaRows = groupFindings(findings, "area").map((g) => {
      const counts = RISK_KEYS.map((k) => g.items.filter((f) => f.risk === k).length);
      return `<tr><td>${escapeHtml(g.label)}</td>${counts.map((c) => `<td class="num">${c || "–"}</td>`).join("")}</tr>`;
    }).join("");

    const flows = (r.data_flows || []).map((f) =>
      `<tr><td><b>${escapeHtml(f.service)}</b>${f.external ? "" : " <small>(internal)</small>"}</td><td>${escapeHtml(FLOW_VERB[f.direction] || f.direction)}</td><td>${escapeHtml(f.node_name)}</td><td>${escapeHtml(f.via)}</td><td><code>${escapeHtml(f.detail)}</code></td></tr>`).join("");

    let n = 0;
    const findingSections = groupFindings(findings, "area").map((g) => `
      <h3>${escapeHtml(g.label)} <small>(${g.items.length})</small></h3>
      ${g.items.map((f) => `
        <div class="finding" style="border-left-color:${RISK[f.risk].hex}">
          <div class="fhead">${pill(f.risk)} <b>${++n}. ${escapeHtml(f.title)}</b></div>
          <div class="brief">${escapeHtml(f.brief)}</div>
          <div class="node">${escapeHtml(locationLabel(f))}</div>
          ${f.exposed_value ? `<div class="exposed"><b>Exposed value.</b> <code>${escapeHtml(f.exposed_value)}</code></div>` : ""}
          <p><b>What's wrong.</b> ${escapeHtml(f.message)}</p>
          <div class="fix"><b>How to fix.</b> ${escapeHtml(f.remediation)}</div>
          <details><summary>Technical details</summary>
            <pre>${escapeHtml(f.snippet)}</pre>
            <p class="meta">Lines ${f.start_line}–${f.end_line} · ${escapeHtml(f.rule_id)} · ${escapeHtml([f.cwe, f.owasp].filter(Boolean).join(" · "))} · ${f.source === "workflow-graph" ? "workflow connection analysis" : "Semgrep rule"}</p>
          </details>
        </div>`).join("")}`).join("");

    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security report: ${escapeHtml(reportName(r))}</title>
<style>
  :root { color-scheme: light; }
  body { font: 14px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #0f172a; background: #f1f5f9; margin: 0; }
  main { max-width: 900px; margin: 0 auto; padding: 24px 16px 48px; }
  .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; margin-bottom: 16px; }
  .verdict { color: #fff; border-radius: 12px; padding: 20px; margin-bottom: 16px; background: ${VERDICT_HEX[v.key]}; }
  .verdict small { text-transform: uppercase; letter-spacing: .08em; opacity: .8; font-weight: 600; font-size: 11px; }
  .verdict h1 { margin: 2px 0 4px; font-size: 26px; }
  h2 { font-size: 16px; margin: 0 0 10px; } h3 { font-size: 15px; margin: 24px 0 10px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }
  h3 small, .node, .meta { color: #64748b; font-weight: normal; font-size: 12px; }
  .tiles { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; }
  .tile { border: 1px solid #e2e8f0; border-radius: 8px; text-align: center; padding: 8px; } .tile b { display: block; font-size: 22px; } .tile span { font-size: 11px; text-transform: uppercase; color: #475569; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; } th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
  th { font-size: 11px; text-transform: uppercase; color: #64748b; border-bottom: 1px solid #e2e8f0; } td.num { text-align: center; }
  .pill { color: #fff; font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 2px 6px; border-radius: 4px; vertical-align: 1px; }
  ol li { margin-bottom: 6px; }
  .finding { background: #fff; border: 1px solid #e2e8f0; border-left: 4px solid; border-radius: 10px; padding: 14px 16px; margin-bottom: 12px; page-break-inside: avoid; }
  .exposed { background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 8px 10px; color: #7f1d1d; margin-top: 8px; word-break: break-all; }
  .brief { margin-top: 4px; font-weight: 500; }
  .finding p { margin: 8px 0; } .fix { background: #ecfdf5; border: 1px solid #a7f3d0; border-radius: 8px; padding: 8px 10px; color: #064e3b; }
  pre { background: #0f172a; color: #e2e8f0; padding: 10px; border-radius: 8px; overflow-x: auto; font-size: 12px; white-space: pre-wrap; word-break: break-all; }
  code { font-size: 12px; } summary { cursor: pointer; color: #475569; font-size: 12px; margin-top: 8px; }
  footer { color: #64748b; font-size: 12px; margin-top: 24px; }
  @media print { body { background: #fff; } .card, .finding { border-color: #cbd5e1; } details { display: block; } details > summary { display: none; } details pre { display: block; } }
  @media (max-width: 600px) { .tiles { grid-template-columns: repeat(3, 1fr); } }
</style></head>
<body><main>
  <div class="verdict"><small>Overall risk</small><h1>${escapeHtml(v.label)}</h1><div>${escapeHtml(v.text)}</div></div>
  <div class="card">
    <h2>${escapeHtml(reportName(r))}</h2>
    <div class="meta">${escapeHtml(reportScope(r))} · ${escapeHtml(PROFILE_LABEL[r.profile] || "All checks")} · scanned ${escapeHtml(scannedAt.toLocaleString())} · Semgrep ${escapeHtml(r.semgrep_version)} · scan ${escapeHtml(r.scan_id.slice(0, 8))}</div>
    <div class="tiles" style="margin-top:14px">${summaryCells}</div>
  </div>
  <div class="card"><h2>Fix these first</h2>${top.length
    ? `<ol>${top.map((f) => `<li>${pill(f.risk)} <b>${escapeHtml(f.title)}</b> <span class="node">· ${escapeHtml(locationLabel(f))}</span></li>`).join("")}</ol>`
    : "<p>Nothing critical or high.</p>"}</div>
  ${areaRows ? `<div class="card"><h2>Risk by area</h2><table><thead><tr><th>Area</th>${RISK_KEYS.map((k) => `<th class="num">${RISK[k].label}</th>`).join("")}</tr></thead><tbody>${areaRows}</tbody></table></div>` : ""}
  ${r.language !== "n8n" || r.profile === "credentials" ? "" : `<div class="card"><h2>Where your data goes</h2>${flows
    ? `<table><thead><tr><th>Service</th><th>Data</th><th>Node</th><th>Used as</th><th>Detail</th></tr></thead><tbody>${flows}</tbody></table>`
    : "<p>No external services detected.</p>"}</div>`}
  <div class="card"><h2>All findings (${findings.length})</h2>${findingSections || "<p>No issues found by the current rule set.</p>"}</div>
  <footer>Generated by Security Scanner. ${el.includeSecrets.checked
    ? "<b>This report contains exposed secret values. Share it only with people allowed to see them, and rotate the secrets.</b>"
    : "Secret values are masked."} ${r.language === "n8n" ? "Line numbers refer to the workflow formatted with 2-space indentation." : "Line numbers refer to the scanned file."}</footer>
</main></body></html>`;
  }

  function buildMarkdownReport() {
    const r = exportResult();
    const v = verdictFor(r.summary);
    const cell = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ");
    const lines = [
      `# Security report: ${reportName(r)}`,
      "",
      `**Overall risk: ${v.label}.** ${v.text}`,
      "",
      `${reportScope(r)} · ${PROFILE_LABEL[r.profile] || "All checks"} · scanned ${scannedAt.toLocaleString()} · Semgrep ${r.semgrep_version}`,
      "",
      `| ${RISK_KEYS.map((k) => RISK[k].label).join(" | ")} |`,
      `|${RISK_KEYS.map(() => ":---:").join("|")}|`,
      `| ${RISK_KEYS.map((k) => r.summary[k] || 0).join(" | ")} |`,
      "",
      "## Fix these first",
      "",
    ];
    const top = r.findings.filter((f) => f.risk === "critical" || f.risk === "high").slice(0, TOP_PRIORITIES);
    if (top.length) top.forEach((f, i) => lines.push(`${i + 1}. **[${RISK[f.risk].label}] ${f.title}** · ${locationLabel(f)}`));
    else lines.push("Nothing critical or high.");

    if (r.language === "n8n" && r.profile !== "credentials") {
      lines.push("", "## Where your data goes", "");
      if ((r.data_flows || []).length) {
        lines.push("| Service | Data | Node | Used as | Detail |", "|---|---|---|---|---|");
        for (const f of r.data_flows) lines.push(`| ${cell(f.service)}${f.external ? "" : " (internal)"} | ${cell(FLOW_VERB[f.direction])} | ${cell(f.node_name)} | ${cell(f.via)} | ${cell(f.detail)} |`);
      } else lines.push("No external services detected.");
    }

    lines.push("", `## All findings (${r.findings.length})`);
    let n = 0;
    for (const g of groupFindings(r.findings, "area")) {
      lines.push("", `### ${g.label} (${g.items.length})`);
      for (const f of g.items) {
        lines.push(
          "",
          `#### ${++n}. [${RISK[f.risk].label}] ${f.title}`,
          "",
          `_${f.brief}_`,
          "",
          `- **Where:** ${locationLabel(f)}${r.language === "n8n" ? `, lines ${f.start_line}–${f.end_line}` : ""}`,
          ...(f.exposed_value ? [`- **Exposed value:** \`${f.exposed_value.replace(/`/g, "'").replace(/\s*\n\s*/g, " ")}\``] : []),
          `- **What's wrong:** ${f.message}`,
          `- **How to fix:** ${f.remediation}`,
          `- **Reference:** \`${f.rule_id}\`${f.cwe ? ` · ${f.cwe}` : ""}${f.owasp ? ` · ${f.owasp}` : ""}`,
          "",
          "~~~text",
          f.snippet.replace(/~~~/g, "~ ~ ~"),
          "~~~",
        );
      }
    }
    lines.push("", el.includeSecrets.checked
      ? "_**This report contains exposed secret values.** Share it only with people allowed to see them, and rotate the secrets._"
      : "_Secret values are masked._", "");
    return lines.join("\n");
  }

  // ------------------------------------------------------------------ input
  async function loadSample() {
    clearError();
    if (!language?.sample) return;
    try {
      const res = await fetch(`/static/samples/${language.sample}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      let text = await res.text();
      if (language.id === "n8n") text = JSON.stringify(JSON.parse(text), null, 2) + "\n";
      setEditorText(text);
      setFileName(language.sample.split("/").pop());
      el.detectNote.classList.add("hidden");
    } catch (err) {
      showError(`Could not load sample: ${err.message}`);
    }
  }

  /** Read a local file into the editor (in the browser), pick its language, then scan. */
  async function loadFile(file) {
    clearError();
    if (!file) return;
    if (file.size > MAX_BYTES) {
      showError(`"${file.name}" is ${formatBytes(file.size)}; the limit is ${formatBytes(MAX_BYTES)}.`);
      return;
    }
    let text;
    try {
      text = await file.text();
    } catch (err) {
      showError(`Could not read "${file.name}": ${err.message}`);
      return;
    }
    if (text.includes("\u0000")) {
      showError(`"${file.name}" looks like a binary file. Only text files (source code, config, JSON) can be scanned.`);
      return;
    }
    const detected = detectLanguage(file.name, text);
    selectLanguage(detected, { detectedFrom: file.name });
    setEditorText(text);
    setFileName(file.name);
    await scan();
  }

  function setDropActive(active) {
    el.dropOverlay.classList.toggle("hidden", !active);
    el.dropOverlay.classList.toggle("flex", active);
  }

  async function loadEngineStatus() {
    try {
      const res = await fetch("/api/health");
      if (!res.ok) return;
      const health = await res.json();
      el.engine.textContent = `Semgrep ${health.semgrep_version} · ${health.rules_loaded} rules`;
      el.engine.classList.remove("hidden");
      el.statRules.textContent = String(health.rules_loaded);
    } catch { /* status badge is optional */ }
  }

  // ----------------------------------------------------------------- wiring
  el.scan.addEventListener("click", scan);
  el.sample.addEventListener("click", loadSample);
  el.format.addEventListener("click", () => {
    clearError();
    const data = parseWorkflow(el.input.value);
    if (data) setEditorText(JSON.stringify(data, null, 2) + "\n");
  });
  el.clear.addEventListener("click", () => {
    setEditorText("");
    setFileName(null);
    clearError();
    el.detectNote.classList.add("hidden");
    el.input.focus();
  });
  el.groupBy.addEventListener("change", () => lastResult && renderFindings());
  el.btnPdf.addEventListener("click", downloadPdf);
  el.btnHtml.addEventListener("click", () => lastResult && download(buildHtmlReport(), "text/html", reportFilename("html")));
  el.btnMd.addEventListener("click", () => lastResult && download(buildMarkdownReport(), "text/markdown", reportFilename("md")));
  el.btnJson.addEventListener("click", () => lastResult && download(JSON.stringify(exportResult(), null, 2), "application/json", reportFilename("json")));

  el.upload.addEventListener("click", () => el.fileInput.click());
  el.fileInput.addEventListener("change", () => {
    const [file] = el.fileInput.files;
    el.fileInput.value = ""; // allow re-selecting the same file
    loadFile(file);
  });

  // Drag-and-drop onto the editor. Dropping elsewhere on the page must not
  // make the browser navigate to (open) the file.
  let dragDepth = 0;
  el.dropZone.addEventListener("dragenter", (e) => {
    if (!e.dataTransfer?.types.includes("Files")) return;
    e.preventDefault();
    dragDepth++;
    setDropActive(true);
  });
  el.dropZone.addEventListener("dragover", (e) => {
    if (!e.dataTransfer?.types.includes("Files")) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
  });
  el.dropZone.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) setDropActive(false);
  });
  el.dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dragDepth = 0;
    setDropActive(false);
    const files = e.dataTransfer?.files;
    if (files && files.length > 1) {
      showError("Drop one file at a time.");
      return;
    }
    loadFile(files?.[0]);
  });
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => e.preventDefault());
  el.input.addEventListener("input", () => {
    clearHighlight(); // edits can shift lines
    updateMeta();
  });
  el.input.addEventListener("scroll", syncEditorScroll);
  // The textarea is resizable; keep the gutter and highlight aligned.
  new ResizeObserver(syncEditorScroll).observe(el.input);
  el.input.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      if (!el.scan.disabled) scan();
    }
  });

  updateMeta();
  loadLanguages();
  loadEngineStatus();
})();

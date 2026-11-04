/**
 * Stylesheet and page script of the HTML report, kept apart from the
 * generator so the script's CSP hash is computed over exactly this text.
 * The script builds the page from the embedded JSON with createElement and
 * textContent only; it never parses server text as HTML.
 */

export const HTML_STYLE = String.raw`
:root {
  --bg: #ffffff; --surface: #ffffff; --surface-2: #fafafa; --border: #e4e4e7; --border-strong: #d4d4d8;
  --text: #18181b; --muted: #71717a; --accent: #c026d3; --accent-strong: #86198f; --accent-soft: #fdf4ff;
  --critical: #dc2626; --high: #ea580c; --medium: #ca8a04; --low: #2563eb; --info: #71717a;
  --pass: #16a34a; --fail: #dc2626; --shadow: 0 1px 2px rgba(0,0,0,.04), 0 4px 16px rgba(0,0,0,.05);
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #000000; --surface: #0c0c0f; --surface-2: #131318; --border: #26262b; --border-strong: #3f3f46;
    --text: #f4f4f5; --muted: #a1a1aa; --accent: #e879f9; --accent-strong: #f0abfc; --accent-soft: #2b0b30;
    --critical: #f87171; --high: #fb923c; --medium: #facc15; --low: #60a5fa; --info: #a1a1aa;
    --pass: #4ade80; --fail: #f87171; --shadow: 0 1px 2px rgba(0,0,0,.6), 0 8px 24px rgba(0,0,0,.5);
    color-scheme: dark;
  }
}
:root[data-theme="dark"] {
  --bg: #000000; --surface: #0c0c0f; --surface-2: #131318; --border: #26262b; --border-strong: #3f3f46;
  --text: #f4f4f5; --muted: #a1a1aa; --accent: #e879f9; --accent-strong: #f0abfc; --accent-soft: #2b0b30;
  --critical: #f87171; --high: #fb923c; --medium: #facc15; --low: #60a5fa; --info: #a1a1aa;
  --pass: #4ade80; --fail: #f87171; --shadow: 0 1px 2px rgba(0,0,0,.6), 0 8px 24px rgba(0,0,0,.5);
  color-scheme: dark;
}
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--bg); color: var(--text); }
body { font: 14px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
.wrap { max-width: 1280px; margin: 0 auto; padding: 28px 32px 64px; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.noscript { padding: 24px; }
.topbar { display: flex; align-items: center; gap: 14px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }
.brand { display: flex; align-items: center; gap: 12px; }
.brand-name { font-family: var(--mono); font-weight: 700; font-size: 18px; letter-spacing: -.01em; }
.brand-sub { color: var(--muted); font-size: 13px; }
.topbar .meta { margin-left: auto; color: var(--muted); font-size: 12.5px; text-align: right; }
.icon-btn { border: 1px solid var(--border); background: var(--surface); color: var(--text); border-radius: 8px; padding: 6px 10px; font: inherit; font-size: 12.5px; cursor: pointer; }
.icon-btn:hover { border-color: var(--accent); }
section { margin-top: 28px; }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin: 0 0 12px; font-weight: 600; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; box-shadow: var(--shadow); }
.hero { display: grid; grid-template-columns: 300px 1fr; gap: 16px; }
.verdict { padding: 22px; display: flex; flex-direction: column; justify-content: space-between; position: relative; overflow: hidden; }
.verdict::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 5px; background: var(--v); }
.verdict.fail { --v: var(--fail); } .verdict.pass { --v: var(--pass); }
.verdict-label { font-size: 12px; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); }
.verdict-value { font-size: 44px; font-weight: 800; letter-spacing: -.02em; color: var(--v); line-height: 1.1; margin: 6px 0 8px; }
.verdict-note { color: var(--muted); font-size: 13px; }
.verdict-note b { color: var(--text); }
.dist { padding: 20px 22px; display: grid; grid-template-columns: 150px 1fr; gap: 24px; align-items: center; }
.donut-total { font-size: 26px; font-weight: 800; fill: var(--text); }
.donut-caption { font-size: 10px; fill: var(--muted); text-transform: uppercase; letter-spacing: .1em; }
.chips { display: flex; flex-wrap: wrap; gap: 8px; }
.chip { display: inline-flex; align-items: center; gap: 8px; border: 1px solid var(--border); border-radius: 999px; padding: 5px 12px 5px 8px; font-size: 13px; background: var(--surface); }
.chip .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--c); }
.chip .n { font-weight: 700; font-variant-numeric: tabular-nums; }
.chip.zero { opacity: .45; }
.stack { display: flex; height: 10px; border-radius: 999px; overflow: hidden; background: var(--surface-2); border: 1px solid var(--border); margin-top: 16px; }
.stack span { background: var(--c); }
.sev-critical { --c: var(--critical); } .sev-high { --c: var(--high); } .sev-medium { --c: var(--medium); } .sev-low { --c: var(--low); } .sev-info { --c: var(--info); }
.servers { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 14px; }
.server { padding: 16px 18px; }
.server-head { display: flex; align-items: center; gap: 10px; }
.server-name { font-family: var(--mono); font-weight: 700; font-size: 14px; overflow-wrap: anywhere; }
.kind { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; border-radius: 6px; padding: 2px 7px; background: var(--accent-soft); color: var(--accent-strong); border: 1px solid var(--border); }
.server-target { font-family: var(--mono); font-size: 12px; color: var(--muted); margin: 6px 0 12px; overflow-wrap: anywhere; }
.counts { display: flex; gap: 18px; font-size: 12.5px; color: var(--muted); }
.counts b { color: var(--text); font-size: 16px; display: block; font-variant-numeric: tabular-nums; }
.facts { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; }
.fact { font-size: 11.5px; border: 1px solid var(--border); border-radius: 6px; padding: 1px 7px; color: var(--muted); }
.risk { margin-top: 14px; }
.risk-row { display: flex; justify-content: space-between; font-size: 12px; color: var(--muted); margin-bottom: 6px; }
.risk .stack { margin-top: 0; height: 8px; }
.matrix-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { padding: 9px 12px; border-bottom: 1px solid var(--border); text-align: left; }
th { font-size: 11.5px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); font-weight: 600; background: var(--surface-2); }
tr:last-child td { border-bottom: 0; }
.matrix td.cell { text-align: center; font-variant-numeric: tabular-nums; font-weight: 700; }
.matrix td.cell.on { background: color-mix(in srgb, var(--c) 14%, transparent); color: var(--c); }
.matrix td.cell.off { color: var(--border-strong); font-weight: 400; }
.rule-id { font-family: var(--mono); font-size: 12.5px; white-space: nowrap; }
.toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; padding: 12px 14px; margin-bottom: 14px; position: sticky; top: 0; z-index: 2; }
.toggle { border: 1px solid var(--border); background: var(--surface); color: var(--text); border-radius: 999px; padding: 5px 12px 5px 9px; font: inherit; font-size: 12.5px; cursor: pointer; display: inline-flex; align-items: center; gap: 7px; }
.toggle .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--c); }
.toggle[aria-pressed="false"] { opacity: .45; text-decoration: line-through; }
select, input[type="search"] { font: inherit; font-size: 13px; color: var(--text); background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 6px 10px; }
input[type="search"] { flex: 1; min-width: 200px; }
select:focus, input:focus, .toggle:focus-visible, .icon-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.shown { margin-left: auto; color: var(--muted); font-size: 12.5px; }
.group { margin-bottom: 18px; }
.group-head { display: flex; align-items: center; gap: 10px; margin: 0 0 8px; }
.group-head .server-name { font-size: 15px; }
.group-head .count { color: var(--muted); font-size: 12.5px; }
.item { margin: 0 0 10px; padding: 12px 14px; }
.item-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.item-kind { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
.item-name { font-family: var(--mono); font-weight: 600; overflow-wrap: anywhere; }
details.finding { border: 1px solid var(--border); border-radius: 10px; margin-top: 8px; background: var(--surface); overflow: hidden; }
details.finding[open] { border-color: var(--border-strong); }
details.finding > summary { list-style: none; cursor: pointer; display: grid; grid-template-columns: 92px 84px minmax(0, 1fr) auto 14px; gap: 12px; align-items: center; padding: 10px 14px; border-left: 4px solid var(--c); }
details.finding > summary::-webkit-details-marker { display: none; }
details.finding > summary:hover { background: var(--surface-2); }
.pill { display: inline-flex; justify-content: center; font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .06em; border-radius: 6px; padding: 3px 8px; color: var(--c); background: color-mix(in srgb, var(--c) 13%, transparent); border: 1px solid color-mix(in srgb, var(--c) 35%, transparent); }
.f-title { font-weight: 600; }
.f-field { color: var(--muted); font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
.chev { color: var(--muted); transition: transform .15s; font-family: var(--mono); }
details[open] .chev { transform: rotate(90deg); }
.f-body { padding: 4px 18px 16px 18px; border-left: 4px solid var(--c); }
.f-body h4 { margin: 14px 0 6px; font-size: 11.5px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); }
.f-body p { margin: 6px 0; }
.evidence { font-family: var(--mono); font-size: 12.5px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; }
.tok { display: inline-block; border-radius: 5px; padding: 0 5px; margin: 0 1px; font-size: 11.5px; font-weight: 700; line-height: 1.6; }
.tok-cp { background: #fde68a; color: #713f12; }
.tok-ctl { background: #fecaca; color: #7f1d1d; }
.tok-hidden { background: var(--accent); color: #fff; }
.tok-hidden i { font-style: normal; opacity: .8; font-weight: 500; margin-right: 4px; }
.tok-secret { background: #e4e4e7; color: #3f3f46; }
:root[data-theme="dark"] .tok-secret { background: #3f3f46; color: #e4e4e7; }
.refs { margin: 4px 0 0; padding-left: 18px; }
.judge { border-left: 3px solid var(--accent); padding: 6px 10px; background: var(--accent-soft); border-radius: 0 8px 8px 0; font-size: 13px; }
.empty { padding: 28px; text-align: center; color: var(--muted); }
details.probe > summary { cursor: pointer; color: var(--muted); font-size: 13px; padding: 12px 16px; }
.status-called { color: var(--pass); font-weight: 600; } .status-skipped { color: var(--muted); } .status-error { color: var(--fail); font-weight: 600; }
footer { margin-top: 36px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
@media (max-width: 860px) {
  .wrap { padding: 20px 16px 48px; }
  .hero, .dist { grid-template-columns: 1fr; }
  details.finding > summary { grid-template-columns: auto auto minmax(0, 1fr) 14px; }
  details.finding > summary .f-field { display: none; }
}
`;

export const HTML_CLIENT = String.raw`
(function () {
  "use strict";
  var data = JSON.parse(document.getElementById("report-data").textContent);
  var SEV = ["critical", "high", "medium", "low", "info"];
  var RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function add(parent) {
    for (var i = 1; i < arguments.length; i++) if (arguments[i]) parent.appendChild(arguments[i]);
    return parent;
  }
  function svg(tag, attrs) {
    var e = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (var k in attrs) e.setAttribute(k, String(attrs[k]));
    return e;
  }
  function link(url, text) {
    var a = el("a", null, text);
    if (/^https:\/\/[^\s]+$/.test(url)) { a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer"; }
    return a;
  }
  function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
  function worst(list) {
    var w = null;
    list.forEach(function (f) { if (!w || RANK[f.severity] > RANK[w]) w = f.severity; });
    return w;
  }
  function countBy(list) {
    var c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    list.forEach(function (f) { c[f.severity]++; });
    return c;
  }
  function stackBar(counts) {
    var total = SEV.reduce(function (n, s) { return n + counts[s]; }, 0);
    var bar = el("div", "stack");
    SEV.forEach(function (s) {
      if (!counts[s]) return;
      var seg = el("span", "sev-" + s);
      seg.style.width = (100 * counts[s] / total) + "%";
      seg.title = counts[s] + " " + s;
      bar.appendChild(seg);
    });
    return bar;
  }

  // ------------------------------------------------------------ theme
  var root = document.documentElement;
  var themes = ["auto", "light", "dark"];
  var theme = "auto";
  function applyTheme() {
    if (theme === "auto") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", theme);
    themeBtn.textContent = "Theme: " + theme;
  }
  var themeBtn = el("button", "icon-btn");
  themeBtn.type = "button";
  themeBtn.addEventListener("click", function () {
    theme = themes[(themes.indexOf(theme) + 1) % themes.length];
    applyTheme();
  });

  // ------------------------------------------------------------ header
  var app = document.getElementById("app");
  var wrap = add(app, el("div", "wrap")).firstChild;

  var logo = svg("svg", { width: 40, height: 40, viewBox: "0 0 128 128", "aria-hidden": "true" });
  var grad = svg("linearGradient", { id: "g", x1: 0, y1: 0, x2: 1, y2: 1 });
  add(grad, svg("stop", { offset: 0, "stop-color": "#D946EF" }), svg("stop", { offset: 1, "stop-color": "#86198F" }));
  add(logo, add(svg("defs", {}), grad), svg("rect", { width: 128, height: 128, rx: 28, fill: "url(#g)" }),
    svg("rect", { x: 30, y: 34, width: 52, height: 10, rx: 5, fill: "#fff", opacity: .55 }),
    svg("rect", { x: 30, y: 59, width: 68, height: 10, rx: 5, fill: "#fff" }),
    svg("rect", { x: 30, y: 84, width: 40, height: 10, rx: 5, fill: "#fff", opacity: .55 }),
    svg("path", { d: "M22 50 H16 V78 H22 M106 50 H112 V78 H106", fill: "none", stroke: "#fff", "stroke-width": 6, "stroke-linecap": "round", "stroke-linejoin": "round" }));
  var started = new Date(data.meta.startedAt);
  var when = isNaN(started.getTime()) ? "" : started.toISOString().replace("T", " ").slice(0, 16) + " UTC";
  add(wrap, add(el("header", "topbar"),
    add(el("div", "brand"), logo, add(el("div"), el("div", "brand-name", "mcp-guard"), el("div", "brand-sub", "MCP security report"))),
    add(el("div", "meta"),
      el("div", null, when + "  \u00B7  " + data.meta.durationMs + " ms  \u00B7  v" + data.meta.version),
      el("div", null, "fail-on: " + data.meta.failOn)),
    themeBtn));
  applyTheme();

  // ------------------------------------------------------------ verdict and distribution
  var total = data.findings.length;
  var gating = data.findings.filter(function (f) { return data.meta.failOn !== "none" && RANK[f.severity] >= RANK[data.meta.failOn]; }).length;
  var verdict = add(el("div", "card verdict " + data.meta.verdict),
    add(el("div"), el("div", "verdict-label", "Verdict"), el("div", "verdict-value", data.meta.verdict.toUpperCase())));
  var note = el("div", "verdict-note");
  if (data.meta.failOn === "none") note.textContent = "Gate disabled (--fail-on none). " + total + " finding(s) reported.";
  else {
    add(note, el("b", null, String(gating)), document.createTextNode(" finding(s) at or above "), el("b", null, data.meta.failOn),
      document.createTextNode(" across " + data.servers.length + " server(s); " + total + " in total."));
  }
  verdict.appendChild(note);

  var R = 52, C = 2 * Math.PI * R;
  var donut = svg("svg", { width: 150, height: 150, viewBox: "0 0 150 150", role: "img", "aria-label": total + " findings by severity" });
  add(donut, svg("circle", { cx: 75, cy: 75, r: R, fill: "none", stroke: "var(--surface-2)", "stroke-width": 18 }));
  var offset = 0;
  SEV.forEach(function (s) {
    var n = data.summary[s];
    if (!n || !total) return;
    var len = C * n / total;
    var seg = svg("circle", { cx: 75, cy: 75, r: R, fill: "none", "stroke-width": 18, "stroke-dasharray": len + " " + (C - len), "stroke-dashoffset": -offset, transform: "rotate(-90 75 75)", "class": "sev-" + s });
    seg.style.stroke = "var(--c)";
    donut.appendChild(seg);
    offset += len;
  });
  var t1 = svg("text", { x: 75, y: 78, "text-anchor": "middle", "class": "donut-total" }); t1.textContent = String(total);
  var t2 = svg("text", { x: 75, y: 96, "text-anchor": "middle", "class": "donut-caption" }); t2.textContent = "findings";
  add(donut, t1, t2);

  var chips = el("div", "chips");
  SEV.forEach(function (s) {
    var n = data.summary[s];
    add(chips, add(el("span", "chip sev-" + s + (n ? "" : " zero")), el("span", "dot"), el("span", "n", String(n)), el("span", null, cap(s))));
  });
  var dist = add(el("div", "card dist"), donut, add(el("div"), chips, total ? stackBar(data.summary) : null));
  add(wrap, add(el("section"), add(el("div", "hero"), verdict, dist)));

  // ------------------------------------------------------------ servers
  var sec = add(el("section"), el("h2", null, "Servers (" + data.servers.length + ")"));
  var grid = el("div", "servers");
  data.servers.forEach(function (s) {
    var mine = data.findings.filter(function (f) { return f.server === s.name; });
    var c = countBy(mine), w = worst(mine);
    var card = add(el("div", "card server"),
      add(el("div", "server-head"), el("span", "kind", s.kind), el("span", "server-name", s.name)),
      el("div", "server-target", s.target),
      add(el("div", "counts"),
        add(el("div"), el("b", null, String(s.tools)), document.createTextNode("tools")),
        add(el("div"), el("b", null, String(s.resources)), document.createTextNode("resources")),
        add(el("div"), el("b", null, String(s.prompts)), document.createTextNode("prompts"))));
    if (s.facts.length) {
      var facts = el("div", "facts");
      s.facts.forEach(function (f) { facts.appendChild(el("span", "fact", f)); });
      card.appendChild(facts);
    }
    var risk = add(el("div", "risk"), add(el("div", "risk-row"),
      el("span", null, mine.length ? mine.length + " finding(s)" : "No findings"),
      w ? add(el("span", "pill sev-" + w), document.createTextNode("worst: " + w)) : null));
    if (mine.length) risk.appendChild(stackBar(c));
    card.appendChild(risk);
    grid.appendChild(card);
  });
  add(wrap, add(sec, grid));

  if (!total) {
    add(wrap, add(el("section"), el("h2", null, "Findings"), el("div", "card empty", "No findings. Every rule passed for every server.")));
  } else {
    // ---------------------------------------------------------- matrix
    var ruleIds = Object.keys(data.rules).sort();
    var mx = el("table", "matrix");
    var head = add(el("tr"), el("th", null, "Rule"));
    data.servers.forEach(function (s) { head.appendChild(el("th", null, s.name)); });
    add(mx, add(el("thead"), head));
    var body = el("tbody");
    ruleIds.forEach(function (id) {
      var rows = data.findings.filter(function (f) { return f.ruleId === id; });
      var sev = rows[0].severity;
      var tr = add(el("tr"), add(el("td"), el("span", "rule-id", id), document.createTextNode("  " + data.rules[id].title)));
      data.servers.forEach(function (s) {
        var n = rows.filter(function (f) { return f.server === s.name; }).length;
        tr.appendChild(el("td", "cell " + (n ? "on sev-" + sev : "off"), n ? String(n) : "\u00B7"));
      });
      body.appendChild(tr);
    });
    add(wrap, add(el("section"), el("h2", null, "Rule \u00D7 server"), add(el("div", "card matrix-wrap"), add(mx, body))));

    // ---------------------------------------------------------- findings
    var fsec = add(el("section"), el("h2", null, "Findings"));
    var active = {}; SEV.forEach(function (s) { active[s] = true; });
    var toolbar = el("div", "card toolbar");
    SEV.forEach(function (s) {
      if (!data.summary[s]) return;
      var b = add(el("button", "toggle sev-" + s), el("span", "dot"), document.createTextNode(cap(s) + " " + data.summary[s]));
      b.type = "button";
      b.setAttribute("aria-pressed", "true");
      b.addEventListener("click", function () {
        active[s] = !active[s];
        b.setAttribute("aria-pressed", String(active[s]));
        filter();
      });
      toolbar.appendChild(b);
    });
    var sel = el("select");
    sel.setAttribute("aria-label", "Filter by rule");
    sel.appendChild(el("option", null, "All rules")).value = "";
    ruleIds.forEach(function (id) { sel.appendChild(el("option", null, id + "  " + data.rules[id].title)).value = id; });
    sel.addEventListener("change", filter);
    var search = el("input");
    search.type = "search"; search.placeholder = "Search tools, messages, evidence"; search.setAttribute("aria-label", "Search findings");
    search.addEventListener("input", filter);
    var shown = el("span", "shown");
    add(toolbar, sel, search, shown);
    fsec.appendChild(toolbar);

    var cards = [];
    var groups = [];
    data.servers.forEach(function (s) {
      var mine = data.findings.filter(function (f) { return f.server === s.name; });
      if (!mine.length) return;
      var g = add(el("div", "group"), add(el("div", "group-head"), el("span", "kind", s.kind), el("span", "server-name", s.name), el("span", "count", mine.length + " finding(s)")));
      var items = [];
      mine.forEach(function (f) {
        var key = f.kind + "\u0000" + f.name;
        var it = items.filter(function (x) { return x.key === key; })[0];
        if (!it) { it = { key: key, kind: f.kind, name: f.name, list: [] }; items.push(it); }
        it.list.push(f);
      });
      items.sort(function (a, b) { return RANK[worst(b.list)] - RANK[worst(a.list)]; });
      var itemEls = [];
      items.forEach(function (it) {
        var box = add(el("div", "card item"), add(el("div", "item-head"), el("span", "pill sev-" + worst(it.list), worst(it.list)), el("span", "item-kind", it.kind), el("span", "item-name", it.name)));
        var itemCards = [];
        it.list.forEach(function (f) {
          var d = card(f);
          box.appendChild(d);
          var entry = { el: d, f: f, text: [f.ruleId, f.name, f.server, f.field, f.message, f.evidence, (data.rules[f.ruleId] || {}).title || ""].join(" ").toLowerCase() };
          cards.push(entry); itemCards.push(entry);
        });
        itemEls.push({ el: box, cards: itemCards });
        g.appendChild(box);
      });
      groups.push({ el: g, items: itemEls });
      fsec.appendChild(g);
    });
    add(wrap, fsec);

    function filter() {
      var rule = sel.value, q = search.value.trim().toLowerCase(), n = 0;
      cards.forEach(function (c) {
        var ok = active[c.f.severity] && (!rule || c.f.ruleId === rule) && (!q || c.text.indexOf(q) !== -1);
        c.el.hidden = !ok; if (ok) n++;
      });
      groups.forEach(function (g) {
        var any = false;
        g.items.forEach(function (it) {
          var vis = it.cards.some(function (c) { return !c.el.hidden; });
          it.el.hidden = !vis; any = any || vis;
        });
        g.el.hidden = !any;
      });
      shown.textContent = "Showing " + n + " of " + cards.length;
    }
    filter();
  }

  // ------------------------------------------------------------ one finding
  function card(f) {
    var r = data.rules[f.ruleId] || { title: "", remediation: "", doc: "", references: [] };
    var d = el("details", "finding sev-" + f.severity);
    d.id = "finding-" + f.ruleId.toLowerCase() + "-" + Math.random().toString(36).slice(2, 8);
    add(d, add(el("summary"), el("span", "pill sev-" + f.severity, f.severity), el("span", "rule-id", f.ruleId), el("span", "f-title", r.title), el("span", "f-field", f.field), el("span", "chev", ">")));
    var b = add(el("div", "f-body"), el("p", null, f.message));
    if (f.evidence) add(b, el("h4", null, "Evidence"), evidence(f.evidence));
    if (f.judge) add(b, el("h4", null, "LLM judge (informational)"), el("div", "judge", f.judge));
    if (r.remediation) add(b, el("h4", null, "Remediation"), el("p", null, r.remediation));
    if (r.references.length) {
      var ul = el("ul", "refs");
      r.references.forEach(function (ref) { add(ul, add(el("li"), link(ref.url, ref.title))); });
      add(b, el("h4", null, "References"), ul);
    }
    add(b, add(el("p"), link(r.doc, "Rule " + f.ruleId + " in docs/rules.md")));
    d.appendChild(b);
    return d;
  }

  /** Evidence with invisible characters, hidden tag text, control codes and redactions as coloured tokens. */
  function evidence(text) {
    var pre = el("pre", "evidence");
    var re = /(<U\+[0-9A-F]{4,6}>)|(<tags:("(?:[^"\\]|\\.)*")>)|(\\x[0-9a-f]{2})|([^\s"'<>]{0,4}\.\.\.(?:\[redacted\]| \(\d+ chars, redacted\)))/g;
    var last = 0, m;
    while ((m = re.exec(text))) {
      if (m.index > last) pre.appendChild(document.createTextNode(text.slice(last, m.index)));
      if (m[1]) pre.appendChild(tok("tok-cp", m[1].slice(1, -1), "Invisible character " + m[1].slice(1, -1)));
      else if (m[2]) {
        var hidden = m[3];
        try { hidden = JSON.parse(m[3]); } catch (e) { /* keep the quoted form */ }
        var t = tok("tok-hidden", "", "Text hidden with Unicode tag characters");
        add(t, el("i", null, "hidden:"), document.createTextNode(hidden));
        pre.appendChild(t);
      } else if (m[4]) pre.appendChild(tok("tok-ctl", m[4], "Control character"));
      else pre.appendChild(tok("tok-secret", m[5], "Credential, redacted"));
      last = re.lastIndex;
    }
    if (last < text.length) pre.appendChild(document.createTextNode(text.slice(last)));
    return pre;
  }
  function tok(cls, text, title) { var s = el("span", "tok " + cls, text); s.title = title; return s; }

  // ------------------------------------------------------------ probe and footer
  if (data.probe) {
    var called = data.probe.filter(function (p) { return p.status === "called"; }).length;
    var det = add(el("details", "card probe"), el("summary", null, "Probe: " + called + " called, " + (data.probe.length - called) + " skipped or failed. Show calls"));
    var tb = el("tbody");
    data.probe.forEach(function (p) {
      add(tb, add(el("tr"), el("td", "rule-id", p.server), el("td", null, p.kind + " " + p.target), el("td", "status-" + p.status, p.status), el("td", null, p.reason)));
    });
    add(det, add(el("table"), add(el("thead"), add(el("tr"), el("th", null, "Server"), el("th", null, "Target"), el("th", null, "Status"), el("th", null, "Reason"))), tb));
    add(wrap, add(el("section"), el("h2", null, "Probe"), det));
  }
  add(wrap, add(el("footer"), el("span", null, "Generated by mcp-guard " + data.meta.version + ". Server-supplied text is shown as data; invisible characters are revealed and credentials redacted."),
    link("https://github.com/diegoperezg7/mcp-guard-scan", "github.com/diegoperezg7/mcp-guard-scan")));
})();
`;

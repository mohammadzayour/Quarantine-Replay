"use strict";
// All server data (log text, model output, reasons) is untrusted: it is only ever
// inserted with textContent / setAttribute, never as HTML.

const SVG_NS = "http://www.w3.org/2000/svg";
const $ = (sel) => document.querySelector(sel);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let state = null;
let busy = false;
let busyLabel = "";
let openEventId = null;
const lastNodeClass = {};

function build(ns, tag, attrs, kids) {
  const el = ns ? document.createElementNS(ns, tag) : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(3)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const h = (tag, attrs, ...kids) => build(null, tag, attrs, kids);
const s = (tag, attrs, ...kids) => build(SVG_NS, tag, attrs, kids);

async function api(path, body) {
  const res = await fetch(path, body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (!res.ok) {
    const detail = data && data.detail;
    throw new Error(typeof detail === "string" ? detail : `Request failed (HTTP ${res.status})`);
  }
  return data;
}

function toast(message) {
  const el = $("#toast");
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.hidden = true; }, 6000);
}

const clock = (iso) => (iso || "").slice(11, 19);
const endpoint = (world, hostname) => world.endpoints.find((e) => e.hostname === hostname);
const decisionsFor = (lane) => state.events.filter((e) => e.kind === "tool_decision" && e.lane === lane);

// ------------------------------------------------------------------ actions

async function refresh() {
  state = await api("/api/state");
  render();
}

async function guarded(fn) {
  if (busy) return;
  busy = true;
  render();
  try { await fn(); } catch (err) { toast(err.message); }
  busy = false;
  try { await refresh(); } catch (err) { toast(err.message); }
}

function runDemo(mode, scenario = "poisoned") {
  return guarded(async () => {
    // Start each run from the same clean state; the live-run history is kept.
    if (state.capture) { await api("/api/demo/reset", { keep_live_history: true }); await refresh(); await sleep(350); }
    if (mode === "live") {
      busyLabel = `Running ${state.live.model} on the ${scenario} log… a small local model can take a minute or more.`;
      render();
    }
    let capture;
    try { capture = await api("/api/demo/capture", { mode, scenario }); } finally { busyLabel = ""; }
    await refresh();
    pulse("#capture-panel");
    if (capture.outcome !== "tool_call") return;
    await sleep(1100);
    await api("/api/demo/replay", { capture_id: capture.capture_id });
    await refresh();
  });
}

function approveWorkstation() {
  return guarded(async () => {
    await api("/api/analyst/approvals", {
      incident_id: state.incident.incident_id,
      action: "quarantine_endpoint",
      endpoint: "workstation-17",
    });
    await refresh();
    await sleep(800);
    await api("/api/demo/contain-workstation", {});
  });
}

function resetDemo() {
  return guarded(async () => { closeDrawer(); await api("/api/demo/reset", {}); });
}

function pulse(sel) {
  const el = $(sel);
  el.classList.remove("flash");
  void el.offsetWidth;
  el.classList.add("flash");
}

// ------------------------------------------------------------------- render

function render() {
  if (!state) return;
  renderHeader();
  renderSteps();
  renderEvidence();
  renderCapture();
  renderReplay();
  renderAnalyst();
  renderTimeline();
  if (openEventId !== null) {
    const ev = state.events.find((e) => e.event_id === openEventId);
    if (ev) renderDrawer(ev); else closeDrawer();
  }
}

function renderHeader() {
  const inc = state.incident;
  $("#incident-chip").textContent = `${inc.incident_id} · ${inc.title}`;
  $("#btn-run").disabled = busy;
  $("#btn-reset").disabled = busy;
  const live = state.live;
  for (const scenario of ["poisoned", "clean"]) {
    const btn = $(`#btn-live-${scenario}`);
    btn.disabled = busy || !live.available;
    btn.title = live.available
      ? `Sends the ${scenario} log to ${live.label} once and captures the real response`
      : live.hint;
  }
  const hint = $("#live-hint");
  hint.classList.toggle("working", !!busyLabel);
  hint.textContent = busyLabel || (live.available
    ? `Live model: ${live.label}${live.paid ? "" : " — runs on this machine, no paid API calls"}. ` +
      "The poisoned log contains the attacker's entry; the clean log is the same incident without it."
    : `Live model unavailable: ${live.hint} The fixture demo works without it.`);
}

function currentScenario() {
  return state.capture ? state.capture.scenario || "poisoned" : "poisoned";
}

function renderSteps() {
  const p = state.worlds.protected;
  const cap = state.capture;
  const done = [
    true,
    !!(cap && cap.outcome === "tool_call"),
    !!(cap && cap.replayed_at),
    endpoint(p, "workstation-17").network_status === "isolated",
  ];
  const labels = [
    "Attacker text sits in the log",
    "Responder proposes a tool call",
    "Same call replayed on two backends",
    "Analyst approves the right target",
  ];
  const firstOpen = done.indexOf(false);
  $("#steps").replaceChildren(...labels.map((label, i) =>
    h("li", { class: done[i] ? "done" : (i === firstOpen ? "next" : "") },
      h("span", { class: "n", text: done[i] ? "✓" : String(i + 1) }), label)));
}

function renderEvidence() {
  const clean = currentScenario() === "clean";
  const tag = $("#evidence-scenario");
  tag.className = `tag ${clean ? "clean" : "untrusted"}`;
  tag.textContent = clean ? "clean log · no attacker entry" : "poisoned log · untrusted input";
  const entries = clean ? state.evidence_clean : state.evidence;
  const rows = entries.map((e) =>
    h("li", { class: e.attacker_controlled ? "injected" : "" },
      h("span", { class: "ts", text: clock(e.ts) }),
      h("span", { class: "src", text: e.source, title: e.source }),
      h("span", { class: "txt" },
        e.attacker_controlled && h("span", { class: "tag attack", text: "attacker-controlled" }),
        e.text,
        e.note && h("span", { class: "why", text: e.note }))));
  if (clean) {
    rows.push(h("li", { class: "log-note",
      text: "Clean incident: the attacker-controlled scheduled-task entry (09:04:52) is not in this log." }));
  }
  $("#evidence").replaceChildren(...rows);
}

function liveRunsTable() {
  if (!state.live_runs.length) return null;
  const world = (run, name) => {
    if (!run.replay) return "not replayed";
    const w = run.replay[name];
    return w.decisions.map((d) => `${d.outcome} (${d.target})`).join(", ") + ` · app ${w.app}`;
  };
  return h("div", { class: "runs" },
    h("h3", { text: `Live runs this session · real output from ${[...new Set(state.live_runs.map((r) => r.model || "model"))].join(", ")}` }),
    h("table", { class: "grid" },
      h("thead", {}, h("tr", {}, ["Log", "Model did", "Vulnerable", "Protected", "Time"].map((t) => h("th", { text: t })))),
      h("tbody", {}, state.live_runs.map((run) => h("tr", {},
        h("td", { class: "nowrap", text: run.scenario }),
        h("td", { class: run.outcome === "error" || run.targets_injected_endpoint ? "val-bad" : "",
                  text: (run.outcome === "tool_call" ? `proposed quarantine of ${run.targets.join(", ")}`
                    : run.outcome === "error" ? "request failed" : run.outcome.replace(/_/g, " ")) +
                    (run.targets_injected_endpoint === true ? " — the injected target"
                      : run.targets_injected_endpoint === false ? " — injected target (prod-db-01) not called" : "") }),
        h("td", { text: run.outcome === "tool_call" ? world(run, "vulnerable") : "—" }),
        h("td", { text: run.outcome === "tool_call" ? world(run, "protected") : "—" }),
        h("td", { class: "nowrap", text: run.duration_s ? `${Math.round(run.duration_s)}s` : "—" }))))));
}

function renderCapture() {
  const cap = state.capture;
  const root = $("#capture");
  if (!cap) {
    root.replaceChildren(h("p", { class: "empty" },
      "Nothing captured yet. ", h("b", { text: "Run demo (fixture)" }),
      " replays a labelled, hand-written call. ", h("b", { text: "Run live model" }),
      " asks the real model and replays whatever it actually proposes."), liveRunsTable());
    return;
  }
  const isLive = cap.source === "live";
  if (cap.outcome === "error") {
    // The request failed: say only that, and nothing about model behaviour.
    root.replaceChildren(
      h("div", { class: "capture-meta" },
        h("span", { class: "tag error", text: "live run failed · no model response" }),
        h("span", { class: "small muted", text: `${clock(cap.created_at)} · requested ${cap.model_requested || "model"} (${cap.provider || "live"})` })),
      h("div", { class: "error-box", text: cap.note }),
      h("p", { class: "note muted",
        text: "No model output exists for this run, so nothing was replayed and neither backend was touched. Run demo (fixture) still works." }),
      liveRunsTable());
    return;
  }
  const kids = [
    h("div", { class: "capture-meta" },
      h("span", { class: `tag ${isLive ? "live" : "fixture"}`,
                  text: isLive ? "live model output" : "fixture · not model output" }),
      isLive && h("span", { class: `tag ${cap.scenario === "clean" ? "clean" : "untrusted"}`, text: `${cap.scenario} log` }),
      isLive && h("span", { class: "small mono muted",
        text: `${cap.model_served || cap.model_requested} via ${cap.provider}` +
              (cap.fallback_used ? " (fallback model answered)" : "") +
              (cap.stop_reason ? ` · ${cap.stop_reason}` : "") +
              (cap.duration_s ? ` · ${cap.duration_s}s` : "") }),
      h("span", { class: "small muted", text: `captured ${clock(cap.created_at)}` })),
  ];
  if (isLive && cap.model_thinking) {
    kids.push(h("details", { class: "thinking" },
      h("summary", { text: "Model reasoning, as returned by the model" }),
      h("pre", { class: "code", text: cap.model_thinking })));
  }
  if (isLive && cap.model_text) kids.push(h("blockquote", { class: "quote", text: cap.model_text }));
  if (cap.tool_calls.length) {
    kids.push(h("pre", { class: "code", text: JSON.stringify(cap.tool_calls.length === 1 ? cap.tool_calls[0] : cap.tool_calls, null, 2) }));
    kids.push(h("div", { class: "hash", text: `sha256 ${cap.calls_sha256}`, title: "Hash of the exact bytes replayed into both backends" }));
  } else if (cap.raw_tool_calls && cap.raw_tool_calls.length) {
    kids.push(h("pre", { class: "code", text: JSON.stringify(cap.raw_tool_calls, null, 2) }));
  }
  kids.push(h("p", { class: "note", text: cap.note }));
  if (isLive && cap.outcome !== "tool_call") {
    kids.push(h("p", { class: "note muted",
      text: "Nothing was replayed, because there is no tool call. Run demo (fixture) shows the deterministic fixture instead." }));
  }
  kids.push(liveRunsTable());
  root.replaceChildren(...kids.filter(Boolean));
}

// ---- network map

const NODE_W = 136, NODE_H = 56;
const POS = { customers: [76, 46], app: [285, 46], db: [494, 46], ws: [76, 158], hub: [285, 158] };

const ICONS = {
  customers: () => [s("circle", { cx: 7, cy: 6, r: 3.5 }), s("path", { d: "M0 18c0-5 3-7 7-7s7 2 7 7" }),
                    s("circle", { cx: 16, cy: 7, r: 2.6 }), s("path", { d: "M17 12c3 0 5 2 5 6" })],
  app: () => [s("rect", { x: 0, y: 1, width: 22, height: 17, rx: 2 }), s("path", { d: "M0 6h22M3 3.6h.1M6 3.6h.1" })],
  db: () => [s("ellipse", { cx: 11, cy: 4, rx: 9, ry: 3.2 }), s("path", { d: "M2 4v12c0 1.8 4 3.2 9 3.2s9-1.4 9-3.2V4M2 10c0 1.8 4 3.2 9 3.2s9-1.4 9-3.2" })],
  ws: () => [s("rect", { x: 0, y: 1, width: 22, height: 14, rx: 2 }), s("path", { d: "M7 19h8M11 15v4" })],
  hub: () => [s("circle", { cx: 11, cy: 10, r: 9 }), s("path", { d: "M5 10h12M11 4v12M7 6l8 8M15 6l-8 8" })],
};

function edge(a, b, cls, label) {
  const [x1, y1] = POS[a], [x2, y2] = POS[b];
  const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
  const parts = [s("line", { class: `edge ${cls}`, x1, y1, x2, y2 })];
  if (cls === "severed") {
    parts.push(s("g", { class: "cut", transform: `translate(${mx} ${my})` },
      s("circle", { r: 9 }), s("path", { d: "M-4 -4L4 4M4 -4L-4 4" })));
  } else if (label) {
    parts.push(s("text", { class: `edge-label ${cls === "fail" ? "bad" : ""}`, x: mx, y: my - 6, text: label }));
  }
  return parts;
}

function node(worldName, key, name, cls, status) {
  const [cx, cy] = POS[key];
  const id = `${worldName}:${key}`;
  const changed = lastNodeClass[id] !== undefined && lastNodeClass[id] !== cls;
  lastNodeClass[id] = cls;
  return s("g", { class: `node ${cls} ${changed ? "changed" : ""}` },
    s("rect", { x: cx - NODE_W / 2, y: cy - NODE_H / 2, width: NODE_W, height: NODE_H, rx: 10 }),
    s("g", { class: "icon", transform: `translate(${cx - 58} ${cy - 10})` }, ICONS[key]()),
    s("text", { class: "name", x: cx - 28, y: cy - 3, text: name }),
    s("text", { class: "status", x: cx - 28, y: cy + 14, text: status }));
}

function renderMap(name, world) {
  const db = endpoint(world, "prod-db-01");
  const ws = endpoint(world, "workstation-17");
  const online = world.app.status === "online";
  const dbCut = db.network_status === "isolated";
  const wsCut = ws.network_status === "isolated";
  return s("svg", { class: "map", viewBox: "0 0 570 192", role: "img",
                    "aria-label": `${name} world: app ${world.app.status}, prod-db-01 ${db.network_status}, workstation-17 ${ws.network_status}` },
    edge("customers", "app", online ? "ok" : "fail", online ? "HTTP 200" : "HTTP 503"),
    edge("app", "db", dbCut ? "severed" : "ok", "SQL"),
    edge("hub", "db", dbCut ? "severed" : "", ""),
    edge("ws", "hub", wsCut ? "severed" : (ws.compromised ? "threat" : ""), ws.compromised ? "attacker" : ""),
    node(name, "customers", "Customers", online ? "" : "down", online ? "BEING SERVED" : "GETTING ERRORS"),
    node(name, "app", world.app.name + " app", online ? "ok" : "down", online ? "ONLINE" : "OFFLINE"),
    node(name, "db", db.hostname, dbCut ? "down" : "ok", dbCut ? "ISOLATED" : "HEALTHY"),
    node(name, "ws", ws.hostname, wsCut ? "contained" : "threat", wsCut ? "ISOLATED" : "COMPROMISED"),
    node(name, "hub", "Corp network", "", "10.0.0.0/8"));
}

function badgeFor(auth) {
  if (auth.outcome === "denied") return ["denied", "DENIED"];
  if (auth.outcome === "rejected") return ["rejected", "REJECTED"];
  return auth.authorization_checked ? ["approved", "EXECUTED · APPROVED"] : ["exec-noauth", "EXECUTED · NO AUTH CHECK"];
}

function verdict(name, world, decisions) {
  const online = world.app.status === "online";
  const wsCut = endpoint(world, "workstation-17").network_status === "isolated";
  if (!decisions.length) return ["", "Waiting for a tool call."];
  if (!online) {
    return ["bad", `Outage. The customer app is offline${wsCut ? "." : " and the compromised workstation is still connected."}`];
  }
  if (name === "vulnerable") {
    const ran = decisions.some((d) => d.detail.authorization.outcome === "executed");
    return ran ? ["bad", "Executed with no authorization check. Any well-formed call would have run."]
               : ["", "Nothing executed."];
  }
  if (wsCut) return ["good", "Contained. workstation-17 is isolated with analyst approval; the app is still online."];
  return ["good", "Blocked. No trusted approval exists for that target, so nothing changed."];
}

function renderWorld(name, world) {
  const decisions = decisionsFor(name);
  const ws = endpoint(world, "workstation-17");
  const online = world.app.status === "online";
  const wsCut = ws.network_status === "isolated";
  const [vClass, vText] = verdict(name, world, decisions);
  return h("article", { class: `world ${name}` },
    h("header", { class: "world-head" },
      h("h2", { text: name === "vulnerable" ? "Vulnerable backend" : "Protected backend" }),
      h("span", { class: "world-rule", text: name === "vulnerable"
        ? "Runs any well-formed tool call"
        : "Runs only with a server-side approval for this incident, action and endpoint" })),
    renderMap(name, world),
    h("div", { class: "tiles" },
      h("div", { class: `tile ${online ? "good" : "bad"}` },
        h("div", { class: "k", text: "Customer app" }),
        h("div", { class: "v", text: online ? "ONLINE" : "OFFLINE" }),
        h("div", { class: "d", text: `HTTP ${world.app.http_status} · ${world.app.detail}` })),
      h("div", { class: `tile ${wsCut ? "info" : "bad"}` },
        h("div", { class: "k", text: "Compromised workstation" }),
        h("div", { class: "v", text: wsCut ? "ISOLATED" : "CONNECTED" }),
        h("div", { class: "d", text: wsCut ? "Cut off from the network" : "Attacker still has network access" }))),
    h("div", { class: `verdict ${vClass}`, text: vText }),
    h("ul", { class: "decisions" }, decisions.map((ev) => {
      const auth = ev.detail.authorization;
      const [cls, label] = badgeFor(auth);
      const target = ev.detail.target.hostname || ev.detail.target.requested;
      return h("li", {},
        h("span", { class: `badge ${cls}`, text: label }),
        h("div", {},
          h("div", { class: "what", text: `quarantine_endpoint → ${target}` }),
          h("div", { class: "why", text: auth.reason })),
        h("button", { class: "btn tiny", type: "button", text: "Inspect event", onclick: () => openDrawer(ev.event_id) }));
    })));
}

function renderReplay() {
  $("#replay").replaceChildren(
    renderWorld("vulnerable", state.worlds.vulnerable),
    renderWorld("protected", state.worlds.protected));
}

function renderAnalyst() {
  const wsCut = endpoint(state.worlds.protected, "workstation-17").network_status === "isolated";
  const kids = [
    h("p", { class: "analyst-copy",
      text: `You are ${state.analyst}. An approval is a server-side record; nothing written in a log or produced by the model can create one.` }),
    h("button", { class: "btn approve", type: "button", disabled: busy || wsCut, onclick: approveWorkstation,
      text: wsCut ? "✓ workstation-17 quarantined" : "✓ Approve workstation quarantine" }),
    h("p", { class: "binding" }, "Approval is bound to ",
      h("b", { text: state.incident.incident_id }), " · ", h("b", { text: "quarantine_endpoint" }), " · ",
      h("b", { text: "ep-ws-0017" }), " (workstation-17). It then runs through the protected backend only."),
  ];
  if (state.approvals.length) {
    kids.push(h("table", { class: "grid" },
      h("thead", {}, h("tr", {}, ["Approval", "Endpoint", "Granted", "Status"].map((t) => h("th", { text: t })))),
      h("tbody", {}, state.approvals.map((a) => h("tr", {},
        h("td", { text: a.approval_id }),
        h("td", { text: `${a.endpoint_id} (${a.hostname || "?"})` }),
        h("td", { text: clock(a.created_at) }),
        h("td", { class: a.status === "used" ? "val-good" : "", text: a.status }))))));
  } else {
    kids.push(h("p", { class: "small muted", text: "No approvals on record." }));
  }
  $("#analyst").replaceChildren(...kids);
}

function renderTimeline() {
  const list = $("#timeline");
  list.replaceChildren(...state.events.map((ev) =>
    h("li", { onclick: () => openDrawer(ev.event_id) },
      h("span", { class: "ts", text: clock(ev.ts) }),
      h("span", { class: `lane ${ev.lane}`, text: ev.lane }),
      h("div", {},
        h("div", { class: "title", text: ev.title }),
        h("div", { class: "sum", text: ev.summary })),
      h("button", { class: "btn tiny", type: "button", text: "Inspect event",
                    onclick: (e) => { e.stopPropagation(); openDrawer(ev.event_id); } }))));
  list.scrollTop = list.scrollHeight;
}

// ------------------------------------------------------------------- drawer

function kv(rows) {
  return h("table", { class: "kv" }, h("tbody", {}, rows.filter(Boolean).map(([k, v, cls]) =>
    h("tr", {}, h("th", { text: k }), h("td", { class: cls || "", text: v === null || v === undefined || v === "" ? "—" : String(v) })))));
}

function stateTable(before, after) {
  const rows = after.endpoints.map((ep) => {
    const prev = before ? before.endpoints.find((e) => e.endpoint_id === ep.endpoint_id).network_status : null;
    return [`${ep.hostname} (${ep.endpoint_id})`, prev, ep.network_status];
  });
  rows.push([`${after.app.name} app`, before ? before.app.status : null, after.app.status]);
  return h("table", { class: "grid" },
    h("thead", {}, h("tr", {}, [after.world + " world", before ? "Before" : null, before ? "After" : "State"]
      .filter((t) => t !== null).map((t) => h("th", { text: t })))),
    h("tbody", {}, rows.map(([name, prev, now]) => h("tr", {},
      h("td", { text: name }),
      before && h("td", { text: prev }),
      h("td", { class: before && prev !== now ? "changed-cell" : "", text: now })))));
}

function renderDrawer(ev) {
  const d = ev.detail;
  const sections = [];
  const section = (title, ...kids) => sections.push(h("section", {}, h("h3", { text: title }), kids));

  if (!d.error && (d.source_log !== undefined || d.source_note)) {
    section("Source log",
      d.source_log && d.source_log.length
        ? h("ul", { class: "log" }, d.source_log.map((e) =>
            h("li", { class: e.attacker_controlled ? "injected" : "" },
              h("span", { class: "ts", text: clock(e.ts) }),
              h("span", { class: "src", text: e.source }),
              h("span", { class: "txt" },
                e.attacker_controlled && h("span", { class: "tag attack", text: "attacker-controlled" }), e.text))))
        : null,
      h("p", { class: "note", text: d.source_note || "" }));
  }
  if (d.target) {
    section("Target", kv([
      ["Requested", d.target.requested],
      ["Canonical endpoint ID", d.target.canonical_endpoint_id],
      ["Hostname", d.target.hostname],
      ["Role", d.target.role],
    ]));
  }
  if (d.proposed_action) {
    const pa = d.proposed_action;
    section("Proposed action",
      kv([["Origin", pa.origin_label], ["Capture", pa.capture_id], ["sha256 of replayed call", pa.calls_sha256]]),
      pa.tool_calls && pa.tool_calls.length
        ? h("pre", { class: "code", text: JSON.stringify(pa.tool_calls.length === 1 ? pa.tool_calls[0] : pa.tool_calls, null, 2) })
        : h("p", { class: "note muted", text: "No tool call was proposed." }));
  }
  if (d.error) {
    section("Request failure",
      kv([["Provider", d.error.provider], ["Model requested", d.error.model_requested]]),
      h("div", { class: "error-box", text: d.error.message }),
      h("p", { class: "note", text: d.source_note || "" }));
  }
  if (d.model) {
    section("Model output",
      kv([["Provider", d.model.provider], ["Log sent", d.model.scenario],
          ["Model requested", d.model.model_requested], ["Model that answered", d.model.model_served],
          ["Stop reason", d.model.stop_reason],
          ["Duration", d.model.duration_s ? `${d.model.duration_s}s` : null]]),
      d.model.model_thinking ? h("details", { class: "thinking" },
        h("summary", { text: "Model reasoning, as returned by the model" }),
        h("pre", { class: "code", text: d.model.model_thinking })) : null,
      d.model.model_text ? h("blockquote", { class: "quote", text: d.model.model_text })
                         : h("p", { class: "note muted", text: "The model returned no text." }));
  }
  if (d.authorization) {
    const a = d.authorization;
    const good = a.outcome === "denied" || a.code === "approved";
    section("Authorization decision", kv([
      ["Backend", a.backend],
      ["Decision", `${a.outcome.toUpperCase()} (${a.code})`, good ? "val-good" : "val-bad"],
      ["Reason", a.reason],
      ["Authorization checked", a.authorization_checked ? "yes" : "no — this backend has no check", a.authorization_checked ? "" : "val-bad"],
      a.checked && ["Approval looked up for", `${a.checked.incident_id} · ${a.checked.action} · ${a.checked.endpoint_id}`],
      ["Approval used", a.approval_id ? `${a.approval_id} (${a.approved_by})` : "none"],
      ["Untrusted extra fields ignored", a.ignored_fields && a.ignored_fields.length ? a.ignored_fields.join(", ") : "none"],
    ]));
  }
  if (d.approval) {
    const a = d.approval;
    section("Approval record (server-side)", kv([
      ["Approval ID", a.approval_id], ["Incident", a.incident_id], ["Action", a.action],
      ["Endpoint", a.endpoint_id], ["Approved by", a.approved_by], ["Expires", a.expires_at],
    ]));
  }
  if (d.resulting_state) {
    const rs = d.resulting_state;
    section("Resulting state", rs.endpoints
      ? stateTable(d.state_before || null, rs)
      : Object.values(rs).map((w) => stateTable(null, w)));
  }

  $("#drawer").replaceChildren(
    h("div", { class: "drawer-head" },
      h("h2", { text: ev.title }),
      h("button", { class: "btn tiny", type: "button", text: "Close ✕", onclick: closeDrawer })),
    h("div", { class: "when" }, h("span", { class: `lane ${ev.lane}`, text: ev.lane }), `event #${ev.event_id} · ${ev.ts}`),
    h("p", { text: ev.summary }),
    ...sections);
}

function openDrawer(eventId) {
  const ev = state.events.find((e) => e.event_id === eventId);
  if (!ev) return;
  openEventId = eventId;
  renderDrawer(ev);
  $("#drawer").hidden = false;
  $("#scrim").hidden = false;
  $("#drawer").scrollTop = 0;
}

function closeDrawer() {
  openEventId = null;
  $("#drawer").hidden = true;
  $("#scrim").hidden = true;
}

// --------------------------------------------------------------------- boot

$("#btn-run").addEventListener("click", () => runDemo("fixture"));
$("#btn-live-poisoned").addEventListener("click", () => runDemo("live", "poisoned"));
$("#btn-live-clean").addEventListener("click", () => runDemo("live", "clean"));
$("#btn-reset").addEventListener("click", resetDemo);
$("#scrim").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

refresh().catch((err) => toast(err.message));

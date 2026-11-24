/* AI tool guard UI. Like app.js: every dynamic string is inserted as a text node (createElement /
   textContent), never as markup. Documents, arguments and tool descriptions are attacker-controlled. */
(function () {
  "use strict";
  var TOKEN = (document.querySelector('meta[name="demo-token"]') || {}).content || "";
  var $ = function (s, r) { return (r || document).querySelector(s); };

  function h(tag, attrs) {
    var el = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "class") el.className = attrs[k]; else el.setAttribute(k, attrs[k]);
    });
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c == null) continue;
      (Array.isArray(c) ? c : [c]).forEach(function (x) {
        if (x != null) el.appendChild(typeof x === "string" ? document.createTextNode(x) : x);
      });
    }
    return el;
  }
  function clear(el) { while (el && el.firstChild) el.removeChild(el.firstChild); }
  function api(path, opts) {
    opts = opts || {};
    var init = { method: opts.method || "GET", headers: { "X-Demo-Token": TOKEN } };
    if (opts.body !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(opts.body); }
    return fetch(path, init).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) throw new Error((j.error && j.error.message) || j.detail || ("Request failed (" + r.status + ")"));
        return j;
      });
    });
  }
  function chip(decision) {
    var cls = { BLOCK: "bad", ASK: "warn", ALLOW: "ok" }[decision] || "";
    return h("span", { "class": "chip " + cls }, decision === "UNGUARDED" ? "NO GUARD" : decision);
  }
  function refresh() { document.body.dispatchEvent(new Event("approvals-changed")); }

  /* ---------- live alerts (server-sent events) ---------- */
  var seen = {};
  function toast(e) {
    var box = $("#guard-alerts");
    if (!box || seen[e.id]) return;
    seen[e.id] = true;
    var cls = e.level === "block" ? "bad" : e.level === "ask" ? "warn" : "info";
    var close = h("button", { "class": "icon-btn", type: "button", "aria-label": "Dismiss" }, "×");
    var actions = h("div", { "class": "row-btns" });
    if (e.approval_id) {
      actions.appendChild(h("a", { "class": "btn small primary", href: "/guard/approvals" }, "Review"));
    }
    if (e.session_id) actions.appendChild(h("a", { "class": "small", href: "/guard/session/" + encodeURIComponent(e.session_id) }, "Attack trail →"));
    var card = h("div", { "class": "alert " + cls, role: "alert" },
      h("div", { "class": "alert-head" }, h("strong", {}, e.title || "Guard alert"), close),
      h("p", {}, e.message || ""), actions);
    close.addEventListener("click", function () { card.remove(); });
    box.insertBefore(card, box.firstChild);
    while (box.children.length > 3) box.removeChild(box.lastChild);
    setTimeout(function () { card.classList.add("fade"); }, 14000);
    setTimeout(function () { card.remove(); }, 15000);
  }
  if (window.EventSource && document.body.getAttribute("data-page") !== null) {
    var startAt = Date.now() / 1000;
    var es = new EventSource("/api/v1/guard/stream");
    es.addEventListener("alert", function (m) {
      try { var e = JSON.parse(m.data); if (e.ts >= startAt - 2) toast(e); } catch (err) { /* ignore */ }
    });
  }

  /* ---------- header buttons ---------- */
  var vb = $("#guard-verify");
  if (vb) vb.addEventListener("click", function () {
    var out = $("#guard-verify-out");
    api("/api/v1/guard/audit/verify").then(function (r) {
      out.hidden = false;
      out.className = "chip " + (r.ok ? "ok" : "bad");
      out.textContent = r.ok ? ("Audit chain intact · " + r.checked + " entries") : ("Audit chain BROKEN at row " + r.broken_id);
    }, function (e) { out.hidden = false; out.className = "chip bad"; out.textContent = e.message; });
  });
  var rb = $("#guard-reset");
  if (rb) rb.addEventListener("click", function () {
    if (!window.confirm("Clear guard sessions, calls and approvals? The audit log is kept.")) return;
    api("/api/v1/guard/reset", { method: "POST" }).then(function () { window.location.reload(); });
  });

  /* ---------- approvals ---------- */
  document.addEventListener("click", function (ev) {
    var t = ev.target.closest ? ev.target.closest("[data-approve],[data-deny],[data-approve-tool]") : null;
    if (!t) return;
    t.disabled = true;
    if (t.hasAttribute("data-approve-tool")) {
      api("/api/v1/guard/tools/" + encodeURIComponent(t.getAttribute("data-approve-tool")) + "/approve", { method: "POST" })
        .then(function () { window.location.reload(); }, function (e) { window.alert(e.message); t.disabled = false; });
      return;
    }
    var id = t.getAttribute("data-approve") || t.getAttribute("data-deny");
    api("/api/v1/guard/approvals/" + encodeURIComponent(id), { method: "POST", body: { approve: t.hasAttribute("data-approve") } })
      .then(refresh, function (e) { window.alert(e.message); refresh(); });
  });

  /* ---------- what-if tester ---------- */
  var wf = $("#whatif");
  if (wf) wf.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var out = $("#whatif-out"), args;
    clear(out); out.hidden = false;
    try { args = JSON.parse(wf.args.value || "{}"); } catch (e) { out.appendChild(h("p", { "class": "error" }, "Arguments must be JSON.")); return; }
    api("/api/v1/guard/evaluate", { method: "POST", body: { role: wf.role.value, taint: wf.taint.value, tool: wf.tool.value, args: args } })
      .then(function (r) {
        out.appendChild(h("p", {}, chip(r.decision), " ", r.explanation || r.reason));
        if (r.matched_rules.length) out.appendChild(h("p", { "class": "small muted" }, "Policy rules matched: " + r.matched_rules.join(", ")));
        out.appendChild(h("ul", { "class": "findings" }, r.findings.map(function (f) {
          return h("li", {}, h("span", { "class": "sev " + f.severity }, f.severity), h("span", { "class": "rule" }, f.rule_id), f.message);
        })));
        out.appendChild(h("p", { "class": "small muted" }, "Decided in " + r.latency_ms.toFixed(2) + " ms"));
      }, function (e) { out.appendChild(h("p", { "class": "error" }, e.message)); });
  });

  /* ---------- side-by-side demo ---------- */
  function renderSide(prefix, r) {
    var tx = $("#" + prefix + "-tx"); clear(tx);
    (r.transcript || []).forEach(function (t) {
      var args = Object.keys(t.args).map(function (k) { return k + "=" + String(t.args[k]).slice(0, 60); }).join(", ");
      var li = h("li", { "class": "tx-" + t.decision.toLowerCase() },
        h("div", { "class": "step-head" }, chip(t.decision), h("span", { "class": "mono strong" }, t.tool),
          h("span", { "class": "mono small muted" }, args)),
        h("p", { "class": "small muted" }, t.why === "user task" ? "Requested by the user" : "Because the content told the assistant to"));
      if (t.explanation && (t.decision === "BLOCK" || t.decision === "ASK")) li.appendChild(h("p", { "class": "small" }, t.explanation));
      tx.appendChild(li);
    });
    var v = $("#" + prefix + "-verdict"); clear(v);
    v.appendChild(r.leaked ? h("span", { "class": "chip bad" }, "DATA LEAKED via " + r.leak_channels.join(", "))
                           : h("span", { "class": "chip ok" }, "Nothing leaked"));
    $("#" + prefix + "-sink").textContent = (r.sink_events || []).length ? r.sink_events.map(function (e) {
      return "[" + e.channel + "] " + (e.to || e.url || e.tool || "") + "\n" + String(e.body || e.notes || "").slice(0, 400);
    }).join("\n\n") : "(nothing arrived)";
  }
  var df = $("#demo-form");
  if (df) df.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var btn = df.querySelector("button"), err = $("#demo-error");
    btn.disabled = true; err.hidden = true;
    api("/api/v1/guard/demo", { method: "POST", body: { scenario: df.scenario.value, mode: "both" } })
      .then(function (r) {
        $("#demo-split").hidden = false;
        renderSide("off", r.off); renderSide("on", r.on);
        $("#on-trail").setAttribute("href", "/guard/session/" + encodeURIComponent(r.on.session_id));
      }, function (e) { err.textContent = e.message; err.hidden = false; })
      .then(function () { btn.disabled = false; });
  });
})();

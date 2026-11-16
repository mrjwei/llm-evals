// The offline rating pack (Plan P6.6): the Rate page in one file, for a
// rater without the app. Built by `cjp rating export-pack`; the data comes
// from the JSON block above. Every string from a log or a model is set as
// textContent, never as HTML. Scores autosave in this browser
// (localStorage) and leave as a downloaded JSON for `cjp rating import`.
(function () {
  "use strict";
  var PACK = JSON.parse(document.getElementById("pack-data").textContent);
  var ITEMS = ["R1", "R2", "R3", "R4", "R5"];
  var FIELDS = [
    ["disposition", "Disposition"], ["severity", "Severity"], ["technique_label", "Technique"],
    ["candidate_labels", "Could be"], ["confidence", "Confidence"], ["recommended_action", "Recommended action"],
    ["event_type", "What happened"], ["reasoning", "Reasoning"], ["evidence", "Evidence"], ["cognitive_notes", "Context"]
  ];
  var WORDS = { escalate: "Escalate", needs_more_info: "Needs more info", dismiss_false_positive: "Dismiss (false positive)" };
  var app = document.getElementById("app");
  var state = null;      // {rater, started_at, updated_at, ratings}
  var pos = 0;
  var storageOk = true;

  function key(rater) { return "cjp-rating:" + PACK.batch + ":" + rater; }
  function now() { return new Date().toISOString().replace(/\.\d+Z$/, "Z"); }
  function load(rater) {
    try { var s = localStorage.getItem(key(rater)); return s ? JSON.parse(s) : null; } catch (e) { storageOk = false; return null; }
  }
  function persist() {
    try { localStorage.setItem(key(state.rater), JSON.stringify(state)); localStorage.setItem(key("last"), state.rater); }
    catch (e) { storageOk = false; }
  }
  function lastRater() { try { return localStorage.getItem(key("last")); } catch (e) { return null; } }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") node.textContent = attrs[k];
      else if (k === "on") Object.keys(attrs.on).forEach(function (ev) { node.addEventListener(ev, attrs.on[ev]); });
      else if (k in node && typeof node[k] === "boolean") node[k] = attrs[k];
      else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c) node.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return node;
  }
  function clear() { while (app.firstChild) app.removeChild(app.firstChild); }

  function order() { return PACK.orders[state.rater]; }
  function isComplete(r) { return !!r && ITEMS.every(function (k) { return r[k] !== undefined && r[k] !== null; }); }
  function doneCount() { return order().filter(function (id) { return isComplete(state.ratings[id]); }).length; }
  function firstOpen() { var o = order(); for (var i = 0; i < o.length; i++) if (!isComplete(state.ratings[o[i]])) return i; return -1; }

  function download() {
    var doc = { schema_version: PACK.schema_version, batch: PACK.batch, rater: state.rater,
                rubric: { version: PACK.rubric.version, sha256: PACK.rubric.sha256 },
                started_at: state.started_at, updated_at: state.updated_at, via: "pack", ratings: state.ratings };
    var blob = new Blob([JSON.stringify(doc, null, 2) + "\n"], { type: "application/json" });
    var a = el("a", { href: URL.createObjectURL(blob), download: PACK.batch + "_rater-" + state.rater + ".json" });
    document.body.appendChild(a); a.click(); a.remove();
  }

  // ── start: choose your rater ID ──
  function startScreen() {
    clear();
    var n = Object.keys(PACK.items).length;
    app.appendChild(el("h1", { text: "Rating pack · " + PACK.batch }));
    app.appendChild(el("p", { class: "muted", text: n + " items, one per screen. The first " + PACK.calibration.length +
      " are the calibration round, done together and not analysed. You see each alert and the triage answer only." }));
    app.appendChild(el("p", { text: "Your scores are saved in this browser as you go. When you finish, or to send what you have, press “Download ratings” and send that file back to the researcher." }));
    app.appendChild(el("h2", { text: "Who is rating?" }));
    var bar = el("div", { class: "bar" });
    ["A", "B"].forEach(function (r) {
      var saved = load(r);
      var label = "Rater " + r + (saved ? " · continue (" + Object.keys(saved.ratings || {}).filter(function (id) { return isComplete(saved.ratings[id]); }).length + " done)" : "");
      bar.appendChild(el("button", { class: r === lastRater() ? "primary" : "", text: label, on: { click: function () { begin(r); } } }));
    });
    app.appendChild(bar);
    if (!storageOk) app.appendChild(el("p", { class: "warn", text: "This browser can’t save here. Download your ratings often, or open the file in another browser." }));
  }

  function begin(rater) {
    state = load(rater) || { rater: rater, started_at: now(), updated_at: null, ratings: {} };
    persist();
    var open = firstOpen();
    pos = open < 0 ? 0 : open;
    open < 0 ? doneScreen() : itemScreen();
  }

  // ── one item ──
  function rows(obj) {
    var dl = el("dl");
    FIELDS.forEach(function (f) {
      var v = obj[f[0]];
      if (v === undefined || v === null || v === "" || (Array.isArray(v) && !v.length)) return;
      var text = Array.isArray(v) ? v.join(", ") : (f[0] === "disposition" ? (WORDS[v] || v) : String(v));
      dl.appendChild(el("div", { class: "row" }, [el("dt", { text: f[1] }), el("dd", { class: /label|evidence/.test(f[0]) ? "mono" : /severity|confidence/.test(f[0]) ? "cap" : "", text: text })]));
    });
    return dl;
  }

  function alertCard(item) {
    var a = item.alert || {}, rule = a.rule || {};
    var card = el("section", { class: "card", "aria-label": "Alert" }, [
      el("h2", { text: rule.description || "(no rule description)" }),
      el("p", { class: "muted", text: "Wazuh rule " + (rule.id || "?") + " · level " + (rule.level === undefined ? "?" : rule.level) + (a.timestamp ? " · " + a.timestamp : "") })
    ]);
    if (a.full_log) card.appendChild(el("pre", { text: a.full_log }));
    var body = item.body || {};
    if (body.request_body) card.appendChild(el("details", {}, [el("summary", { text: "Request body" }), el("pre", { text: body.request_body })]));
    if (body.response_body) card.appendChild(el("details", {}, [el("summary", { text: "Response body" }), el("pre", { text: body.response_body })]));
    if (!body.request_body && !body.response_body) card.appendChild(el("p", { class: "muted", text: "No request or response body came with this alert." }));
    card.appendChild(el("details", {}, [el("summary", { text: "Raw alert" }), el("pre", { text: JSON.stringify(a, null, 2) })]));
    return card;
  }

  function rubricForm(id) {
    var record = state.ratings[id] || {};
    var form = el("form", { "aria-label": "Rubric", on: { submit: function (e) { e.preventDefault(); } } });
    var savedNote = el("p", { class: "saved", text: record.saved_at ? "Saved." : "" });
    PACK.rubric.items.forEach(function (spec) {
      var fs = el("fieldset", {}, [el("legend", { text: spec.id + " · " + spec.name }), el("p", { class: "muted", text: spec.question })]);
      var grid = el("div", { class: spec.options ? "choices" : "scale" });
      var options = spec.options || [];
      if (!spec.options) for (var v = spec.scale[0]; v <= spec.scale[1]; v++) options.push({ value: v, label: String(v), anchor: (spec.anchors || {})[String(v)] });
      options.forEach(function (o) {
        var input = el("input", { type: "radio", name: spec.id, value: String(o.value), checked: record[spec.id] === o.value,
          on: { change: function () {
            var r = state.ratings[id] || {};
            r[spec.id] = o.value; r.saved_at = now();
            state.ratings[id] = r; state.updated_at = r.saved_at; persist();
            savedNote.textContent = storageOk ? "Saved." : "Not saved in this browser: download your ratings.";
            nav.querySelector("[data-next]").textContent = nextLabel();
          } } });
        grid.appendChild(el("label", { class: "opt" }, [input, el("span", {}, [el("b", { text: o.label }), o.anchor ? el("small", { text: o.anchor }) : null])]));
      });
      fs.appendChild(grid);
      form.appendChild(fs);
    });
    form.appendChild(savedNote);
    var nav = navBar();
    form.appendChild(nav);
    return form;
  }

  function nextLabel() { return pos + 1 < order().length ? "Next" : "Finish"; }

  function navBar() {
    return el("div", { class: "bar" }, [
      el("button", { type: "button", text: "Previous", disabled: pos === 0, on: { click: function () { pos--; itemScreen(); } } }),
      el("span", { class: "spacer" }),
      el("button", { type: "button", text: "First unrated", on: { click: function () { var o = firstOpen(); if (o < 0) doneScreen(); else { pos = o; itemScreen(); } } } }),
      el("button", { type: "button", class: "primary", "data-next": "", text: nextLabel(), on: { click: function () {
        if (pos + 1 < order().length) { pos++; itemScreen(); } else if (firstOpen() < 0) doneScreen(); else { pos = firstOpen(); itemScreen(); }
      } } })
    ]);
  }

  function header() {
    var o = order();
    var id = o[pos];
    var cal = PACK.calibration.indexOf(id) >= 0;
    return el("header", {}, [
      el("div", { class: "bar" }, [
        el("strong", { text: "Item " + (pos + 1) + " of " + o.length }),
        cal ? el("span", { class: "badge cal", text: "Calibration round" }) : null,
        el("span", { class: "muted", text: "Rater " + state.rater + " · " + doneCount() + " done" }),
        el("span", { class: "spacer" }),
        el("button", { type: "button", text: "Download ratings", on: { click: download } })
      ]),
      el("progress", { max: String(o.length), value: String(doneCount()), "aria-label": "Items rated" })
    ]);
  }

  function itemScreen() {
    clear();
    var id = order()[pos];
    var item = PACK.items[id];
    app.appendChild(header());
    app.appendChild(alertCard(item));
    app.appendChild(el("section", { class: "card", "aria-label": "Triage answer" }, [el("h2", { text: "Triage answer" }), rows(item.answer || {})]));
    app.appendChild(el("p", { class: "muted mono", text: "Item " + id }));
    app.appendChild(rubricForm(id));
    if (!storageOk) app.appendChild(el("p", { class: "warn", text: "This browser can’t save here. Download your ratings before closing it." }));
    window.scrollTo(0, 0);
  }

  function doneScreen() {
    clear();
    app.appendChild(header());
    app.appendChild(el("h1", { text: "All " + order().length + " items are rated" }));
    app.appendChild(el("p", { text: "Press “Download ratings” and send the file back to the researcher. You can still go back and change a score; download again afterwards." }));
    app.appendChild(el("div", { class: "bar" }, [
      el("button", { type: "button", class: "primary", text: "Download ratings", on: { click: download } }),
      el("button", { type: "button", text: "Back to the items", on: { click: function () { pos = 0; itemScreen(); } } })
    ]));
  }

  startScreen();
})();

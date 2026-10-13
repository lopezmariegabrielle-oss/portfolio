/* Behavioral NIDS : logique du dashboard.
   Regle de securite : tout texte venant de l'API passe par textContent (jamais innerHTML). */
(function () {
  "use strict";

  var REFRESH_MS = 5000;
  var PAGE = 25;
  var SEV_LABEL = { critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible" };
  var SEV_ORDER = ["critical", "high", "medium", "low"];

  var $ = function (id) { return document.getElementById(id); };
  var state = { limit: PAGE, points: [], hover: -1 };

  function getJSON(url) {
    return fetch(url, { headers: { Accept: "application/json" } }).then(function (r) {
      if (!r.ok) { throw new Error("HTTP " + r.status); }
      return r.json();
    });
  }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text !== undefined && text !== null) { n.textContent = text; }
    return n;
  }

  function fmtInt(n) { return Number(n).toLocaleString("fr-FR"); }

  function fmtTime(iso) {
    var d = new Date(iso);
    if (isNaN(d)) { return "—"; }
    return d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function setStatus(text, isErr) {
    var s = $("status");
    s.textContent = text;
    s.classList.toggle("err", !!isErr);
  }

  /* ------------------------------------------------------------ cartes */
  function renderStats(s) {
    $("demo-banner").hidden = !s.demo;
    $("v-flows").textContent = fmtInt(s.flows_24h);
    $("s-flows").textContent = "sur les dernières 24 h";
    $("v-alerts").textContent = fmtInt(s.alerts_24h);
    $("s-alerts").textContent = fmtInt(s.alerts_last_hour) + " dans la dernière heure";
    $("v-rate").textContent = s.anomaly_rate.toLocaleString("fr-FR", { maximumFractionDigits: 2 }) + " %";
    if (s.top_source) {
      $("v-top").textContent = s.top_source.ip;
      $("s-top").textContent = fmtInt(s.top_source.count) + " alertes";
    } else {
      $("v-top").textContent = "—";
      $("s-top").textContent = "aucune alerte";
    }
    var chips = $("chips");
    chips.textContent = "";
    SEV_ORDER.forEach(function (sev) {
      var chip = el("span", "chip");
      chip.appendChild(el("span", "dot dot-" + sev));
      chip.appendChild(document.createTextNode(SEV_LABEL[sev] + " "));
      chip.appendChild(el("b", null, fmtInt(s.by_severity[sev] || 0)));
      chips.appendChild(chip);
    });
  }

  /* --------------------------------------------------------- graphique */
  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function drawChart() {
    var cv = $("chart");
    var pts = state.points;
    var dpr = window.devicePixelRatio || 1;
    var w = cv.clientWidth, h = cv.clientHeight;
    if (!w || !h) { return; }
    cv.width = Math.round(w * dpr);
    cv.height = Math.round(h * dpr);
    var ctx = cv.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    var pad = { l: 46, r: 40, t: 10, b: 24 };
    var iw = w - pad.l - pad.r, ih = h - pad.t - pad.b;
    var gold = css("--gold"), crit = css("--crit"), muted = css("--muted"), line = css("--line");
    ctx.font = "11px " + css("--mono");

    if (!pts.length) { return; }
    var maxF = Math.max.apply(null, pts.map(function (p) { return p.flows; })) || 1;
    var maxA = Math.max.apply(null, pts.map(function (p) { return p.anomalies; })) || 1;
    maxF = niceMax(maxF); maxA = Math.ceil(niceMax(maxA) / 4) * 4;  // graduations entieres
    var n = pts.length;
    var step = iw / n;
    function x(i) { return pad.l + step * (i + 0.5); }
    function yF(v) { return pad.t + ih - (v / maxF) * ih; }
    function yA(v) { return pad.t + ih - (v / maxA) * ih; }

    // grille + axes
    ctx.strokeStyle = line; ctx.fillStyle = muted; ctx.lineWidth = 1;
    ctx.textAlign = "right"; ctx.textBaseline = "middle";
    for (var g = 0; g <= 4; g++) {
      var gy = pad.t + (ih * g) / 4;
      ctx.beginPath(); ctx.moveTo(pad.l, gy); ctx.lineTo(pad.l + iw, gy); ctx.stroke();
      ctx.textAlign = "right";
      ctx.fillText(String(Math.round(maxF * (1 - g / 4))), pad.l - 6, gy);
      ctx.textAlign = "left";
      ctx.fillText(String(Math.round(maxA * (1 - g / 4))), pad.l + iw + 6, gy);
    }

    // aire des flux
    ctx.beginPath();
    ctx.moveTo(x(0), pad.t + ih);
    pts.forEach(function (p, i) { ctx.lineTo(x(i), yF(p.flows)); });
    ctx.lineTo(x(n - 1), pad.t + ih);
    ctx.closePath();
    ctx.globalAlpha = 0.18; ctx.fillStyle = gold; ctx.fill(); ctx.globalAlpha = 1;
    ctx.beginPath();
    pts.forEach(function (p, i) { i ? ctx.lineTo(x(i), yF(p.flows)) : ctx.moveTo(x(i), yF(p.flows)); });
    ctx.strokeStyle = gold; ctx.lineWidth = 1.6; ctx.stroke();

    // barres d'anomalies
    var bw = Math.max(1.5, Math.min(8, step * 0.6));
    ctx.fillStyle = crit;
    pts.forEach(function (p, i) {
      if (p.anomalies > 0) {
        var top = yA(p.anomalies);
        ctx.fillRect(x(i) - bw / 2, top, bw, pad.t + ih - top);
      }
    });

    // axe des temps
    ctx.fillStyle = muted; ctx.textBaseline = "top"; ctx.textAlign = "center";
    var labels = Math.min(6, n);
    for (var k = 0; k < labels; k++) {
      var idx = Math.round((k * (n - 1)) / Math.max(1, labels - 1));
      var d = new Date(pts[idx].minute);
      ctx.fillText(d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" }), x(idx), pad.t + ih + 6);
    }

    // repere de survol
    if (state.hover >= 0 && state.hover < n) {
      ctx.strokeStyle = css("--gold-soft"); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(x(state.hover), pad.t); ctx.lineTo(x(state.hover), pad.t + ih); ctx.stroke();
    }
    state.geom = { pad: pad, step: step, n: n };
  }

  function niceMax(v) {
    var p = Math.pow(10, Math.floor(Math.log10(v)));
    var m = v / p;
    var r = m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10;
    return Math.max(4, r * p);
  }

  function onMove(ev) {
    var g = state.geom, tip = $("tooltip");
    if (!g || !state.points.length) { return; }
    var rect = $("chart").getBoundingClientRect();
    var mx = ev.clientX - rect.left;
    var i = Math.floor((mx - g.pad.l) / g.step);
    if (i < 0 || i >= g.n) { leave(); return; }
    state.hover = i;
    var p = state.points[i];
    tip.textContent = fmtTime(p.minute) + " · " + fmtInt(p.flows) + " flux · " + fmtInt(p.anomalies) + " anomalies";
    tip.hidden = false;
    var left = Math.min(mx + 12, rect.width - tip.offsetWidth - 4);
    tip.style.left = Math.max(4, left) + "px";
    tip.style.top = "8px";
    drawChart();
  }

  function leave() {
    state.hover = -1;
    $("tooltip").hidden = true;
    drawChart();
  }

  /* ----------------------------------------------------------- tableau */
  function renderAlerts(data) {
    var body = $("alerts-body");
    body.textContent = "";
    if (!data.items.length) {
      var tr = el("tr");
      var td = el("td", "empty", "Aucune alerte.");
      td.colSpan = 7;
      tr.appendChild(td); body.appendChild(tr);
    }
    data.items.forEach(function (a) {
      var tr = el("tr");
      tr.appendChild(el("td", "mono", fmtTime(a.ts)));
      tr.appendChild(el("td", "mono", a.src_ip));
      tr.appendChild(el("td", "mono", a.dst_ip + (a.dst_port ? ":" + a.dst_port : "")));
      tr.appendChild(el("td", null, a.proto || "—"));

      var sc = el("td");
      var wrap = el("span", "score");
      var bar = el("span", "bar");
      var fill = document.createElement("i");
      fill.style.width = Math.round(a.score * 100) + "%";
      bar.appendChild(fill);
      wrap.appendChild(bar);
      wrap.appendChild(document.createTextNode(a.score.toFixed(2)));
      sc.appendChild(wrap); tr.appendChild(sc);

      var sv = el("td");
      var sev = SEV_LABEL[a.severity] ? a.severity : "low";
      sv.appendChild(el("span", "sev sev-" + sev, SEV_LABEL[sev]));
      tr.appendChild(sv);

      tr.appendChild(el("td", "reason", a.reason || "—"));
      body.appendChild(tr);
    });
    $("alerts-count").textContent = data.items.length + " affichées sur " + fmtInt(data.total);
    $("more").hidden = data.items.length >= data.total || state.limit >= 200;
  }

  /* ------------------------------------------------------- rafraichir */
  function refresh() {
    var minutes = encodeURIComponent($("range").value);
    var sev = $("sev").value;
    var alertsUrl = "/api/alerts?limit=" + state.limit + (sev ? "&severity=" + encodeURIComponent(sev) : "");
    Promise.all([getJSON("/api/stats"), getJSON("/api/traffic?minutes=" + minutes), getJSON(alertsUrl)])
      .then(function (r) {
        renderStats(r[0]);
        state.points = r[1].points;
        drawChart();
        renderAlerts(r[2]);
        setStatus("Mis à jour " + fmtTime(r[0].generated_at));
      })
      .catch(function () { setStatus("API injoignable : nouvelle tentative…", true); });
  }

  $("range").addEventListener("change", refresh);
  $("sev").addEventListener("change", function () { state.limit = PAGE; refresh(); });
  $("more").addEventListener("click", function () { state.limit = Math.min(200, state.limit + PAGE); refresh(); });
  $("chart").addEventListener("mousemove", onMove);
  $("chart").addEventListener("mouseleave", leave);
  window.addEventListener("resize", drawChart);

  refresh();
  setInterval(refresh, REFRESH_MS);
})();

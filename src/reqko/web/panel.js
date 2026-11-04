"use strict";
/* ph-reqKO stats panel: fetches the read-only API and draws charts on <canvas>.
   No external libraries, no CDN, no inline scripts (CSP: script-src 'self'). */

(function () {
  var TOKEN_KEY = "reqko_token";
  var REFRESH_MS = 10000;
  var MAX_BARS = 8;

  var state = { bucket: "hour", timer: null };

  function el(id) {
    return document.getElementById(id);
  }

  function getToken() {
    return window.sessionStorage.getItem(TOKEN_KEY);
  }

  function showError(id, message) {
    var node = el(id);
    node.textContent = message; // textContent: API data is never injected as HTML
    node.hidden = false;
  }

  function clearError(id) {
    var node = el(id);
    node.hidden = true;
    node.textContent = "";
  }

  function showTokenGate(message) {
    el("dashboard").hidden = true;
    el("token-gate").hidden = false;
    var error = el("token-error");
    if (message) {
      error.textContent = message;
      error.hidden = false;
    } else {
      error.hidden = true;
    }
  }

  function showDashboard() {
    el("token-gate").hidden = true;
    el("dashboard").hidden = false;
  }

  function apiFetch(path) {
    return fetch(path, { headers: { Authorization: "Bearer " + getToken() } }).then(
      function (resp) {
        if (resp.status === 401) {
          window.sessionStorage.removeItem(TOKEN_KEY);
          var err = new Error("unauthorized");
          err.unauthorized = true;
          throw err;
        }
        if (!resp.ok) {
          throw new Error("HTTP " + resp.status + " for " + path);
        }
        return resp.json();
      }
    );
  }

  function cssVar(name, fallback) {
    var value = window.getComputedStyle(document.documentElement).getPropertyValue(name);
    return value.trim() || fallback;
  }

  function prepareCanvas(canvas) {
    var ratio = window.devicePixelRatio || 1;
    var width = canvas.clientWidth || 640;
    var height = canvas.clientHeight || 240;
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    var ctx = canvas.getContext("2d");
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    return { ctx: ctx, width: width, height: height };
  }

  /* ── summary tiles ─────────────────────────────────────────────────────── */

  function renderSummary(data) {
    el("tile-total").textContent = String(data.total_queries);
    el("tile-blocked").textContent = data.blocked_percentage + "%";
    el("tile-cache").textContent = data.cache_hit_percentage + "%";
    el("tile-latency").textContent =
      data.avg_latency_ms === null ? "–" : data.avg_latency_ms + " ms";
  }

  /* ── time series line chart (total vs blocked) ─────────────────────────── */

  function drawTimeseries(series) {
    clearError("error-timeseries");
    var canvas = el("chart-timeseries");
    var prepared = prepareCanvas(canvas);
    var ctx = prepared.ctx;
    var w = prepared.width;
    var h = prepared.height;
    ctx.clearRect(0, 0, w, h);

    var points = series.map(function (row) {
      return {
        label: String(row.bucket).slice(state.bucket === "hour" ? 11 : 5),
        total: row.total_queries,
        blocked: row.blocked_queries,
      };
    });
    if (points.length === 0) {
      ctx.fillStyle = cssVar("--muted", "#888");
      ctx.fillText("No data yet — send some DNS queries", 16, 28);
      return;
    }

    var max = 1;
    points.forEach(function (p) {
      max = Math.max(max, p.total, p.blocked);
    });

    var padLeft = 44;
    var padBottom = 34;
    var padTop = 12;
    var plotW = w - padLeft - 12;
    var plotH = h - padBottom - padTop;

    // grid + y labels
    ctx.strokeStyle = cssVar("--border", "#ddd");
    ctx.fillStyle = cssVar("--muted", "#888");
    ctx.font = "11px system-ui";
    ctx.textAlign = "left";
    for (var g = 0; g <= 4; g++) {
      var gy = padTop + plotH - (plotH * g) / 4;
      ctx.beginPath();
      ctx.moveTo(padLeft, gy);
      ctx.lineTo(padLeft + plotW, gy);
      ctx.stroke();
      ctx.fillText(String(Math.round((max * g) / 4)), 6, gy + 4);
    }

    function xAt(i) {
      return padLeft + (plotW * i) / Math.max(points.length - 1, 1);
    }
    function yAt(value) {
      return padTop + plotH - (plotH * value) / max;
    }

    function drawLine(key, color) {
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.beginPath();
      points.forEach(function (p, i) {
        if (i === 0) ctx.moveTo(xAt(i), yAt(p[key]));
        else ctx.lineTo(xAt(i), yAt(p[key]));
      });
      ctx.stroke();
    }

    drawLine("total", cssVar("--accent", "#2f6fed"));
    drawLine("blocked", cssVar("--blocked", "#d64545"));

    // Point markers keep single-bucket data visible (a lone line segment
    // has zero length and would render as nothing)
    points.forEach(function (p, i) {
      [
        ["total", cssVar("--accent", "#2f6fed")],
        ["blocked", cssVar("--blocked", "#d64545")],
      ].forEach(function (pair) {
        ctx.fillStyle = pair[1];
        ctx.beginPath();
        ctx.arc(xAt(i), yAt(p[pair[0]]), 3, 0, Math.PI * 2);
        ctx.fill();
      });
    });

    // x labels (thin out to ~6)
    ctx.fillStyle = cssVar("--muted", "#888");
    ctx.textAlign = "center";
    var step = Math.ceil(points.length / 6);
    points.forEach(function (p, i) {
      if (i % step === 0) ctx.fillText(p.label, xAt(i), h - 18);
    });

    // legend
    ctx.textAlign = "left";
    ctx.fillStyle = cssVar("--accent", "#2f6fed");
    ctx.fillRect(padLeft, 0, 10, 3);
    ctx.fillText("total", padLeft + 14, 6);
    ctx.fillStyle = cssVar("--blocked", "#d64545");
    ctx.fillRect(padLeft + 60, 0, 10, 3);
    ctx.fillText("blocked", padLeft + 74, 6);
  }

  function refreshTimeseries() {
    return apiFetch("/api/v1/stats/timeseries?bucket=" + state.bucket)
      .then(function (data) {
        drawTimeseries(data.series || []);
      })
      .catch(function (err) {
        if (err.unauthorized) throw err;
        showError("error-timeseries", "Failed to load time series: " + err.message);
      });
  }

  /* ── horizontal bar charts ─────────────────────────────────────────────── */

  function drawBars(canvas, errorId, rows, labelKey, colorVar, fallbackColor) {
    clearError(errorId);
    var prepared = prepareCanvas(canvas);
    var ctx = prepared.ctx;
    var w = prepared.width;
    var h = prepared.height;
    ctx.clearRect(0, 0, w, h);

    var bars = rows.slice(0, MAX_BARS);
    if (bars.length === 0) {
      ctx.fillStyle = cssVar("--muted", "#888");
      ctx.font = "12px system-ui";
      ctx.fillText("No data yet", 16, 28);
      return;
    }

    var max = 1;
    bars.forEach(function (r) {
      max = Math.max(max, r.hits);
    });

    var labelW = Math.min(w * 0.45, 190);
    var rowH = h / bars.length;
    var barH = Math.min(rowH * 0.55, 18);
    ctx.font = "11px system-ui";
    ctx.textBaseline = "middle";

    bars.forEach(function (row, i) {
      var y = i * rowH + rowH / 2;
      // Label is drawn on canvas, truncated to the available width
      var label = String(row[labelKey]);
      while (label.length > 4 && ctx.measureText(label).width > labelW - 8) {
        label = label.slice(0, -2) + "…";
      }
      ctx.fillStyle = cssVar("--text", "#333");
      ctx.textAlign = "left";
      ctx.fillText(label, 4, y);

      var barW = Math.max(2, ((w - labelW - 34) * row.hits) / max);
      ctx.fillStyle = cssVar(colorVar, fallbackColor);
      ctx.fillRect(labelW, y - barH / 2, barW, barH);

      ctx.fillStyle = cssVar("--muted", "#888");
      ctx.textAlign = "left";
      ctx.fillText(String(row.hits), labelW + barW + 4, y);
    });
  }

  function refreshTopDomains() {
    return apiFetch("/api/v1/stats/top-domains?status=blocked")
      .then(function (data) {
        drawBars(
          el("chart-top-domains"),
          "error-top-domains",
          data.domains || [],
          "question_name",
          "--blocked",
          "#d64545"
        );
      })
      .catch(function (err) {
        if (err.unauthorized) throw err;
        showError("error-top-domains", "Failed to load top domains: " + err.message);
      });
  }

  function refreshTopClients() {
    return apiFetch("/api/v1/stats/top-clients")
      .then(function (data) {
        drawBars(
          el("chart-top-clients"),
          "error-top-clients",
          data.clients || [],
          "client_ip",
          "--accent",
          "#2f6fed"
        );
      })
      .catch(function (err) {
        if (err.unauthorized) throw err;
        showError("error-top-clients", "Failed to load top clients: " + err.message);
      });
  }

  /* ── refresh cycle ─────────────────────────────────────────────────────── */

  function refreshAll() {
    return apiFetch("/api/v1/stats/summary")
      .then(function (data) {
        showDashboard();
        clearError("global-error");
        el("refresh-status").textContent =
          "auto-refresh every " + REFRESH_MS / 1000 + " s · updated " +
          new Date().toLocaleTimeString();
        renderSummary(data);
        return Promise.allSettled([refreshTimeseries(), refreshTopDomains(), refreshTopClients()]);
      })
      .catch(function (err) {
        if (err.unauthorized) {
          showTokenGate("Token rejected or expired. Please enter it again.");
          return;
        }
        el("dashboard").hidden = false;
        var globalError = el("global-error");
        globalError.textContent = "Network error: " + err.message;
        globalError.hidden = false;
      });
  }

  function startRefreshCycle() {
    if (state.timer !== null) {
      window.clearInterval(state.timer);
    }
    state.timer = window.setInterval(refreshAll, REFRESH_MS);
  }

  /* ── wiring ────────────────────────────────────────────────────────────── */

  function setBucket(bucket) {
    state.bucket = bucket;
    el("btn-hour").className = bucket === "hour" ? "active" : "";
    el("btn-day").className = bucket === "day" ? "active" : "";
    refreshTimeseries();
  }

  function init() {
    el("token-form").addEventListener("submit", function (event) {
      event.preventDefault();
      var token = el("token-input").value.trim();
      if (!token) {
        showTokenGate("Please enter a token.");
        return;
      }
      window.sessionStorage.setItem(TOKEN_KEY, token);
      el("token-input").value = "";
      refreshAll().then(function () {
        if (!el("token-gate").hidden) {
          window.sessionStorage.removeItem(TOKEN_KEY);
        } else {
          startRefreshCycle();
        }
      });
    });

    el("btn-hour").addEventListener("click", function () {
      setBucket("hour");
    });
    el("btn-day").addEventListener("click", function () {
      setBucket("day");
    });

    if (getToken()) {
      refreshAll().then(function () {
        if (el("token-gate").hidden) {
          startRefreshCycle();
        }
      });
    } else {
      showTokenGate("");
    }
  }

  function boot() {
    try {
      init();
    } catch (err) {
      var globalError = el("global-error");
      globalError.textContent = "Panel failed to initialize: " + err;
      globalError.hidden = false;
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    // DOMContentLoaded may already have fired (e.g. late deferred execution)
    boot();
  }
})();

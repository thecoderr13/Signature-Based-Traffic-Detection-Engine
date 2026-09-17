// Shared utilities used by every page. Nothing here is page-specific —
// per-page behaviour lives in ingest.js / signatures.js / detections.js /
// report.js, each of which calls into `Sentinel.*` below.
const Sentinel = (() => {
  async function api(path, options = {}) {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    let body = null;
    try {
      body = await res.json();
    } catch (_) {
      /* no body */
    }
    if (!res.ok) {
      const message = (body && body.error) || `${res.status} ${res.statusText}`;
      throw new Error(message);
    }
    return body;
  }

  function fmtTime(iso) {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour12: false });
  }

  function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  }

  function protoLabel(p) {
    if (typeof p === "string") return p;
    if (p && typeof p === "object" && "Other" in p) return `PROTO ${p.Other}`;
    return String(p);
  }

  function verdictBadge(verdict) {
    const map = {
      Benign: { icon: "i-check-circle", label: "Benign" },
      Suspicious: { icon: "i-alert-triangle", label: "Suspicious" },
      Malicious: { icon: "i-x-circle", label: "Malicious" },
    };
    const v = map[verdict] || map.Benign;
    return `<span class="badge ${verdict.toLowerCase()}"><svg class="icon"><use href="/icons.svg#${v.icon}"/></svg>${v.label}</span>`;
  }

  function iocTypeLabel(type) {
    const labels = { Ip: "IP", Domain: "Domain", Url: "URL", Sha256: "SHA-256" };
    return labels[type] || type;
  }

  function iocTypeBadge(type) {
    const icons = { Ip: "i-server", Domain: "i-external", Url: "i-external", Sha256: "i-hash" };
    return `<span class="badge neutral"><svg class="icon"><use href="/icons.svg#${icons[type] || "i-hash"}"/></svg>${iocTypeLabel(type)}</span>`;
  }

  function escapeHtml(s) {
    if (s === null || s === undefined) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // ---- shared top status pills -----------------------------------------
  async function refreshStatus() {
    const el = document.getElementById("status-pills");
    if (!el) return;
    try {
      const s = await api("/api/status");
      el.innerHTML = `
        <span class="pill"><span class="dot ${s.flow_count ? "ready" : ""}"></span>Flows <strong>${s.flow_count}</strong></span>
        <span class="pill"><span class="dot ${s.signature_count ? "ready" : ""}"></span>Signatures <strong>${s.signature_count}</strong>${s.signatures_offline ? " (offline)" : ""}</span>
        <span class="pill"><span class="dot ${s.detection_count ? "ready" : ""}"></span>Detections <strong>${s.detection_count}</strong></span>
        <span class="pill"><span class="dot ${s.auth_key_configured ? "ready" : ""}"></span>${s.auth_key_configured ? "Auth-Key configured" : "No Auth-Key (offline mode)"}</span>
      `;
    } catch (e) {
      el.innerHTML = `<span class="pill muted">status unavailable</span>`;
    }
    return el;
  }

  // ---- live pipeline console (SSE) --------------------------------------
  let sseStarted = false;
  const listeners = [];

  function onEvent(fn) {
    listeners.push(fn);
  }

  function startEventStream() {
    if (sseStarted) return;
    sseStarted = true;
    const source = new EventSource("/api/events");
    source.addEventListener("pipeline", (e) => {
      const evt = JSON.parse(e.data);
      listeners.forEach((fn) => fn(evt));
    });
    source.onerror = () => {
      // EventSource retries automatically; nothing to do here.
    };
  }

  function mountConsole(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const rows = [];
    const render = () => {
      if (rows.length === 0) {
        container.innerHTML = `<div class="console-empty">No pipeline activity yet in this session — actions on any page will appear here as they happen.</div>`;
        return;
      }
      container.innerHTML = rows
        .slice(-200)
        .map(
          (evt) => `
        <div class="console-row">
          <span class="t">${fmtTime(evt.timestamp)}</span>
          <span class="stage">${evt.stage}</span>
          <span class="lvl ${evt.level.toLowerCase()}">${evt.level}</span>
          <span class="msg">${escapeHtml(evt.message)}</span>
        </div>`
        )
        .join("");
      container.scrollTop = container.scrollHeight;
    };
    render();
    onEvent((evt) => {
      rows.push(evt);
      render();
    });
    startEventStream();
  }

  function highlightNav() {
    const page = document.body.dataset.page;
    if (!page) return;
    document.querySelectorAll(".nav-step").forEach((a) => {
      if (a.dataset.page === page) a.classList.add("active");
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    highlightNav();
    refreshStatus();
    startEventStream();
  });

  return {
    api,
    fmtTime,
    fmtBytes,
    protoLabel,
    verdictBadge,
    iocTypeBadge,
    iocTypeLabel,
    escapeHtml,
    refreshStatus,
    mountConsole,
    onEvent,
  };
})();

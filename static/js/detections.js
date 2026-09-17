(() => {
  const runBtn = document.getElementById("run-detect");
  const prereqHint = document.getElementById("prereq-hint");
  const tableWrap = document.getElementById("detections-table-wrap");
  const filterTabs = document.getElementById("filter-tabs");
  const drawer = document.getElementById("drawer");
  const drawerBackdrop = document.getElementById("drawer-backdrop");
  const drawerBody = document.getElementById("drawer-body");
  const drawerBadge = document.getElementById("drawer-badge");
  const drawerFlow = document.getElementById("drawer-flow");
  const drawerClose = document.getElementById("drawer-close");

  let allDetections = [];
  let activeFilter = "all";

  async function checkPrereqs() {
    const s = await Sentinel.api("/api/status");
    const missing = [];
    if (!s.flow_count) missing.push("ingest a capture");
    if (!s.signature_count) missing.push("fetch signatures");
    runBtn.disabled = missing.length > 0;
    prereqHint.textContent = missing.length ? `First: ${missing.join(", then ")}.` : "";
  }

  async function runDetection() {
    runBtn.disabled = true;
    try {
      await Sentinel.api("/api/detect", { method: "POST" });
      await loadDetections();
      Sentinel.refreshStatus();
    } catch (e) {
      tableWrap.innerHTML = `<div class="empty-state">Detection failed: ${Sentinel.escapeHtml(e.message)}</div>`;
    } finally {
      runBtn.disabled = false;
    }
  }

  async function loadDetections() {
    const { detections } = await Sentinel.api("/api/detections");
    allDetections = detections;
    render();
  }

  function render() {
    const rows = activeFilter === "all" ? allDetections : allDetections.filter((d) => d.verdict === activeFilter);
    if (rows.length === 0) {
      tableWrap.innerHTML = `<div class="empty-state"><svg class="icon"><use href="/icons.svg#i-detections"/></svg><div>${allDetections.length ? "No flows match this filter." : "Run detection to see verdicts here."}</div></div>`;
      return;
    }
    tableWrap.innerHTML = `
      <table>
        <thead>
          <tr><th>Verdict</th><th>Source</th><th>Destination</th><th>Proto</th><th>Hostname</th><th>Detail</th></tr>
        </thead>
        <tbody>
          ${rows
            .map(
              (d, i) => `
            <tr data-idx="${allDetections.indexOf(d)}" style="cursor:pointer">
              <td>${Sentinel.verdictBadge(d.verdict)}</td>
              <td class="mono">${d.flow.src_ip}:${d.flow.src_port}</td>
              <td class="mono">${d.flow.dst_ip}:${d.flow.dst_port}</td>
              <td>${Sentinel.protoLabel(d.flow.protocol)}</td>
              <td>${d.flow.hostname ? Sentinel.escapeHtml(d.flow.hostname) : '<span class="faint">—</span>'}</td>
              <td class="muted">${d.reasons[0] ? Sentinel.escapeHtml(truncate(d.reasons[0], 60)) : "—"}</td>
            </tr>`
            )
            .join("")}
        </tbody>
      </table>`;

    tableWrap.querySelectorAll("tbody tr").forEach((tr) => {
      tr.addEventListener("click", () => openDrawer(allDetections[Number(tr.dataset.idx)]));
    });
  }

  function truncate(s, n) {
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }

  function openDrawer(d) {
    drawerBadge.innerHTML = Sentinel.verdictBadge(d.verdict);
    drawerFlow.textContent = `${d.flow.src_ip}:${d.flow.src_port} → ${d.flow.dst_ip}:${d.flow.dst_port}`;

    let html = `
      <dl class="kv">
        <dt>Protocol</dt><dd>${Sentinel.protoLabel(d.flow.protocol)}</dd>
        <dt>Hostname</dt><dd>${d.flow.hostname ? Sentinel.escapeHtml(d.flow.hostname) : "—"}</dd>
        <dt>URL</dt><dd>${d.flow.url ? Sentinel.escapeHtml(d.flow.url) : "—"}</dd>
        <dt>Packets</dt><dd>${d.flow.packet_count}</dd>
        <dt>Bytes</dt><dd>${Sentinel.fmtBytes(d.flow.byte_count)}</dd>
        <dt>Payload SHA-256</dt><dd style="font-size:11px">${d.flow.payload_sha256 ? Sentinel.escapeHtml(d.flow.payload_sha256) : "—"}</dd>
      </dl>`;

    if (d.reasons && d.reasons.length) {
      html += `<div class="section-label">Why</div><ul class="reason-list">${d.reasons.map((r) => `<li>${Sentinel.escapeHtml(r)}</li>`).join("")}</ul>`;
    }

    if (d.matched_signature) {
      const sig = d.matched_signature;
      html += `
        <div class="section-label">Matched indicator</div>
        <dl class="kv">
          <dt>Type</dt><dd>${Sentinel.iocTypeLabel(sig.ioc_type)}</dd>
          <dt>Value</dt><dd>${Sentinel.escapeHtml(sig.value)}</dd>
          <dt>Source</dt><dd>${Sentinel.escapeHtml(sig.source)}</dd>
          <dt>Malware</dt><dd>${sig.malware ? Sentinel.escapeHtml(sig.malware) : "—"}</dd>
          <dt>Threat type</dt><dd>${sig.threat_type ? Sentinel.escapeHtml(sig.threat_type) : "—"}</dd>
          <dt>Confidence</dt><dd>${sig.confidence !== null && sig.confidence !== undefined ? sig.confidence + "%" : "—"}</dd>
        </dl>`;
    }

    if (d.ips_action) {
      html += `
        <div class="section-label">Simulated IPS action</div>
        <div class="callout warn"><svg class="icon"><use href="/icons.svg#i-block"/></svg><div class="mono">${Sentinel.escapeHtml(d.ips_action)}</div></div>`;
    }

    drawerBody.innerHTML = html;
    drawer.classList.add("open");
    drawerBackdrop.classList.add("open");
  }

  function closeDrawer() {
    drawer.classList.remove("open");
    drawerBackdrop.classList.remove("open");
  }

  filterTabs.addEventListener("click", (e) => {
    const btn = e.target.closest(".filter-tab");
    if (!btn) return;
    filterTabs.querySelectorAll(".filter-tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    activeFilter = btn.dataset.filter;
    render();
  });

  runBtn.addEventListener("click", runDetection);
  drawerClose.addEventListener("click", closeDrawer);
  drawerBackdrop.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDrawer();
  });

  checkPrereqs();
  loadDetections();
  Sentinel.mountConsole("console");
})();

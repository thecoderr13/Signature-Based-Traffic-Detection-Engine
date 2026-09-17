(() => {
  const fetchBtn = document.getElementById("fetch-btn");
  const sourceSelect = document.getElementById("source-select");
  const forceRefresh = document.getElementById("force-refresh");
  const summary = document.getElementById("sig-summary");
  const tableWrap = document.getElementById("sig-table-wrap");
  const keyCallout = document.getElementById("key-callout");
  const PAGE_SIZE = 25;
  let currentPage = 1;
  let currentRows = [];

  function summarizeCounts(rows, keyFn) {
    const counts = {};
    rows.forEach((row) => {
      const key = keyFn(row);
      counts[key] = (counts[key] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }

  function renderSummaryCards(s) {
    const typeCounts = summarizeCounts(s.signatures || [], (sig) => sig.ioc_type);
    const sourceCounts = summarizeCounts(s.signatures || [], (sig) => sig.source || "Unknown");

    const renderList = (items, formatter) => {
      if (!items.length) return '<div class="summary-empty">No entries</div>';
      return items
        .map(([name, count]) => `<div class="summary-pill"><span class="summary-key">${formatter(name)}</span><strong>${count}</strong></div>`)
        .join("");
    };

    return `
      <div class="summary-grid">
        <div class="mini-metric">
          <span class="label">Type breakdown</span>
          <div class="summary-list">${renderList(typeCounts, (name) => Sentinel.iocTypeLabel(name))}</div>
        </div>
        <div class="mini-metric">
          <span class="label">Source breakdown</span>
          <div class="summary-list">${renderList(sourceCounts, (name) => Sentinel.escapeHtml(name))}</div>
        </div>
      </div>
    `;
  }

  function renderPageControls(totalRows) {
    const totalPages = Math.max(1, Math.ceil(totalRows / PAGE_SIZE));
    if (totalRows <= PAGE_SIZE) {
      return `<div class="pagination"><span>Page 1 of 1</span></div>`;
    }

    const canPrev = currentPage > 1;
    const canNext = currentPage < totalPages;
    return `
      <div class="pagination">
        <button class="btn" ${canPrev ? "" : "disabled"} data-page-action="prev">Previous</button>
        <span>Page ${currentPage} of ${totalPages}</span>
        <button class="btn" ${canNext ? "" : "disabled"} data-page-action="next">Next</button>
      </div>
    `;
  }

  function renderTable() {
    const totalRows = currentRows.length;
    const totalPages = Math.max(1, Math.ceil(totalRows / PAGE_SIZE));
    currentPage = Math.min(currentPage, totalPages);
    const start = (currentPage - 1) * PAGE_SIZE;
    const rows = currentRows.slice(start, start + PAGE_SIZE);

    const html = `
      ${renderSummaryCards({ signatures: currentRows })}
      <div class="table-shell">
        <table>
          <thead>
            <tr><th>Type</th><th>Value</th><th>Source</th><th>Malware</th><th>Threat type</th></tr>
          </thead>
          <tbody>
            ${rows
              .map(
                (sig) => `
              <tr>
                <td>${Sentinel.iocTypeBadge(sig.ioc_type)}</td>
                <td class="mono">${Sentinel.escapeHtml(sig.value)}</td>
                <td>${Sentinel.escapeHtml(sig.source || "Unknown")}</td>
                <td class="muted">${sig.malware ? Sentinel.escapeHtml(sig.malware) : "—"}</td>
                <td class="muted">${sig.threat_type ? Sentinel.escapeHtml(sig.threat_type) : "—"}</td>
              </tr>`
              )
              .join("")}
          </tbody>
        </table>
      </div>
      ${renderPageControls(totalRows)}
    `;

    tableWrap.innerHTML = html;

    tableWrap.querySelectorAll("[data-page-action]").forEach((button) => {
      button.addEventListener("click", () => {
        const action = button.dataset.pageAction;
        if (action === "prev") currentPage = Math.max(1, currentPage - 1);
        if (action === "next") currentPage = Math.min(totalPages, currentPage + 1);
        renderTable();
      });
    });
  }

  async function checkAuthKey() {
    const s = await Sentinel.api("/api/status");
    if (!s.auth_key_configured) {
      keyCallout.innerHTML = `
        <div class="callout warn" style="margin-top:14px">
          <svg class="icon"><use href="/icons.svg#i-alert-triangle"/></svg>
          <div>No <code class="mono">ABUSECH_AUTH_KEY</code> is configured, so ThreatFox/URLhaus
          requests will automatically fall back to the bundled offline sample set. Get a free
          key at <a href="https://auth.abuse.ch/" target="_blank" rel="noopener">auth.abuse.ch</a>
          and set it in <code class="mono">.env</code> to pull live indicators.</div>
        </div>`;
    } else {
      keyCallout.innerHTML = "";
    }
  }

  async function doFetch() {
    fetchBtn.disabled = true;
    try {
      await Sentinel.api("/api/signatures/fetch", {
        method: "POST",
        body: JSON.stringify({ source: sourceSelect.value, force: forceRefresh.checked }),
      });
      await loadSignatures();
      Sentinel.refreshStatus();
    } catch (e) {
      summary.textContent = `Fetch failed: ${e.message}`;
    } finally {
      fetchBtn.disabled = false;
    }
  }

  async function loadSignatures() {
    const s = await Sentinel.api("/api/signatures");
    if (!s.loaded) {
      summary.textContent = "Not fetched yet";
      tableWrap.innerHTML = `
        <div class="empty-state">
          <svg class="icon"><use href="/icons.svg#i-signatures"/></svg>
          <div>Fetch a signature set to see loaded indicators here.</div>
        </div>
      `;
      return;
    }

    const rows = s.signatures || s.sample || [];
    currentRows = rows;
    currentPage = 1;

    const sourceBits = Object.entries(s.source_counts || {})
      .map(([name, count]) => `${name}: ${count}`)
      .join(" · ");
    const typeBits = Object.entries(s.type_counts || {})
      .map(([name, count]) => `${name}: ${count}`)
      .join(" · ");
    summary.textContent = `${s.total} IOCs — sources: ${sourceBits || "none"} — types: ${typeBits || "none"} — fetched ${Sentinel.fmtTime(s.fetched_at)}${s.offline ? " (offline sample)" : ""}`;

    renderTable();
  }

  fetchBtn.addEventListener("click", doFetch);

  checkAuthKey();
  loadSignatures();
  Sentinel.mountConsole("console");
})();

(() => {
  const select = document.getElementById("pcap-select");
  const runBtn = document.getElementById("run-ingest");
  const refreshBtn = document.getElementById("refresh-list");
  const fileInput = document.getElementById("file-input");
  const uploadLabel = document.getElementById("upload-label");
  const noPcapsHint = document.getElementById("no-pcaps-hint");
  const summary = document.getElementById("flow-summary");
  const tableWrap = document.getElementById("flow-table-wrap");

  async function loadPcapList(selectName) {
    const { pcaps } = await Sentinel.api("/api/pcaps");
    select.innerHTML = pcaps.map((p) => `<option value="${Sentinel.escapeHtml(p)}">${Sentinel.escapeHtml(p)}</option>`).join("");
    noPcapsHint.hidden = pcaps.length > 0;
    runBtn.disabled = pcaps.length === 0;
    if (selectName && pcaps.includes(selectName)) {
      select.value = selectName;
    }
  }

  async function runIngest() {
    if (!select.value) return;
    runBtn.disabled = true;
    try {
      const result = await Sentinel.api("/api/ingest", {
        method: "POST",
        body: JSON.stringify({ filename: select.value }),
      });
      summary.textContent = `${result.flow_count} flows from ${result.parsed_packet_count}/${result.packet_count} packets — ${result.filename}`;
      await loadFlows();
      Sentinel.refreshStatus();
    } catch (e) {
      summary.textContent = `Ingestion failed: ${e.message}`;
    } finally {
      runBtn.disabled = false;
    }
  }

  async function loadFlows() {
    const { flows } = await Sentinel.api("/api/flows");
    if (flows.length === 0) {
      tableWrap.innerHTML = `<div class="empty-state"><svg class="icon"><use href="/icons.svg#i-ingest"/></svg><div>Run ingestion to see assembled flows here.</div></div>`;
      return;
    }
    tableWrap.innerHTML = `
      <table>
        <thead>
          <tr><th>Source</th><th>Destination</th><th>Proto</th><th>Hostname</th><th>URL</th><th>Packets</th><th>Bytes</th></tr>
        </thead>
        <tbody>
          ${flows
            .map(
              (f) => `
            <tr>
              <td class="mono">${f.src_ip}:${f.src_port}</td>
              <td class="mono">${f.dst_ip}:${f.dst_port}</td>
              <td>${Sentinel.protoLabel(f.protocol)}</td>
              <td>${f.hostname ? Sentinel.escapeHtml(f.hostname) : '<span class="faint">—</span>'}</td>
              <td class="mono">${f.url ? Sentinel.escapeHtml(f.url) : '<span class="faint">—</span>'}</td>
              <td class="mono">${f.packet_count}</td>
              <td class="mono">${Sentinel.fmtBytes(f.byte_count)}</td>
            </tr>`
            )
            .join("")}
        </tbody>
      </table>`;
  }

  runBtn.addEventListener("click", runIngest);
  refreshBtn.addEventListener("click", () => loadPcapList(select.value));

  fileInput.addEventListener("change", async () => {
    const file = fileInput.files[0];
    if (!file) return;
    uploadLabel.textContent = `Uploading ${file.name}…`;
    const form = new FormData();
    form.append("file", file, file.name);
    try {
      const res = await fetch("/api/pcaps/upload", { method: "POST", body: form });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || "upload failed");
      uploadLabel.textContent = `Uploaded ${body.filename}`;
      await loadPcapList(body.filename);
    } catch (e) {
      uploadLabel.textContent = `Upload failed: ${e.message}`;
    }
  });

  loadPcapList();
  loadFlows();
  Sentinel.mountConsole("console");
})();

(() => {
  const statRow = document.getElementById("stat-row");
  const bars = document.getElementById("bars");
  const maliciousCount = document.getElementById("malicious-count");
  const maliciousWrap = document.getElementById("malicious-wrap");

  function bar(label, count, total, cls) {
    const pct = total > 0 ? (count / total) * 100 : 0;
    const width = count > 0 ? Math.max(6, pct) : 0;
    return `
      <div class="bar-row">
        <span class="bar-label">${label}</span>
        <span class="bar-track"><span class="bar-fill ${cls}" style="width:${width}%"></span></span>
        <span class="bar-count mono muted">${count}</span>
      </div>`;
  }

  async function load() {
    const r = await Sentinel.api("/api/report");
    const total = r.total_flows;

    statRow.innerHTML = `
      <div class="stat"><div class="value">${total}</div><div class="label">Flows analyzed</div></div>
      <div class="stat"><div class="value">${r.malicious}</div><div class="label">Malicious</div></div>
      <div class="stat"><div class="value">${r.suspicious}</div><div class="label">Suspicious</div></div>
      <div class="stat"><div class="value">${r.benign}</div><div class="label">Benign</div></div>
      <div class="stat"><div class="value">${r.signature_total}</div><div class="label">Indicators loaded</div></div>
    `;

    bars.innerHTML =
      bar("Malicious", r.malicious, total, "malicious") +
      bar("Suspicious", r.suspicious, total, "suspicious") +
      bar("Benign", r.benign, total, "benign");

    const malicious = r.detections.filter((d) => d.verdict === "Malicious");
    maliciousCount.textContent = r.pcap_file ? `${malicious.length} of ${total} flows — ${r.pcap_file}` : `${malicious.length} of ${total} flows`;

    if (malicious.length === 0) {
      maliciousWrap.innerHTML = `<div class="empty-state"><svg class="icon"><use href="/icons.svg#i-check-circle"/></svg><div>No malicious flows in the current report.</div></div>`;
      return;
    }

    maliciousWrap.innerHTML = `
      <table>
        <thead><tr><th>Source</th><th>Destination</th><th>Matched on</th><th>Malware</th><th>IPS action</th></tr></thead>
        <tbody>
          ${malicious
            .map(
              (d) => `
            <tr>
              <td class="mono">${d.flow.src_ip}:${d.flow.src_port}</td>
              <td class="mono">${d.flow.dst_ip}:${d.flow.dst_port}</td>
              <td>${d.matched_signature ? Sentinel.escapeHtml(d.matched_signature.value) : "—"}</td>
              <td class="muted">${d.matched_signature && d.matched_signature.malware ? Sentinel.escapeHtml(d.matched_signature.malware) : "—"}</td>
              <td class="mono muted" style="font-size:11.5px">${Sentinel.escapeHtml(d.ips_action || "—")}</td>
            </tr>`
            )
            .join("")}
        </tbody>
      </table>`;
  }

  load();
})();

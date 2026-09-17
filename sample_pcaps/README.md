# Sample captures

This directory holds `.pcap` files Sentinel can ingest. It starts empty on a
fresh clone; populate it one of these ways:

1. **Generate the bundled demo capture (no network, no root):**
   ```
   cargo run --bin gen-sample-pcap
   ```
   Writes `demo-traffic.pcap` — a handful of benign, suspicious, and
   malicious flows built from scratch. Its "malicious" addresses are
   documentation-only IPs (RFC 5737) paired with indicators already present
   in `data/sample_iocs.json`, so a full offline run produces real verdicts.

2. **Capture your own traffic** (as the assignment suggests — curl a few
   known-bad domains from your chosen feed's IOC list, plus a few benign
   ones — then capture with `tcpdump` or `tshark`):
   ```
   sudo tcpdump -i any -w sample_pcaps/my-capture.pcap
   # in another terminal: curl the sites you want captured, then Ctrl-C tcpdump
   ```
   Only the classic pcap format is supported. If your tool produces
   `.pcapng`, convert it first:
   ```
   tshark -F pcap -r my-capture.pcapng -w sample_pcaps/my-capture.pcap
   ```

3. **Upload through the dashboard** — the Ingest page has a file picker that
   saves into `data/uploads/` and lists alongside anything in this folder.

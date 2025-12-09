import tkinter as tk
from tkinter import filedialog, scrolledtext
import pyshark
from datetime import datetime
import re

# TTL extraction helper
def extract_ttls(pkt):
    ttl = getattr(pkt.dns, 'resp_ttl', None)
    if ttl is not None:
        if isinstance(ttl, list):
            return [int(t) for t in ttl if str(t).isdigit()]
        return [int(ttl)] if str(ttl).isdigit() else []
    # scan all fields for TTLs
    ttls = []
    for f in pkt.dns._all_fields:
        name = getattr(f, 'showname_key', '') or getattr(f, 'name', '')
        if 'ttl' in name.lower() or 'time to live' in getattr(f, 'showname', '').lower():
            val = getattr(f, 'show', None)
            if val and str(val).isdigit():
                ttls.append(int(val))
    return ttls

# Analyzer function
def analyze_pcap(file_path):
    cap = pyshark.FileCapture(file_path, display_filter='dns')
    query_log = {}
    anomalies = {}

    for packet in cap:
        try:
            domain = getattr(packet.dns, 'resp_name', None) or getattr(packet.dns, 'qry_name', None)
            ips = []
            a_ip = getattr(packet.dns, 'a', None)
            if a_ip: ips.append(a_ip)
            aaaa_ip = getattr(packet.dns, 'aaaa', None)
            if aaaa_ip: ips.append(aaaa_ip)

            ttls = extract_ttls(packet)

            # response code (NXDOMAIN, SERVFAIL, etc.)
            rcode = getattr(packet.dns, 'flags_rcode', None)
            qtype = getattr(packet.dns, 'qry_type', None)

            if domain:
                query_log.setdefault(domain, []).append({
                    "ips": tuple(ips) or None,
                    "ttls": ttls or None,
                    "rcode": rcode,
                    "qtype": qtype,
                    "length": int(getattr(packet, 'length', '0'))
                })
        except AttributeError:
            continue

    # anomaly detection
    for domain, entries in query_log.items():
        # repeated queries
        if len(entries) > 3:
            anomalies.setdefault(domain, []).append(f"Repeated queries ({len(entries)} times)")

        # multiple IPs
        all_ips = {ip for e in entries if e["ips"] for ip in e["ips"]}
        if len(all_ips) > 1:
            anomalies.setdefault(domain, []).append(f"Multiple IPs: {all_ips}")

        # short TTLs
        for e in entries:
            ttls = e["ttls"]
            if ttls:
                min_ttl = min(ttls)
                if min_ttl < 60:
                    anomalies.setdefault(domain, []).append(f"Short TTL (min={min_ttl}s)")

        # NXDOMAIN responses
        nxdomain_count = sum(1 for e in entries if e["rcode"] == "3")
        if nxdomain_count > 0:
            anomalies.setdefault(domain, []).append(f"NXDOMAIN responses ({nxdomain_count} times)")

        # unusual query types
        unusual_qtypes = [e["qtype"] for e in entries if e["qtype"] not in ("1", "28")]  # 1=A, 28=AAAA
        if unusual_qtypes:
            anomalies.setdefault(domain, []).append(f"Unusual query types: {set(unusual_qtypes)}")

        # excessive subdomains
        subdomains = {d for d in [domain] if d and "." in d}
        if len(subdomains) > 10:  # threshold
            anomalies.setdefault(domain, []).append(f"Excessive subdomain queries ({len(subdomains)} unique)")

        # large responses
        large_responses = [e["length"] for e in entries if e["length"] > 512]
        if large_responses:
            anomalies.setdefault(domain, []).append(f"Large DNS responses detected (sizes: {large_responses})")

        # suspicious domain patterns
        if domain and (len(domain) > 50 or re.match(r"^[a-z0-9]{20,}\.", domain)):
            anomalies.setdefault(domain, []).append("Suspicious domain pattern (very long or random string)")

        # repeated errors (SERVFAIL = rcode 2)
        servfail_count = sum(1 for e in entries if e["rcode"] == "2")
        if servfail_count > 0:
            anomalies.setdefault(domain, []).append(f"SERVFAIL errors ({servfail_count} times)")

    # report formatting
    report_lines = []
    report_lines.append("=== Forensic Report ===")
    report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    if not anomalies:
        report_lines.append("No anomalies detected.")
    else:
        for domain, issues in anomalies.items():
            report_lines.append(f"Domain: {domain}")
            for issue in issues:
                report_lines.append(f"  - {issue}")
            report_lines.append("")  # blank line for readability

    return "\n".join(report_lines)

# GUI setup
def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcapng *.pcap")])
    if file_path:
        report = analyze_pcap(file_path)
        text_box.delete(1.0, tk.END)
        text_box.insert(tk.END, report)

root = tk.Tk()
root.title("DNS Forensic Analyzer")

open_button = tk.Button(root, text="Open PCAP File", command=open_file)
open_button.pack(pady=10)

text_box = scrolledtext.ScrolledText(root, width=100, height=40)
text_box.pack(padx=10, pady=10)

root.mainloop()

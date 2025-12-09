import pyshark
from collections import defaultdict

from report_writer import generate_report, save_report

cap = pyshark.FileCapture('sample2.pcapng', display_filter='dns')

query_log = defaultdict(list)

for packet in cap:
    try:
        domain = packet.dns.qry_name
        ip = getattr(packet.dns, 'a', None)
        ttl = int(getattr(packet.dns, 'ttl', '0'))

        query_log[domain].append((ip, ttl))

    except AttributeError:
        continue

# Detection Logic

anomalies = {}

for domain, entries in query_log.items():
    ips = set(ip for ip, _ in entries if ip)
    ttls = [ttl for _, ttl in entries]

    if len(entries) > 3:
        anomalies.setdefault(domain, []).append(f"Repeated queries ({len(entries)} times)")

    if len(ips) > 1:
        anomalies.setdefault(domain, []).append(f"Resolved to multiple IPs: {ips}")

    if any(ttl < 60 for ttl in ttls):
        anomalies.setdefault(domain, []).append(f"Unusually short TTLs: {ttls}")

report = generate_report(anomalies)
save_report(report)
print(report)  # optional: show in terminal


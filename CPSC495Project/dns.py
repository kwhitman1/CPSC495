import pyshark

cap = pyshark.FileCapture('sample2.pcapng', display_filter='dns')

for i, packet in enumerate(cap):
    if i >= 10:
        break
    try:
        print(f"[DNS] Query: {packet.dns.qry_name} | Type: {packet.dns.qry_type} | Response: {packet.dns.a}")
    except AttributeError:
        print("[DNS] Incomplete or malformed DNS packet.")

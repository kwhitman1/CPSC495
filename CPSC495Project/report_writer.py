from datetime import datetime

def generate_report(anomalies):
    report = []
    report.append("=== Forensic Report ===")
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    for domain, issues in anomalies.items():
        report.append(f"Domain: {domain}")
        for issue in issues:
            report.append(f"  - {issue}")
        report.append("")  # blank line between domains

    return "\n".join(report)

def save_report(report, filename="forensic_report.txt"):
    with open(filename, "w") as f:
        f.write(report)

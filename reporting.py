def generate_report(findings):
    report = "Penetration Test Report\n"
    report += "=======================\n"
    for finding in findings:
        report += f"- {finding}\n"
    return report

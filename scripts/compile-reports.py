#!/usr/bin/env python3
"""
LibreLeak Report Compiler
Aggregates multiple scan reports into researcher-friendly summaries and presentations.

Usage:
    python compile-reports.py                    # Compile all reports in /reports
    python compile-reports.py /path/to/reports  # Compile reports from specific directory
    python compile-reports.py --format html     # Generate HTML report
    python compile-reports.py --format md       # Generate Markdown report
"""

import json
import os
import sys
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


class ReportCompiler:
    def __init__(self, reports_dir: Path):
        self.reports_dir = reports_dir
        self.reports = []
        self.findings = []
        self.summary_stats = {}

    def load_reports(self) -> bool:
        """Load all JSON reports from the directory."""
        json_files = list(self.reports_dir.glob("*.json"))

        if not json_files:
            print(f"No JSON report files found in {self.reports_dir}")
            return False

        print(f"Loading {len(json_files)} report files...")

        for json_file in json_files:
            try:
                with open(json_file, "r") as f:
                    report = json.load(f)

                # Handle different report formats
                if "findings" in report:
                    self.reports.append(
                        {
                            "file": json_file.name,
                            "data": report,
                            "findings_count": len(report.get("findings", [])),
                        }
                    )
                    self.findings.extend(report.get("findings", []))
                elif "report" in report and "findings" in report["report"]:
                    # Handle nested format
                    self.reports.append(
                        {
                            "file": json_file.name,
                            "data": report,
                            "findings_count": len(report["report"].get("findings", [])),
                        }
                    )
                    self.findings.extend(report["report"].get("findings", []))
                else:
                    print(f"Warning: Skipping {json_file.name} - unrecognized format")

            except (json.JSONDecodeError, IOError) as e:
                print(f"Error loading {json_file.name}: {e}")
                continue

        print(
            f"Loaded {len(self.reports)} reports with {len(self.findings)} total findings"
        )
        return len(self.findings) > 0

    def generate_summary_stats(self):
        """Generate comprehensive summary statistics."""
        if not self.findings:
            return

        # Initialize summary stats
        self.summary_stats = {}

        # Basic counts
        self.summary_stats["total_reports"] = len(self.reports)
        self.summary_stats["total_findings"] = len(self.findings)
        self.summary_stats["reports_with_findings"] = len(
            [r for r in self.reports if r["findings_count"] > 0]
        )
        self.summary_stats["reports_without_findings"] = len(
            [r for r in self.reports if r["findings_count"] == 0]
        )

        # Findings by rule
        rule_counts = Counter(f.get("rule_id", "unknown") for f in self.findings)
        self.summary_stats["findings_by_rule"] = dict(
            sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)
        )
        self.summary_stats["reports_without_findings"] = len(
            [r for r in self.reports if r["findings_count"] == 0]
        )

        # Findings by rule
        rule_counts = Counter(f.get("rule_id", "unknown") for f in self.findings)
        self.summary_stats["findings_by_rule"] = dict(
            sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)
        )

        # Findings by verification status
        verification_counts = Counter()
        for finding in self.findings:
            if "verification_status" in finding:
                status = finding["verification_status"].get("status", "unknown")
            elif "verification" in finding:
                status = finding["verification"].get("status", "unknown")
            else:
                status = "not_verified"
            verification_counts[status] += 1
        self.summary_stats["findings_by_verification"] = dict(verification_counts)

        # High-value findings (verified active secrets)
        high_value_rules = {
            "openai-api-key",
            "anthropic-api-key",
            "claude-3-api-key",
            "stripe-secret-key",
            "github-pat",
            "aws-access-key-id",
            "stripe-restricted-key",
        }
        high_value_findings = [
            f for f in self.findings if f.get("rule_id") in high_value_rules
        ]
        self.summary_stats["high_value_findings"] = len(high_value_findings)

        # Active high-value secrets
        active_high_value = [
            f
            for f in high_value_findings
            if (
                f.get("verification_status", {}).get("status") == "Active"
                or f.get("verification", {}).get("status") == "Active"
            )
        ]
        self.summary_stats["active_high_value_secrets"] = len(active_high_value)

        # Repository statistics
        repo_domains = Counter()
        for report in self.reports:
            report_data = report["data"]
            if "target" in report_data and report_data["target"]:
                target = report_data["target"]
                if isinstance(target, str) and "://" in target:
                    domain = target.split("://")[1].split("/")[0]
                    repo_domains[domain] += 1
                elif isinstance(target, dict) and "path" in target:
                    path = target["path"]
                    if "github.com" in path:
                        repo_domains["github.com"] += 1
                    elif "gitlab.com" in path:
                        repo_domains["gitlab.com"] += 1
                    elif "codeberg.org" in path:
                        repo_domains["codeberg.org"] += 1

        self.summary_stats["repositories_by_platform"] = dict(
            sorted(repo_domains.items(), key=lambda x: x[1], reverse=True)
        )

        # Time-based analysis
        scan_times = []
        for report in self.reports:
            if "timestamp" in report["data"]:
                try:
                    dt = datetime.fromisoformat(
                        report["data"]["timestamp"].replace("Z", "+00:00")
                    )
                    scan_times.append(dt)
                except:
                    pass

        if scan_times:
            self.summary_stats["scan_period"] = {
                "earliest": min(scan_times).isoformat(),
                "latest": max(scan_times).isoformat(),
                "total_scans": len(scan_times),
            }

    def generate_markdown_report(self) -> str:
        """Generate a comprehensive Markdown report for researchers."""
        if not self.summary_stats:
            self.generate_summary_stats()

        md = []

        # Header
        md.append("# LibreLeak Security Research Report")
        md.append("")
        md.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        md.append(
            f"**Report Period:** {self.summary_stats.get('scan_period', {}).get('earliest', 'Unknown')} to {self.summary_stats.get('scan_period', {}).get('latest', 'Unknown')}"
        )
        md.append("")

        # Executive Summary
        md.append("## Executive Summary")
        md.append("")
        md.append(
            f"- **Total Repositories Scanned:** {self.summary_stats['total_reports']:,}"
        )
        md.append(
            f"- **Repositories with Findings:** {self.summary_stats['reports_with_findings']:,} ({self.summary_stats['reports_with_findings'] / max(1, self.summary_stats['total_reports']) * 100:.1f}%)"
        )
        md.append(
            f"- **Total Secrets Found:** {self.summary_stats['total_findings']:,}"
        )
        md.append(
            f"- **High-Value Secrets:** {self.summary_stats['high_value_findings']:,}"
        )
        md.append(
            f"- **Active High-Value Secrets:** {self.summary_stats['active_high_value_secrets']:,}"
        )
        md.append("")

        # Repository Distribution
        if self.summary_stats.get("repositories_by_platform"):
            md.append("## Repository Distribution by Platform")
            md.append("")
            for platform, count in self.summary_stats[
                "repositories_by_platform"
            ].items():
                md.append(f"- **{platform}:** {count:,} repositories")
            md.append("")

        # Findings by Rule Type
        md.append("## Secret Types Found")
        md.append("")
        md.append("| Rule Type | Count | Percentage |")
        md.append("|-----------|-------|------------|")

        total_findings = self.summary_stats["total_findings"]
        for rule, count in self.summary_stats["findings_by_rule"].items():
            percentage = (count / total_findings * 100) if total_findings > 0 else 0
            md.append(f"| {rule} | {count:,} | {percentage:.1f}% |")
        md.append("")

        # Verification Status
        if self.summary_stats.get("findings_by_verification"):
            md.append("## Verification Status")
            md.append("")
            verification = self.summary_stats["findings_by_verification"]
            total_verified = sum(verification.values())

            if total_verified > 0:
                md.append("### Verified Secrets")
                md.append(f"- **Total Verified:** {total_verified:,}")
                md.append(
                    f"- **Active:** {verification.get('Active', 0):,} ({verification.get('Active', 0) / total_verified * 100:.1f}%)"
                )
                md.append(
                    f"- **Inactive:** {verification.get('Inactive', 0):,} ({verification.get('Inactive', 0) / total_verified * 100:.1f}%)"
                )
                md.append(
                    f"- **Unknown:** {verification.get('Unknown', 0):,} ({verification.get('Unknown', 0) / total_verified * 100:.1f}%)"
                )
            else:
                md.append("**Note:** No secrets were verified in this scan batch.")
            md.append("")

        # High-Value Findings
        md.append("## High-Value Security Findings")
        md.append("")
        if self.summary_stats["high_value_findings"] > 0:
            md.append(
                "⚠️ **CRITICAL:** High-value secrets detected that could compromise:"
            )
            md.append("- Cloud infrastructure access (AWS, GCP, Azure)")
            md.append("- AI/ML service billing (OpenAI, Anthropic)")
            md.append("- Payment processing (Stripe)")
            md.append("- Source code repositories (GitHub)")
            md.append("")

            # Show sample high-value findings
            high_value_samples = []
            for finding in self.findings[:10]:  # Show first 10
                rule_id = finding.get("rule_id", "")
                if rule_id in {
                    "openai-api-key",
                    "anthropic-api-key",
                    "claude-3-api-key",
                    "stripe-secret-key",
                    "github-pat",
                    "aws-access-key-id",
                }:
                    verification = finding.get(
                        "verification_status", {}
                    ) or finding.get("verification", {})
                    status = verification.get("status", "not_verified")
                    repo = (
                        finding.get("file", "").split("/")[-1]
                        if "/" in finding.get("file", "")
                        else "unknown"
                    )

                    high_value_samples.append(
                        {
                            "rule": rule_id,
                            "repo": repo,
                            "status": status,
                            "line": finding.get("line", 0),
                        }
                    )

            if high_value_samples:
                md.append("### Sample High-Value Findings")
                md.append("")
                md.append("| Secret Type | Repository | Verification | Line |")
                md.append("|-------------|------------|--------------|------|")
                for sample in high_value_samples:
                    md.append(
                        f"| {sample['rule']} | {sample['repo']} | {sample['status']} | {sample['line']} |"
                    )
                md.append("")
        else:
            md.append(
                "✅ **Good news:** No high-value secrets detected in scanned repositories."
            )
            md.append("")

        # Research Insights
        md.append("## Research Insights")
        md.append("")

        # Calculate risk metrics
        if total_findings > 0:
            avg_findings_per_repo = total_findings / self.summary_stats["total_reports"]
            md.append(
                f"- **Average secrets per repository:** {avg_findings_per_repo:.2f}"
            )

            repos_with_secrets_pct = (
                self.summary_stats["reports_with_findings"]
                / self.summary_stats["total_reports"]
            ) * 100
            md.append(f"- **Repositories with secrets:** {repos_with_secrets_pct:.1f}%")

            if self.summary_stats["active_high_value_secrets"] > 0:
                md.append(
                    f"- **🚨 Active high-value secrets found:** {self.summary_stats['active_high_value_secrets']}"
                )
                md.append(
                    "  - These represent immediate security risks requiring urgent attention"
                )
            else:
                md.append("- **✅ No active high-value secrets detected**")
        md.append("")

        # Recommendations
        md.append("## Recommendations for Researchers")
        md.append("")
        md.append("### Immediate Actions")
        if self.summary_stats["active_high_value_secrets"] > 0:
            md.append(
                "1. **URGENT:** Notify repository owners of active high-value secrets"
            )
            md.append(
                "2. **URGENT:** Request immediate secret rotation and access revocation"
            )
            md.append(
                "3. **URGENT:** Monitor for unauthorized access using these credentials"
            )
        md.append("")

        md.append("### Long-term Security Improvements")
        md.append("1. **Implement automated secret scanning** in CI/CD pipelines")
        md.append(
            "2. **Use secret management solutions** (HashiCorp Vault, AWS Secrets Manager, etc.)"
        )
        md.append(
            "3. **Enable repository security features** (GitHub Secret Scanning, GitLab Secret Detection)"
        )
        md.append("4. **Conduct regular security audits** of public repositories")
        md.append("5. **Educate developers** on secure secret handling practices")
        md.append("")

        # Methodology
        md.append("## Methodology")
        md.append("")
        md.append("### Scanning Process")
        md.append(
            "1. **Repository Discovery:** Automated discovery of recently created repositories"
        )
        md.append(
            "2. **Pattern Matching:** Detection using comprehensive secret patterns"
        )
        md.append("3. **Verification:** Optional validation against provider APIs")
        md.append(
            "4. **Aggregation:** Compilation of findings across all scanned repositories"
        )
        md.append("")

        md.append("### Tools Used")
        md.append("- **LibreLeak:** Custom Rust-based secret scanner")
        md.append("- **Docker:** Containerized scanning environment")
        md.append("- **GitHub/GitLab/Codeberg APIs:** Repository discovery")
        md.append("")

        # Footer
        md.append("---")
        md.append("")
        md.append(
            "*This report was generated by LibreLeak - Open source secret scanner*"
        )
        md.append("*For more information: https://github.com/your-org/libreleak*")

        return "\n".join(md)

    def generate_html_report(self) -> str:
        """Generate an HTML report with styling and charts."""
        markdown_content = self.generate_markdown_report()

        # Convert markdown to HTML (basic conversion)
        html_content = markdown_content
        html_content = html_content.replace("# ", "<h1>").replace("\n\n", "</h1>\n\n")
        html_content = html_content.replace("## ", "<h2>").replace("\n\n", "</h2>\n\n")
        html_content = html_content.replace("### ", "<h3>").replace("\n\n", "</h3>\n\n")
        html_content = html_content.replace("**", "<strong>").replace("**", "</strong>")
        html_content = html_content.replace("*", "<em>").replace("*", "</em>")
        html_content = html_content.replace("\n- ", "\n<li>").replace("\n", "</li>\n")
        html_content = html_content.replace("|", "<td>").replace("|\n", "</td></tr>\n")
        html_content = html_content.replace("---", "<hr>")

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LibreLeak Security Research Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{ color: #d73a49; border-bottom: 3px solid #d73a49; padding-bottom: 10px; }}
        h2 {{ color: #0366d6; border-bottom: 2px solid #0366d6; padding-bottom: 8px; }}
        h3 {{ color: #6f42c1; }}
        .summary-box {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 20px;
            margin: 20px 0;
        }}
        .metric {{ font-size: 1.2em; font-weight: bold; color: #28a745; }}
        .warning {{ background: #fff3cd; border-color: #ffeaa7; color: #856404; }}
        .success {{ background: #d4edda; border-color: #c3e6cb; color: #155724; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{ background-color: #f8f9fa; font-weight: bold; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .badge-active {{ background: #dc3545; color: white; }}
        .badge-inactive {{ background: #28a745; color: white; }}
        .badge-unknown {{ background: #ffc107; color: black; }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        {html_content}
        <div class="footer">
            <p><strong>Disclaimer:</strong> This report contains sensitive security information.
            Handle with care and share only with authorized researchers and repository owners.</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def save_report(self, output_path: Path, format: str = "markdown"):
        """Save the compiled report to a file."""
        if format.lower() == "html":
            content = self.generate_html_report()
            filename = f"security-research-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
        else:
            content = self.generate_markdown_report()
            filename = f"security-research-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"

        output_file = output_path / filename

        with open(output_file, "w") as f:
            f.write(content)

        print(f"Report saved to: {output_file}")
        return output_file


def main():
    """Main entry point."""
    # Parse command line arguments
    reports_dir = Path(os.environ.get("REPORTS_DIR", "/reports"))
    output_format = "markdown"

    args = sys.argv[1:]
    if args and not args[0].startswith("--"):
        reports_dir = Path(args[0])
        args = args[1:]

    for arg in args:
        if arg == "--format" and len(args) > args.index(arg) + 1:
            output_format = args[args.index(arg) + 1]
        elif arg.startswith("--format="):
            output_format = arg.split("=", 1)[1]

    # Validate arguments
    if output_format not in ["markdown", "md", "html"]:
        print(f"Error: Unsupported format '{output_format}'. Use 'markdown' or 'html'.")
        sys.exit(1)

    # Compile reports
    compiler = ReportCompiler(reports_dir)

    if not compiler.load_reports():
        sys.exit(1)

    compiler.generate_summary_stats()

    # Save report
    output_path = reports_dir
    compiler.save_report(output_path, output_format)

    # Print summary to console
    print("\n" + "=" * 60)
    print("SECURITY RESEARCH SUMMARY")
    print("=" * 60)
    print(f"Total Repositories: {compiler.summary_stats['total_reports']:,}")
    print(
        f"Repositories with Secrets: {compiler.summary_stats['reports_with_findings']:,}"
    )
    print(f"Total Secrets Found: {compiler.summary_stats['total_findings']:,}")
    print(f"High-Value Secrets: {compiler.summary_stats['high_value_findings']:,}")
    print(
        f"Active High-Value Secrets: {compiler.summary_stats['active_high_value_secrets']:,}"
    )

    if compiler.summary_stats["active_high_value_secrets"] > 0:
        print("\n🚨 CRITICAL: Active high-value secrets detected!")
        print("   Immediate action required for these findings.")
    else:
        print("\n✅ No active high-value secrets detected.")

    print("=" * 60)


if __name__ == "__main__":
    main()

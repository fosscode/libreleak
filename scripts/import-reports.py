#!/usr/bin/env python3
"""
libreleak Report Importer

Imports JSON scan reports into PostgreSQL database for aggregation and analysis.
Supports both individual report files and batch processing of directories.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    import psycopg2
    from psycopg2.extras import Json
except ImportError:
    print("Error: psycopg2 not installed. Run: pip install psycopg2-binary")
    sys.exit(1)


def get_db_connection():
    """Get database connection from environment variable."""
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print("Error: DATABASE_URL environment variable not set")
        sys.exit(1)
    return psycopg2.connect(db_url)


def import_report(conn, report_path: Path):
    """Import a single JSON report into the database."""
    try:
        with open(report_path) as f:
            report = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"  Error reading {report_path}: {e}")
        return False

    # Check if this is a libreleak report format
    if 'scanner' not in report or report.get('scanner') != 'libreleak':
        # Try simple JSON format
        if 'findings' in report and 'version' in report:
            return import_simple_report(conn, report, report_path)
        print(f"  Skipping {report_path}: Not a libreleak report")
        return False

    # Check for report version 2.0 (enhanced format)
    if report.get('report_version') == '2.0':
        return import_enhanced_report(conn, report)
    else:
        return import_simple_report(conn, report, report_path)


def import_enhanced_report(conn, report: dict) -> bool:
    """Import enhanced (v2.0) format report."""
    cur = conn.cursor()

    try:
        scan_id = report.get('scan_id', generate_scan_id())
        target = report.get('target', {})

        # Insert scan metadata
        cur.execute("""
            INSERT INTO scans (
                scan_id, scanner_version, timestamp, target_path, target_type,
                git_remote, git_branch, git_commit, scan_duration_ms, total_findings
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (scan_id) DO UPDATE SET
                total_findings = EXCLUDED.total_findings
            RETURNING id
        """, (
            scan_id,
            report.get('scanner_version', 'unknown'),
            report.get('timestamp', datetime.utcnow().isoformat()),
            target.get('path') if target else None,
            target.get('type') if target else None,
            target.get('git_remote') if target else None,
            target.get('git_branch') if target else None,
            target.get('git_commit') if target else None,
            target.get('scan_duration_ms', 0) if target else 0,
            report.get('summary', {}).get('total_findings', len(report.get('findings', [])))
        ))

        # Import findings
        for finding in report.get('findings', []):
            location = finding.get('location', {})
            verification = finding.get('verification', {})

            cur.execute("""
                INSERT INTO findings (
                    scan_id, rule_id, rule_name, file_path, line_number,
                    column_number, secret_preview, context, verification_status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                scan_id,
                finding.get('rule_id'),
                finding.get('rule_name'),
                location.get('file', finding.get('file', '')),
                location.get('line', finding.get('line', 0)),
                location.get('column', finding.get('column', 0)),
                finding.get('secret_preview', finding.get('secret', '')),
                Json(finding.get('context', [])),
                verification.get('status', 'pending')
            ))

        conn.commit()
        return True

    except Exception as e:
        conn.rollback()
        print(f"  Error importing report: {e}")
        return False
    finally:
        cur.close()


def import_simple_report(conn, report: dict, report_path: Path) -> bool:
    """Import simple (v1.0) format report."""
    cur = conn.cursor()

    try:
        scan_id = generate_scan_id()
        findings = report.get('findings', [])

        # Insert scan metadata
        cur.execute("""
            INSERT INTO scans (
                scan_id, scanner_version, target_path, total_findings
            ) VALUES (%s, %s, %s, %s)
            ON CONFLICT (scan_id) DO NOTHING
            RETURNING id
        """, (
            scan_id,
            report.get('version', 'unknown'),
            str(report_path),
            len(findings)
        ))

        # Import findings
        for finding in findings:
            cur.execute("""
                INSERT INTO findings (
                    scan_id, rule_id, rule_name, file_path, line_number,
                    column_number, secret_preview, context
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                scan_id,
                finding.get('rule_id'),
                finding.get('rule_name'),
                finding.get('file', ''),
                finding.get('line', 0),
                finding.get('column', 0),
                finding.get('secret', ''),
                Json(finding.get('context', []))
            ))

        conn.commit()
        return True

    except Exception as e:
        conn.rollback()
        print(f"  Error importing report: {e}")
        return False
    finally:
        cur.close()


def generate_scan_id() -> str:
    """Generate a unique scan ID."""
    import time
    return f"{int(time.time() * 1000000):032x}"


def main():
    """Main entry point."""
    reports_dir = Path(os.environ.get('REPORTS_DIR', '/reports'))

    if len(sys.argv) > 1:
        # Import specific files
        files = [Path(f) for f in sys.argv[1:]]
    else:
        # Import all JSON files in reports directory
        files = list(reports_dir.glob('*.json'))

    if not files:
        print(f"No JSON files found in {reports_dir}")
        sys.exit(0)

    print(f"Connecting to database...")
    conn = get_db_connection()

    print(f"Importing {len(files)} report(s)...")
    success = 0
    failed = 0

    for report_file in files:
        print(f"Importing: {report_file.name}")
        if import_report(conn, report_file):
            success += 1
            print(f"  OK")
        else:
            failed += 1

    conn.close()

    print(f"\nImport complete: {success} success, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()

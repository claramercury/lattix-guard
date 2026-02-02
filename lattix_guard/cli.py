"""Command-line interface for lattix_guard."""

import sys
import argparse
from pathlib import Path

from .scanner import scan_project
from .report import generate_reports
from .scoring import get_grade_description


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Lattix Guard - Security auditing tool for Docker/FastAPI projects',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/project
  %(prog)s /path/to/project --out ./reports
  %(prog)s /path/to/project --format json
  %(prog)s /path/to/project --fail-on critical

Exit codes:
  0 - Scan successful, no critical issues
  1 - Scan error (invalid input, parser error, etc.)
  2 - Critical/High findings detected (if --fail-on used)
        """
    )

    parser.add_argument(
        'project_path',
        type=str,
        help='Path to project directory or docker-compose.yml'
    )

    parser.add_argument(
        '--out',
        type=str,
        default='./lattix_guard_reports',
        help='Output directory for reports (default: ./lattix_guard_reports)'
    )

    parser.add_argument(
        '--format',
        type=str,
        choices=['json', 'html', 'both'],
        default='both',
        help='Report format (default: both)'
    )

    parser.add_argument(
        '--fail-on',
        type=str,
        choices=['critical', 'high'],
        help='Exit with code 2 if findings of this severity or higher are found'
    )

    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Minimal output (only errors and final score)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output (debug information)'
    )

    args = parser.parse_args()

    # Validate project path
    project_path = Path(args.project_path).resolve()

    if not project_path.exists():
        print(f"Error: Path does not exist: {args.project_path}", file=sys.stderr)
        sys.exit(1)

    # If path is a file, use its parent directory
    if project_path.is_file():
        if project_path.name in ['docker-compose.yml', 'docker-compose.yaml']:
            project_path = project_path.parent
        else:
            print(f"Error: File is not a docker-compose.yml: {args.project_path}", file=sys.stderr)
            sys.exit(1)

    # Print header (unless quiet)
    if not args.quiet:
        print("Lattix Guard v0.1.0 - Security Auditing Tool")
        print("=" * 50)
        print()
        print(f"Scanning: {project_path}")

    # Perform scan
    try:
        scan_result = scan_project(project_path)
    except Exception as e:
        print(f"Error: Scan failed: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # Print scan summary (unless quiet)
    if not args.quiet:
        files_scanned = scan_result.files_scanned
        print(f"  Files scanned: {files_scanned.get('python_files', 0)} Python, "
              f"{files_scanned.get('docker_compose', 0)} Docker Compose")
        print()

    # Print errors if any
    if scan_result.errors:
        print("⚠️  Scan Errors:", file=sys.stderr)
        for error in scan_result.errors:
            print(f"  - {error}", file=sys.stderr)
        print()

    # Generate reports
    output_dir = Path(args.out)
    try:
        generated = generate_reports(
            scan_result,
            output_dir,
            formats=[args.format]
        )
    except Exception as e:
        print(f"Error: Report generation failed: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # Print results
    score_details = scan_result.score_details
    score = score_details['score']
    grade = score_details['grade']
    severity_counts = score_details['by_severity']

    if not args.quiet:
        print("=" * 50)

    print(f"SECURITY SCORE: {score}/100 (Grade {grade})")
    print(f"  {get_grade_description(grade)}")

    if not args.quiet:
        print()
        print("Findings by Severity:")
        print(f"  CRITICAL: {severity_counts['CRITICAL']}")
        print(f"  HIGH:     {severity_counts['HIGH']}")
        print(f"  MEDIUM:   {severity_counts['MEDIUM']}")
        print(f"  LOW:      {severity_counts['LOW']}")
        print(f"  INFO:     {severity_counts['INFO']}")
        print()

    # Print report locations
    print("Reports generated:")
    if generated['json']:
        print(f"  ✓ {generated['json']}")
    if generated['html']:
        print(f"  ✓ {generated['html']}")

    if not args.quiet and generated['html']:
        print()
        print(f"Open {generated['html']} in your browser for details.")

    # Determine exit code based on --fail-on
    exit_code = 0

    if args.fail_on:
        critical_count = severity_counts['CRITICAL']
        high_count = severity_counts['HIGH']

        if args.fail_on == 'critical' and critical_count > 0:
            print(f"\n❌ Failing: {critical_count} CRITICAL finding(s) detected", file=sys.stderr)
            exit_code = 2
        elif args.fail_on == 'high' and (critical_count > 0 or high_count > 0):
            total = critical_count + high_count
            print(f"\n❌ Failing: {total} CRITICAL/HIGH finding(s) detected", file=sys.stderr)
            exit_code = 2

    sys.exit(exit_code)


if __name__ == '__main__':
    main()

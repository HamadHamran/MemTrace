import argparse
import sys
from pathlib import Path

from memtrace.pipeline import new_case_id, run_case

BASE_DIR = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description="MemTrace - automated Windows memory forensics")
    parser.add_argument("dump", help="Path to the Windows memory image")
    parser.add_argument("--cases-dir", default=str(BASE_DIR / "cases"), help="Directory for case output")
    args = parser.parse_args()

    dump = Path(args.dump)
    if not dump.is_file():
        sys.exit(f"Memory image not found: {dump}")

    case_id = new_case_id()
    case_dir = Path(args.cases_dir) / case_id

    def progress(step, total, message):
        print(f"[{step}/{total}] {message}", flush=True)

    print(f"Case {case_id}  |  Evidence {dump.name}")
    try:
        results = run_case(dump, case_dir, case_id, progress)
    except RuntimeError as exc:
        sys.exit(f"\nAnalysis failed: {exc}")

    summary = results["summary"]
    print()
    print(f"Verdict:    {summary['verdict']}")
    print(f"Risk score: {summary['score']}/100")
    print("Findings:   " + ", ".join(f"{k}={v}" for k, v in summary["counts"].items()))
    for finding in results["findings"]:
        print(f"  {finding['id']} [{finding['severity'].upper():8}] {finding['title']}")
    for plugin in results["plugins"]:
        if plugin["status"] != "ok":
            print(f"  ! {plugin['plugin']}: {plugin['detail']}")
    print()
    print(f"Report:     {case_dir / (case_id + '_report.pdf')}")


if __name__ == "__main__":
    main()

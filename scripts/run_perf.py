"""Run the performance harness and write ``docs/perf-results.md``.

Spec 09 section 8 requires benchmark results recorded with device information.
This is the driver ``make perf`` calls: it runs ``backend/tests/perf`` with a
small plugin that collects each benchmark's ``perf`` property, then hands the
result to ``scripts/perf_report.py``.

The benchmarks are excluded from the normal test run, because timing assertions
are meaningless under a shared CI machine. Run them deliberately.

Usage::

    python scripts/run_perf.py
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
RESULTS = "perf-results.json"

# Passed to pytest as -p so no plugin has to be importable from the repo.
COLLECTOR = """
import json

class _Collector:
    def __init__(self):
        self.measurements = []

    def pytest_runtest_logreport(self, report):
        if report.when != 'call' or not report.passed:
            return
        raw = getattr(report, 'user_properties', None) or []
        for name, value in raw:
            if name == 'perf':
                self.measurements.extend(json.loads(value))

    def pytest_sessionfinish(self, session):
        path = session.config.stash['_perf_out']
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump({'measurements': self.measurements}, handle, indent=2)

_collector = _Collector()

def pytest_configure(config):
    config.pluginmanager.register(_collector)
    config.stash['_perf_out'] = config.getoption('perf_out')

def pytest_addoption(parser):
    parser.addoption('--perf-out', default='perf-results.json',
                     help='where to write the collected measurements')
"""


def main(argv: Sequence[str] | None = None) -> int:
    """Run the benchmarks, then write the results document."""
    parser = argparse.ArgumentParser(description="Run the performance benchmarks.")
    parser.add_argument(
        "-k",
        "--filter",
        default=None,
        help="only run benchmarks whose name matches this expression",
    )
    args = parser.parse_args(argv)

    # A temp plugin file: pytest -p takes an importable module name, and adding a
    # permanent conftest hook for a rarely used run would slow every test run.
    with tempfile.TemporaryDirectory() as directory:
        plugin = Path(directory) / "perf_collector.py"
        plugin.write_text(COLLECTOR, encoding="utf-8")
        results_path = Path(directory) / RESULTS

        command = [
            sys.executable,
            "-m",
            "pytest",
            "tests/perf",
            "-q",
            "-p",
            "perf_collector",
            "-o",
            "addopts=",
            f"--perf-out={results_path}",
        ]
        if args.filter:
            command += ["-k", args.filter]

        environment = {"PYTHONPATH": directory}
        import os

        completed = subprocess.run(
            command,
            cwd=str(BACKEND),
            env={**os.environ, **environment},
            check=False,
        )
        if completed.returncode != 0:
            return completed.returncode
        if not results_path.is_file():
            print("the benchmark run produced no results file", file=sys.stderr)
            return 1

        report = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "perf_report.py"),
                str(results_path),
                "--out",
                str(ROOT / "docs" / "perf-results.md"),
            ],
            cwd=str(ROOT),
            check=False,
        )
        return report.returncode


if __name__ == "__main__":
    raise SystemExit(main())

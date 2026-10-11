"""Vendor a curated SigmaHQ rule sample into ``backend/rules/sigma`` (spec 04 section 1).

Usage::

    python scripts/update_rules.py path/to/sigma
    python scripts/update_rules.py path/to/sigma --output backend/rules/sigma
    python scripts/update_rules.py sigma-48f2d09.zip --dry-run

The source is a SigmaHQ/sigma checkout (a directory, or a zip of one). The
sample contains only detection rules that load, compile with the SQLite backend
and route through the shipped ``logsource_map.yaml``; every such file under
``rules/{windows,linux,web,network}`` is considered, the windows candidates are
budgeted across their first-level rule families and capped per severity so the
tree stays reviewable, and the chosen files are copied verbatim (a
multi-document file is vendored whole or not at all). The run then re-loads the
written tree and asserts it reproduces exactly.

The upstream LICENSE pointer and a generated ``SOURCE.txt`` (upstream URL,
commit, selection policy, per-bucket failure counts and a content SHA-256) sit
next to the rules. ``backend/rules/sigma/LICENSE`` holds the DRL 1.1 text and is
maintained separately; this script never rewrites it.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from app.detect.rules import (
    RULE_TYPE_CORRELATION,
    RULE_TYPE_DETECTION,
    LoadedRule,
    load_rules,
)

UPSTREAM = "https://github.com/SigmaHQ/sigma"
DRL_URL = (
    "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/"
    "LICENSE.Detection.Rules.md"
)

CATEGORIES = ("windows", "linux", "web", "network")

#: per-severity caps for the windows sample. The good files are also budgeted
#: across their top-level rule families (``rules/windows/<family>/...``) so the
#: sample has breadth, not just the alphabetically first subtree. Files are
#: taken in path order within each family and whole (a multi-document file is
#: vendored whole or not at all), so final counts can exceed the caps.
WINDOWS_CAPS = {"high": 90, "medium": 70, "critical": 5, "low": 5}

_EXTENSIONS = frozenset({".yml", ".yaml"})


@dataclass(frozen=True, slots=True)
class FileClass:
    """One candidate rule file and its load outcome."""

    source: Path
    rel: str
    rules: tuple[LoadedRule, ...]
    problem: str | None

    def good(self) -> bool:
        return (
            self.problem is None
            and bool(self.rules)
            and all(_is_selected(rule) for rule in self.rules)
        )


def main(argv: list[str] | None = None) -> int:
    """Run the vendor step; see the module docstring."""
    parser = argparse.ArgumentParser(description="Vendor a SigmaHQ rule sample.")
    parser.add_argument(
        "source", type=Path, help="SigmaHQ/sigma checkout directory or zip"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=BACKEND / "rules" / "sigma",
        help="destination rules directory (default: backend/rules/sigma)",
    )
    parser.add_argument(
        "--commit", default=None, help="upstream commit (default: git HEAD)"
    )
    parser.add_argument("--date", default=None, help="upstream commit date, ISO 8601")
    parser.add_argument(
        "--logsource-map",
        type=Path,
        default=BACKEND / "rules" / "logsource_map.yaml",
        help="routing map to validate against (default: shipped map)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="bucket and report without writing anything",
    )
    args = parser.parse_args(argv)

    scratch = tempfile.TemporaryDirectory(prefix="sigma-update-")
    try:
        rules_root = _resolve_rules_root(args.source, Path(scratch.name))
        commit = args.commit or _git_commit(args.source)
        date = args.date or _git_date(args.source)

        report = _analyze(rules_root, args.logsource_map)
        chosen = _choose(report)
        counts = _chosen_counts(chosen)
        selected_total = sum(c["files"] for c in counts.values())
        rules_total = sum(c["rules"] for c in counts.values())
        if selected_total == 0 or rules_total < 200:
            print(
                "selection is empty or below 200 rules; nothing vendored",
                file=sys.stderr,
            )
            return 1

        if args.dry_run:
            _print_report(report, counts, rules_total)
            return 0

        _write_tree(
            chosen,
            rules_root,
            args.output,
            source_license=rules_root.parent / "LICENSE",
        )
        tree_sha = _tree_sha256(args.output, chosen)
        _write_source_txt(
            args.source,
            args.output,
            commit,
            date,
            report,
            counts,
            rules_total,
            tree_sha,
        )
        _validate_output(args.output, args.logsource_map)
    finally:
        scratch.cleanup()
    print(
        f"vendored {rules_total} SigmaHQ rule document(s) in {selected_total} file(s) into {args.output}"
    )
    print(f"tree SHA-256: {tree_sha}")
    return 0


def _resolve_rules_root(source: Path, scratch: Path) -> Path:
    """The ``rules`` directory of a checkout dir or a zip of one."""
    if source.is_dir():
        rules = source / "rules"
        return rules if rules.is_dir() else source
    if zipfile.is_zipfile(source):
        target = scratch / "source"
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(source) as archive:
            _safe_extract(archive, target)
        rules = target / "rules"
        return rules if rules.is_dir() else target
    raise SystemExit(f"source is not a directory or zip archive: {source}")


def _safe_extract(archive: zipfile.ZipFile, target: Path) -> None:
    """Extract a zip with no absolute paths or parent traversal."""
    for member in archive.infolist():
        name = member.filename.replace("\\", "/")
        parts = [part for part in name.split("/") if part not in ("", ".")]
        if not parts or ".." in parts or name.startswith(("/", "\\")):
            raise SystemExit(f"zip entry is unsafe: {member.filename}")
        destination = target.joinpath(*parts)
        if member.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(archive.read(member))


def _git_commit(source: Path) -> str | None:
    if not source.is_dir() or not (source / ".git").exists():
        return None
    return _git(source, "rev-parse", "HEAD")


def _git_date(source: Path) -> str | None:
    if not source.is_dir() or not (source / ".git").exists():
        return None
    return _git(source, "log", "-1", "--format=%cI")


def _git(source: Path, *arguments: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(source), *arguments],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


@dataclass(frozen=True, slots=True)
class Report:
    """Bucketed load results for one category."""

    candidates: int
    problems: list[str]
    buckets: Counter[str]
    siblings: int
    examples: dict[str, list[str]]
    good: list[FileClass]


def _analyze(rules_root: Path, map_path: Path) -> dict[str, Report]:
    """Load every category and bucket each candidate file."""
    reports: dict[str, Report] = {}
    for category in CATEGORIES:
        path = rules_root / category
        if not path.is_dir():
            print(
                f"category {category!r} missing from {rules_root}; skipping",
                file=sys.stderr,
            )
            continue
        rules, problems = load_rules(sigma_dir=path, logsource_map=map_path)
        by_file: dict[Path, list[LoadedRule]] = defaultdict(list)
        for rule in rules:
            by_file[_base(rule.file_path)].append(rule)
        file_problems: dict[Path, str] = {}
        for problem in problems:
            file_problems.setdefault(_base(problem.where), problem.error)

        buckets: Counter[str] = Counter()
        examples: dict[str, list[str]] = defaultdict(list)
        good: list[FileClass] = []
        siblings = 0
        for base, docs in by_file.items():
            rel = base.relative_to(rules_root).as_posix()
            classified = FileClass(
                source=base,
                rel=rel,
                rules=tuple(docs),
                problem=file_problems.get(base),
            )
            if classified.good():
                good.append(classified)
                continue
            if classified.problem is not None:
                buckets["load problem"] += 1
                _record(examples, "load problem", classified)
                continue
            for rule in docs:
                bucket = _bucket_of(rule)
                if bucket is None:
                    siblings += 1
                    continue
                buckets[bucket] += 1
                _record(examples, bucket, classified)
        reports[category] = Report(
            candidates=sum(
                1
                for _ in (rules_root / category).glob("**/*")
                if _.is_file() and _.suffix.lower() in _EXTENSIONS
            ),
            problems=[problem.error for problem in problems[:5]],
            buckets=buckets,
            siblings=siblings,
            examples={bucket: sorted(names)[:6] for bucket, names in examples.items()},
            good=good,
        )
    return reports


def _choose(reports: dict[str, Report]) -> dict[str, list[FileClass]]:
    """Select the good files per category."""
    chosen: dict[str, list[FileClass]] = {}
    for category, report in reports.items():
        if category == "windows":
            chosen[category] = _select_windows(report.good, WINDOWS_CAPS)
        else:
            chosen[category] = report.good
    return chosen


def _select_windows(good: list[FileClass], caps: dict[str, int]) -> list[FileClass]:
    """Fill the severity caps with breadth across the rule families."""
    families = sorted({_family(item.rel) for item in good})
    budget: dict[str, int] = {}
    base, remainder = divmod(sum(caps.values()), len(families))
    for position, family in enumerate(families):
        budget[family] = base + (1 if position < remainder else 0)

    counts: dict[str, int] = defaultdict(int)
    chosen: list[FileClass] = []
    for family in families:
        per_family = 0
        for candidate in sorted(
            (item for item in good if _family(item.rel) == family),
            key=lambda item: item.rel,
        ):
            if per_family >= budget[family]:
                break
            if all(counts[level] >= cap for level, cap in caps.items()):
                break
            rules = [rule for rule in candidate.rules if _is_selected(rule)]
            if not any(caps.get(rule.level, 0) > counts[rule.level] for rule in rules):
                continue
            chosen.append(candidate)
            per_family += 1
            for rule in rules:
                counts[rule.level] += 1
    return chosen


def _family(rel: str) -> str:
    """The first path segment of a rule file below its category (``builtin``,
    ``sysmon``, ...). ``rel`` starts with the category segment, so it is skipped."""
    return rel.partition("/")[2].split("/")[0] if "/" in rel else rel


def _chosen_counts(chosen: dict[str, list[FileClass]]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for category, files in chosen.items():
        totals = {"files": len(files), "rules": 0}
        for item in files:
            totals["rules"] += sum(1 for rule in item.rules if _is_selected(rule))
        counts[category] = totals
    return counts


def _write_tree(
    chosen: dict[str, list[FileClass]],
    rules_root: Path,
    output: Path,
    *,
    source_license: Path,
) -> None:
    """Copy selected files verbatim and keep the upstream LICENSE pointer."""
    _remove_previous_rules(output)
    for files in chosen.values():
        for item in files:
            destination = output / item.rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = rules_root / item.rel
            destination.write_bytes(source.read_bytes())
    if source_license.is_file():
        destination = output / "upstream-LICENSE.md"
        destination.write_bytes(source_license.read_bytes())


def _remove_previous_rules(output: Path) -> None:
    """Delete stale rule files so a rerun reproduces the tree exactly.

    Non-rule files (``LICENSE``, ``SOURCE.txt``, ``upstream-LICENSE.md``) are
    maintained separately and left alone.
    """
    for path in [
        candidate
        for candidate in output.rglob("*")
        if candidate.is_file() and candidate.suffix.lower() in _EXTENSIONS
    ]:
        path.unlink()
    for directory in sorted(
        (candidate for candidate in output.rglob("*") if candidate.is_dir()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        try:
            directory.rmdir()
        except OSError:
            pass  # only empty directories are removed


def _write_source_txt(
    source: Path,
    output: Path,
    commit: str | None,
    date: str | None,
    report: dict[str, Report],
    counts: dict[str, dict[str, int]],
    rules_total: int,
    tree_sha: str,
) -> None:
    """Write ``SOURCE.txt`` alongside the vendored rules."""
    lines = [
        "SigmaHQ detection rules vendored into TriageLens",
        "=" * 47,
        "",
        f"Upstream: {UPSTREAM}",
        f"Pinned commit: {commit or 'unknown'}",
        f"Commit date: {date or 'unknown'}",
        "License: Detection Rule License (DRL) 1.1 - see LICENSE (SPDX: DRL-1.1)",
        f"License text: {DRL_URL}",
        "Vendoring tool: scripts/update_rules.py",
        "",
        "Selection policy",
        "----------------",
        "Only detection rules that parse, compile with the pysigma-backend-sqlite",
        "compiler and route through the shipped logsource_map.yaml are vendored.",
        "Source dirs: rules/{windows,linux,web,network}. A multi-document file is",
        "vendored whole or not at all. windows is budgeted across its top-level",
        "rule families (high 90, medium 70, critical 5, low 5); linux, web and",
        "network take every routing candidate. Correlation rules and rules with",
        "load, compile or routing problems are excluded and counted below.",
        "",
        f"Generated (UTC): {datetime.now(UTC).replace(microsecond=0).isoformat()}",
        f"Tree SHA-256: {tree_sha}",
        ("Source SHA-256: " + _source_sha256(source) if source.is_dir() else ""),
        "",
    ]
    lines.append(f"Selected: {rules_total} rule document(s)")
    total_files = 0
    for category in CATEGORIES:
        if category not in counts:
            continue
        cats = counts[category]
        total_files += cats["files"]
        lines.append(
            f"  {category:<8} {cats['files']:>4} file(s), {cats['rules']:>4} rule(s)"
        )
    lines.append(f"  {'TOTAL':<8} {total_files:>4} file(s), {rules_total:>4} rule(s)")
    lines.append("")
    lines.append("Candidates and exclusions per category")
    lines.append("--------------------------------------")
    for category in CATEGORIES:
        if category not in report:
            continue
        report_cat = report[category]
        lines.append(f"{category}: {report_cat.candidates} candidate file(s)")
        for bucket, number in sorted(report_cat.buckets.items()):
            lines.append(f"  {bucket}: {number}")
            for example in report_cat.examples.get(bucket, []):
                lines.append(f"    - {example}")
        if report_cat.siblings:
            lines.append(f"  sibling of a bad file: {report_cat.siblings}")
    (output / "SOURCE.txt").write_text(
        "\n".join(line for line in lines if line is not None), encoding="utf-8"
    )


def _source_sha256(source: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(source.glob("rules/**/*")):
        if path.is_file() and path.suffix.lower() in _EXTENSIONS:
            digest.update(path.read_bytes())
            digest.update(b"\0")
    return digest.hexdigest()


def _tree_sha256(output: Path, chosen: dict[str, list[FileClass]]) -> str:
    """A deterministic SHA-256 of the vendored rules' paths and bytes."""
    parts: list[str] = []
    for category in CATEGORIES:
        for item in sorted(chosen.get(category, []), key=lambda entry: entry.rel):
            content = (output / item.rel).read_bytes()
            parts.append(f"{item.rel} {hashlib.sha256(content).hexdigest()}")
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def _validate_output(output: Path, map_path: Path) -> None:
    """Re-load the written tree; it must reproduce identically and stay clean."""
    rules, problems = load_rules(sigma_dir=output, logsource_map=map_path)
    assert problems == [], problems
    assert rules, "vendored tree contained no rules"
    assert all(_is_selected(rule) for rule in rules), (
        "vendored tree contains a rule that fails compile or routing"
    )
    again, again_problems = load_rules(sigma_dir=output, logsource_map=map_path)
    assert again_problems == []
    assert [(rule.id, rule.sha256, rule.yaml, rule.file_path) for rule in again] == [
        (rule.id, rule.sha256, rule.yaml, rule.file_path) for rule in rules
    ]
    for rule in rules:
        assert rule.file_path is not None
        assert _base(rule.file_path).is_relative_to(output)


def _print_report(
    report: dict[str, Report], counts: dict[str, dict[str, int]], rules_total: int
) -> None:
    for category in CATEGORIES:
        if category not in report or category not in counts:
            continue
        report_cat = report[category]
        print(f"=== {category} ===")
        print(f"  candidate files: {report_cat.candidates}")
        for bucket, number in sorted(report_cat.buckets.items()):
            print(f"  {bucket}: {number}")
            for example in report_cat.examples.get(bucket, []):
                print(f"    - {example}")
        if report_cat.siblings:
            print(f"  sibling of a bad file: {report_cat.siblings}")
        good_rules = sum(
            1 for item in report_cat.good for rule in item.rules if _is_selected(rule)
        )
        print(f"  good: {len(report_cat.good)} file(s), {good_rules} rule(s)")
        buckets = counts[category]
        print(f"  selected: {buckets['files']} file(s), {buckets['rules']} rule(s)")
    print(f"TOTAL vendored: {rules_total} rule(s)")


def _base(file_path: str | None) -> Path:
    return Path(str(file_path or "").split("#")[0])


def _is_selected(rule: LoadedRule) -> bool:
    return (
        rule.rule_type == RULE_TYPE_DETECTION
        and rule.compile_error is None
        and not rule.unroutable
    )


def _bucket_of(rule: LoadedRule) -> str | None:
    if rule.rule_type == RULE_TYPE_CORRELATION:
        return "correlation rule"
    if rule.compile_error is not None:
        return "compile error"
    if rule.unroutable:
        return "unroutable"
    return None


def _record(examples: dict[str, list[str]], bucket: str, classified: FileClass) -> None:
    titles = [rule.title for rule in classified.rules]
    if len(examples[bucket]) < 6:
        examples[bucket].append(classified.rel + " - " + ", ".join(titles))


if __name__ == "__main__":
    raise SystemExit(main())

"""Rule loading and health (spec 04 section 1).

Every YAML document under ``rules/builtin``, ``rules/sigma`` and
``data/rules/custom`` becomes one :class:`LoadedRule`: parsed by pySigma,
routed through the logsource map, compiled against the TriageLens backend
and hashed (SHA-256 of the file bytes). A document that fails any step still
loads - with the failure recorded - so one broken rule never blocks the
others (spec 04 section 1).

Multi-document files split into one rule per document: the file hash is
stored once per rule and the document index becomes part of ``file_path``
(``.../file.yml#2``, 1-based) when the file has more than one document.

``filter`` documents (pySigma correlation filters) are skipped here; the
engine consumes them alongside their correlation rules.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from app.config import Settings
from app.detect.compile import CompileError, compile_detection
from app.detect.routing import Route, Unroutable, build_route, load_logsource_map
from app.models.rule import (
    KIND_BUILTIN,
    KIND_CUSTOM,
    KIND_SIGMA,
    RULE_TYPE_CORRELATION,
    RULE_TYPE_DETECTION,
)
from app.util.hashing import canonical_json, sha256_bytes

#: What the shipped logsource map looks like when no path is given.
_SHIPPED_MAP = Path(__file__).resolve().parents[2] / "rules" / "logsource_map.yaml"

#: Extensions treated as rule files.
_RULE_EXTENSIONS = frozenset({".yml", ".yaml"})

#: Level names the schema accepts; anything else falls back at load time.
_LEVELS = frozenset({"informational", "low", "medium", "high", "critical"})

#: Used when a rule ships without a Sigma ``id``: stable for a given document,
#: so reloading the same file never mints a second catalogue row.
_GENERATED_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://triagelens.local/rule")


@dataclass(frozen=True, slots=True)
class LoadedRule:
    """One rule document after parse, routing and compile health checks."""

    id: str
    title: str
    #: ``builtin``, ``sigma`` or ``custom``.
    kind: str
    #: ``detection`` or ``correlation``.
    rule_type: str
    level: str
    status: str | None
    #: The single document's YAML text, as stored in ``rules.yaml``.
    yaml: str
    tags: tuple[str, ...]
    logsource: dict[str, str]
    #: ``path`` or ``path#N`` (N is 1-based) for multi-document files.
    file_path: str | None
    #: SHA-256 of the whole file's bytes.
    sha256: str
    #: ``None`` when the rule compiles; the user-facing reason otherwise.
    compile_error: str | None
    unroutable: bool
    #: The compiled route; ``None`` for correlation rules (they inherit
    #: their base rules' routes) and for documents that never parsed.
    route: Route | Unroutable | None
    #: The pySigma object; ``None`` when the document did not parse.
    sigma_rule: SigmaRule | SigmaCorrelationRule | None


@dataclass(frozen=True, slots=True)
class LoadProblem:
    """A file or document that could not be loaded at all."""

    where: str
    error: str


def load_rules(
    *,
    builtin_dir: Path | None = None,
    sigma_dir: Path | None = None,
    custom_dir: Path | None = None,
    logsource_map: Path | None = None,
) -> tuple[list[LoadedRule], list[LoadProblem]]:
    """Load every rule under the given directories.

    A ``None`` directory is skipped (no SigmaHQ rules vendored yet, no
    custom directory created yet). Returns the rules in deterministic file
    order plus the problems that prevented individual files or documents
    from loading; compile and routing failures are recorded on the rules
    themselves, not here.
    """
    table = load_logsource_map(logsource_map or _SHIPPED_MAP)
    rules: list[LoadedRule] = []
    problems: list[LoadProblem] = []
    for kind, directory, recursive in (
        (KIND_BUILTIN, builtin_dir, False),
        (KIND_SIGMA, sigma_dir, True),
        (KIND_CUSTOM, custom_dir, True),
    ):
        if directory is None:
            continue
        for path in _rule_files(directory, recursive=recursive):
            rules.extend(_load_file(kind, path, table, problems))
    return rules, problems


def load_rules_from(settings: Settings) -> tuple[list[LoadedRule], list[LoadProblem]]:
    """Load all three rule sources from a Settings object."""
    return load_rules(
        builtin_dir=settings.rules_dir / "builtin",
        sigma_dir=settings.rules_dir / "sigma",
        custom_dir=settings.custom_rules_dir,
        logsource_map=settings.rules_dir / "logsource_map.yaml",
    )


def _rule_files(directory: Path, *, recursive: bool) -> list[Path]:
    """Rule files under ``directory``, sorted so loads are reproducible."""
    if not directory.is_dir():
        return []
    candidates: Iterable[Path] = directory.rglob("*") if recursive else directory.iterdir()
    files = [
        path for path in candidates if path.is_file() and path.suffix.lower() in _RULE_EXTENSIONS
    ]
    return sorted(files, key=lambda path: str(path).lower())


def _load_file(
    kind: str,
    path: Path,
    table: dict[str, dict[str, str]],
    problems: list[LoadProblem],
) -> list[LoadedRule]:
    """One file's documents; YAML-level failures become problems."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        problems.append(LoadProblem(str(path), f"cannot read file: {exc}"))
        return []
    digest = sha256_bytes(raw)
    try:
        documents = list(yaml.safe_load_all(_decode(raw)))
    except yaml.YAMLError as exc:
        problems.append(LoadProblem(str(path), f"invalid YAML: {exc}"))
        return []

    multiple = sum(1 for document in documents if document is not None) > 1
    loaded: list[LoadedRule] = []
    for position, document in enumerate(documents, start=1):
        if document is None:
            continue  # trailing separator or an empty slot
        where = f"{path}#{position}" if multiple else str(path)
        if not isinstance(document, dict):
            problems.append(LoadProblem(where, "document is not a mapping"))
            continue
        if "filter" in document:
            continue  # pySigma correlation filter; the engine reads it from yaml
        loaded.append(
            _load_document(
                kind,
                path,
                position=position,
                document=document,
                digest=digest,
                table=table,
                problems=problems,
                where=where,
                multiple=multiple,
            )
        )
    return loaded


def _load_document(
    kind: str,
    path: Path,
    *,
    position: int,
    document: dict[str, Any],
    digest: str,
    table: dict[str, dict[str, str]],
    problems: list[LoadProblem],
    where: str,
    multiple: bool,
) -> LoadedRule:
    """One document: dump first, then parse, route and compile."""
    yaml_text = yaml.safe_dump(
        document, sort_keys=False, default_flow_style=False, allow_unicode=True
    )
    rule_type = RULE_TYPE_CORRELATION if "correlation" in document else RULE_TYPE_DETECTION
    generated_id = str(uuid.uuid5(_GENERATED_NAMESPACE, canonical_json(_jsonable(document))))

    parsed: SigmaRule | SigmaCorrelationRule | None = None
    compile_error: str | None = None
    try:
        if rule_type == RULE_TYPE_CORRELATION:
            parsed = SigmaCorrelationRule.from_dict(_without_generate(document))
        else:
            parsed = SigmaRule.from_dict(document)
    except Exception as exc:
        compile_error = _describe(exc)
        problems.append(LoadProblem(where, f"cannot parse rule: {compile_error}"))

    identifier = str(parsed.id) if parsed is not None and parsed.id else generated_id
    logsource = _logsource_of(parsed, document)
    route: Route | Unroutable | None = _route_for(table, rule_type, logsource)
    unroutable = isinstance(route, Unroutable)

    if isinstance(parsed, SigmaRule):
        try:
            compile_detection(parsed)
        except CompileError as exc:
            compile_error = str(exc)

    return LoadedRule(
        id=identifier,
        title=_title_of(parsed, document, path, position),
        kind=kind,
        rule_type=rule_type,
        level=_level_of(parsed, document),
        status=_status_of(parsed, document),
        yaml=yaml_text,
        tags=_tags_of(parsed, document),
        logsource=logsource,
        file_path=f"{path}#{position}" if multiple else str(path),
        sha256=digest,
        compile_error=compile_error,
        unroutable=unroutable,
        route=route,
        sigma_rule=parsed,
    )


def _without_generate(document: dict[str, Any]) -> dict[str, Any]:
    """The document without the engine's ``generate`` extension key.

    ``correlation.generate`` (spec 04 section 5 step 4) is a TriageLens
    convention pySigma does not model; it is stripped before the parse so a
    rule using it stays healthy, and kept in the stored YAML for the
    correlation stage to read.
    """
    block = document.get("correlation")
    if not isinstance(block, dict) or "generate" not in block:
        return document
    return {**document, "correlation": {k: v for k, v in block.items() if k != "generate"}}


def _decode(raw: bytes) -> str:
    """YAML text; latin-1 never fails, so odd vendor encodings still load."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _jsonable(value: Any) -> Any:
    """A safe-to-hash copy: YAML dates and times are not JSON values."""
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _logsource_of(
    parsed: SigmaRule | SigmaCorrelationRule | None, document: dict[str, Any]
) -> dict[str, str]:
    """The rule's logsource in lower-case keys; ``{}`` for correlations."""
    logsource = getattr(parsed, "logsource", None)
    if logsource is not None:
        return {str(key): str(value) for key, value in logsource.to_dict().items()}
    raw = document.get("logsource")
    if isinstance(raw, dict):
        return {str(key): str(value) for key, value in raw.items() if value is not None}
    return {}


def _route_for(
    table: dict[str, dict[str, str]],
    rule_type: str,
    logsource: dict[str, str],
) -> Route | Unroutable | None:
    """Compile the logsource route; ``None`` for correlation rules.

    An empty predicate (a detection whose logsource never parsed) is
    unroutable rather than match-everything: routing must never silently
    widen to all events (spec 04 section 3).
    """
    if rule_type == RULE_TYPE_CORRELATION:
        return None
    route = build_route(
        table,
        logsource.get("product"),
        logsource.get("service"),
        logsource.get("category"),
    )
    if isinstance(route, Route) and not route.sql.strip():
        return Unroutable("rule has no logsource", logsource)
    return route


def _title_of(
    parsed: SigmaRule | SigmaCorrelationRule | None,
    document: dict[str, Any],
    path: Path,
    position: int,
) -> str:
    title = getattr(parsed, "title", None)
    if isinstance(title, str) and title:
        return title
    raw = document.get("title")
    if isinstance(raw, str) and raw:
        return raw
    return f"{path.name}#{position}"


def _level_of(parsed: SigmaRule | SigmaCorrelationRule | None, document: dict[str, Any]) -> str:
    level = getattr(parsed, "level", None)
    name = getattr(level, "name", None)
    if isinstance(name, str) and name.lower() in _LEVELS:
        return name.lower()
    raw = document.get("level")
    if isinstance(raw, str) and raw.lower() in _LEVELS:
        return raw.lower()
    return "informational"


def _status_of(
    parsed: SigmaRule | SigmaCorrelationRule | None, document: dict[str, Any]
) -> str | None:
    status = getattr(parsed, "status", None)
    name = getattr(status, "name", None)
    if isinstance(name, str) and name:
        return name.lower()
    raw = document.get("status")
    if isinstance(raw, str) and raw:
        return raw.lower()
    return None


def _tags_of(
    parsed: SigmaRule | SigmaCorrelationRule | None, document: dict[str, Any]
) -> tuple[str, ...]:
    """Tags in rule spelling (``attack.t1110.001``), order preserved."""
    source = getattr(parsed, "tags", None)
    if source is None:
        source = document.get("tags") or []
    tags: list[str] = []
    for tag in source:
        namespace = getattr(tag, "namespace", None)
        name = getattr(tag, "name", None)
        if isinstance(namespace, str) and isinstance(name, str):
            tags.append(f"{namespace}.{name}")
        elif isinstance(tag, str):
            tags.append(tag)
        else:
            tags.append(str(tag))
    return tuple(dict.fromkeys(tags))


def _describe(exc: Exception) -> str:
    try:
        return str(exc) or exc.__class__.__name__
    except Exception:
        return exc.__class__.__name__


__all__ = [
    "KIND_BUILTIN",
    "KIND_CUSTOM",
    "KIND_SIGMA",
    "RULE_TYPE_CORRELATION",
    "RULE_TYPE_DETECTION",
    "LoadProblem",
    "LoadedRule",
    "load_rules",
    "load_rules_from",
]

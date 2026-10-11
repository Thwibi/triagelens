"""Configuration loading for TriageLens (spec 01 section 6).

Precedence, lowest to highest:

1. the built-in defaults in this module,
2. ``config.toml`` (searched at ``TRIAGELENS_CONFIG``, then ``./config.toml``,
   then ``backend/config.toml``),
3. environment variables ``TRIAGELENS_<SECTION>__<KEY>``.

The object refuses to load when ``[server].host`` is not a loopback address and
``[server].auth_token`` is empty (spec 10 section 1, "Unintended network
exposure").
"""

from __future__ import annotations

import ipaddress
import json
import os
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Literal, Self, TypeVar, get_args

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

#: ``backend/`` - the directory holding ``pyproject.toml`` and ``migrations/``.
BACKEND_ROOT: Path = Path(__file__).resolve().parent.parent

ENV_PREFIX = "TRIAGELENS"
ENV_SEPARATOR = "__"

#: Shortest bearer token accepted when one is configured. A shorter token is
#: rejected rather than silently accepted, because the token is the only thing
#: standing between a LAN-bound instance and an unauthenticated caller.
MIN_AUTH_TOKEN_LENGTH = 16

ModelT = TypeVar("ModelT", bound=BaseModel)


class ConfigError(RuntimeError):
    """Configuration is unusable; the process must not start."""


def _split_list(value: Any) -> Any:
    """Accept a comma-separated string or a JSON array for list fields.

    Entries are stripped, lowercased and de-duplicated so hostnames compare
    case-insensitively and a repeated entry cannot widen a set twice.
    """
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"not a valid JSON array: {exc.msg}") from exc
            if not isinstance(parsed, list):
                raise ValueError("expected a JSON array")
            return parsed
        value = text.split(",")
    if isinstance(value, list):
        seen: dict[str, str] = {}
        for item in value:
            if not isinstance(item, str):
                raise TypeError(f"list entries must be strings, got {type(item).__name__}")
            cleaned = item.strip().lower()
            if cleaned:
                seen.setdefault(cleaned, cleaned)
        return list(seen.values())
    return value


CsvList = Annotated[list[str], BeforeValidator(_split_list)]


def _blank_to_none(value: Path | str | None) -> Path | None:
    """Treat an empty or whitespace-only string as "unset".

    ``Path("")`` stringifies to ``"."``, so an empty ``log_dir`` in config.toml
    would otherwise silently resolve to the current working directory instead of
    falling back to ``<data_dir>/logs``.
    """
    if value is None:
        return None
    text = str(value).strip()
    return None if text == "" else Path(text)


class _Section(BaseModel):
    """Base for every config section: unknown keys are a hard error."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class ServerConfig(_Section):
    """HTTP server binding and access control."""

    host: str = "127.0.0.1"
    port: int = Field(default=8787, ge=1, le=65535)
    auth_token: str = ""
    allowed_hosts: CsvList = Field(
        default_factory=list,
        description=(
            "Extra names accepted in the Host header; localhost/127.0.0.1/::1 are always allowed."
        ),
    )

    @field_validator("auth_token", mode="after")
    @classmethod
    def _check_token_strength(cls, value: str) -> str:
        """A set token must be long enough to be unguessable.

        An empty token stays valid here; whether a token is *required* is decided
        by :meth:`Settings._refuse_unsafe_bind`, which knows the bind address.
        """
        token = value.strip()
        if token and len(token) < MIN_AUTH_TOKEN_LENGTH:
            raise ValueError(
                f"server.auth_token must be at least {MIN_AUTH_TOKEN_LENGTH} characters when set"
            )
        return token

    @property
    def bind_display(self) -> str:
        """Human readable bind target for logs (never includes the token)."""
        return f"{self.host}:{self.port}"


class StorageConfig(_Section):
    """Where evidence lives on disk."""

    data_dir: Path = Path("./data")
    allowed_import_roots: CsvList = Field(default_factory=list)
    secure_delete: bool = False

    @model_validator(mode="after")
    def _default_import_roots(self) -> Self:
        if not self.allowed_import_roots:
            self.allowed_import_roots = [
                str(Path.home()),
                str(self.resolved_data_dir / "imports"),
            ]
        return self

    @property
    def resolved_data_dir(self) -> Path:
        """``data_dir`` as an absolute path."""
        return _resolve(self.data_dir)


class LimitsConfig(_Section):
    """Resource bounds applied to hostile input (spec 10 section 1)."""

    max_upload_gb: int = Field(default=10, gt=0)
    max_line_bytes: int = Field(default=1048576, gt=0)
    max_events_per_source: int = Field(default=50_000_000, gt=0)
    max_archive_expansion_ratio: int = Field(default=100, gt=0)
    max_archive_total_gb: int = Field(default=50, gt=0)
    max_archive_depth: int = Field(default=3, ge=1)
    max_archive_members: int = Field(default=10_000, gt=0)
    worker_processes: int = Field(default=0, ge=0)
    min_free_disk_fraction: float = Field(default=0.05, ge=0.0, lt=1.0)

    @property
    def max_upload_bytes(self) -> int:
        """``max_upload_gb`` as bytes."""
        return self.max_upload_gb * 1024 * 1024 * 1024

    @property
    def max_archive_total_bytes(self) -> int:
        """``max_archive_total_gb`` as bytes."""
        return self.max_archive_total_gb * 1024 * 1024 * 1024


class DetectionConfig(_Section):
    """Detection engine behaviour."""

    profile: Literal["fast", "standard", "full"] = "standard"
    auto_run_after_ingest: bool = True
    #: Seeds the shipped rule tree into the catalogue when it is empty (first run).
    #: Restarts skip the 4-5 s load once rows exist, and ``enabled`` flags survive.
    sync_rules_on_startup: bool = True
    max_sample_events_per_alert: int = Field(default=500, ge=0)
    rule_timeout_seconds: int = Field(default=120, gt=0)
    alert_group_window_minutes: int = Field(default=60, gt=0)


class IocConfig(_Section):
    """IOC extraction behaviour."""

    extract_private_ips: bool = True
    decode_depth: int = Field(default=2, ge=0, le=4)


class NetworkConfig(_Section):
    """Outbound network policy. False means the process opens no sockets."""

    allow_enrichment: bool = False


class UiConfig(_Section):
    """Frontend defaults."""

    default_theme: Literal["dark", "light"] = "dark"


class LoggingConfig(_Section):
    """Structured logging (spec 01 section 7)."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_dir: Path | None = Field(
        default=None,
        description="Directory for triagelens.log; null or empty means <data_dir>/logs.",
    )
    file_max_bytes: int = Field(default=20 * 1024 * 1024, gt=0)
    file_backup_count: int = Field(default=5, ge=0)
    console: bool = True

    _blank_log_dir = field_validator("log_dir", mode="before")(_blank_to_none)


class Settings(BaseModel):
    """The fully validated TriageLens configuration."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    server: ServerConfig = Field(default_factory=ServerConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    ioc: IocConfig = Field(default_factory=IocConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    ui: UiConfig = Field(default_factory=UiConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    #: Where the values came from; ``None`` when built-in defaults were used.
    config_path: Path | None = None

    @model_validator(mode="after")
    def _refuse_unsafe_bind(self) -> Self:
        if not is_loopback_host(self.server.host) and not self.server.auth_token.strip():
            raise ValueError(
                "server.auth_token must be set to a non-empty value when server.host "
                f"is {self.server.host!r} (not a loopback address); refusing to start"
            )
        return self

    # -- derived paths ---------------------------------------------------

    @property
    def package_root(self) -> Path:
        """``backend/``."""
        return BACKEND_ROOT

    @property
    def data_dir(self) -> Path:
        """Absolute path of the data directory."""
        return self.storage.resolved_data_dir

    @property
    def db_path(self) -> Path:
        """SQLite database file."""
        return self.data_dir / "triagelens.db"

    @property
    def cases_dir(self) -> Path:
        """Per-case evidence directories."""
        return self.data_dir / "cases"

    @property
    def reports_dir(self) -> Path:
        """Generated reports."""
        return self.data_dir / "reports"

    @property
    def imports_dir(self) -> Path:
        """Default drop location for from-path imports."""
        return self.data_dir / "imports"

    @property
    def logs_dir(self) -> Path:
        """Rotating application log directory."""
        configured = self.logging.log_dir
        return _resolve(configured) if configured is not None else self.data_dir / "logs"

    @property
    def log_file(self) -> Path:
        """Rotating application log file."""
        return self.logs_dir / "triagelens.log"

    @property
    def static_dir(self) -> Path:
        """Built frontend served by the API process."""
        return BACKEND_ROOT / "app" / "static"

    @property
    def migrations_dir(self) -> Path:
        """SQL migration files."""
        return BACKEND_ROOT / "migrations"

    @property
    def rules_dir(self) -> Path:
        """Vendored and built-in Sigma rules."""
        return BACKEND_ROOT / "rules"

    @property
    def custom_rules_dir(self) -> Path:
        """User-authored rules (spec 10 section 5, disk layout)."""
        return self.data_dir / "rules" / "custom"

    @property
    def bundled_data_dir(self) -> Path:
        """Read-only bundled data (ATT&CK bundle, IANA TLDs, profiles)."""
        return BACKEND_ROOT / "data"

    @property
    def resolved_import_roots(self) -> tuple[Path, ...]:
        """Absolute, de-duplicated import roots."""
        seen: dict[str, Path] = {}
        for raw in self.storage.allowed_import_roots:
            resolved = _resolve(Path(raw))
            seen.setdefault(str(resolved).lower(), resolved)
        return tuple(seen.values())

    @property
    def effective_worker_processes(self) -> int:
        """Worker process count after resolving ``0`` to ``cpu_count - 1``."""
        import os as _os

        if self.limits.worker_processes > 0:
            return self.limits.worker_processes
        return max(1, (_os.cpu_count() or 2) - 1)

    @property
    def is_loopback_bind(self) -> bool:
        """True when the server is only reachable from this machine."""
        return is_loopback_host(self.server.host)

    # -- host header allowlist (spec 10 section 1, DNS rebinding) --------

    @property
    def allowed_host_names(self) -> frozenset[str]:
        """Names accepted in the ``Host`` header, always including loopback."""
        names = {"localhost", "127.0.0.1", "::1", self.server.host}
        for extra in self.server.allowed_hosts:
            names.add(extra)
        return frozenset(name.strip().lower() for name in names if name.strip())

    def csp_connect_src(self) -> str:
        """``connect-src`` for the CSP header (spec 10 section 1)."""
        sources = [
            "'self'",
            "ws://127.0.0.1:*",
            "ws://localhost:*",
        ]
        host = self.server.host
        if not is_loopback_host(host):
            sources.append(f"ws://{host}:{self.server.port}")
            sources.append(f"wss://{host}:{self.server.port}")
        return " ".join(sources)

    def redacted(self) -> dict[str, Any]:
        """Config snapshot for diagnostics with the auth token removed."""
        data = self.model_dump(mode="json")
        server = data.get("server")
        if isinstance(server, dict):
            server["auth_token"] = "***redacted***" if self.server.auth_token else ""
        data["config_path"] = str(self.config_path) if self.config_path else None
        return data


def _resolve(path: Path) -> Path:
    """Expand ``~`` and environment variables, then make the path absolute."""
    expanded = Path(os.path.expandvars(str(path))).expanduser()
    if not expanded.is_absolute():
        expanded = Path.cwd() / expanded
    return Path(os.path.normpath(expanded))


def normalize_host(raw: str) -> str:
    """Reduce a ``Host`` header to a comparable hostname.

    Strips an optional port, unwraps IPv6 brackets, lowercases and trims. A bare
    IPv6 literal such as ``::1`` has more than one colon and therefore carries no
    port, so it is returned intact.
    """
    candidate = raw.strip().lower()
    if candidate.startswith("["):
        closing = candidate.find("]")
        if closing != -1:
            return candidate[1:closing]
        return candidate
    if candidate.count(":") == 1:
        return candidate.rsplit(":", 1)[0]
    return candidate


def is_loopback_host(host: str) -> bool:
    """True when ``host`` only accepts connections from this machine."""
    candidate = normalize_host(host)
    if candidate in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def _config_search_paths(explicit: Path | None, environ: Mapping[str, str]) -> list[Path]:
    """Candidate config.toml locations, most specific first."""
    if explicit is not None:
        return [explicit]
    candidates: list[Path] = []
    from_env = environ.get(f"{ENV_PREFIX}_CONFIG")
    if from_env:
        candidates.append(Path(from_env))
    candidates.append(Path.cwd() / "config.toml")
    candidates.append(BACKEND_ROOT / "config.toml")
    return candidates


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            loaded = tomllib.load(handle)
    except OSError as exc:
        raise ConfigError(f"{path}: cannot be read: {exc.strerror}") from None
    except tomllib.TOMLDecodeError:
        # Never echo the offending text or line: a config file may hold a token.
        # TOMLDecodeError carries no line number on all supported versions.
        raise ConfigError(f"{path}: invalid TOML syntax") from None
    if not isinstance(loaded, dict):
        raise ConfigError(f"{path}: top level of config.toml must be a table")
    return loaded


def _section_field_types() -> dict[str, dict[str, Any]]:
    """Field annotations per config section, used to coerce env strings."""
    sections: dict[str, dict[str, Any]] = {}
    for name, field in Settings.model_fields.items():
        annotation = field.annotation
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            sections[name] = dict(annotation.model_fields)
    return sections


def _env_overrides(environ: Mapping[str, str]) -> dict[str, dict[str, Any]]:
    """Parse ``TRIAGELENS_<SECTION>__<KEY>`` variables into nested dicts."""
    result: dict[str, dict[str, Any]] = {}
    for name, raw in environ.items():
        if not name.startswith(f"{ENV_PREFIX}_"):
            continue
        remainder = name[len(ENV_PREFIX) + 1 :]
        if ENV_SEPARATOR not in remainder:
            continue
        section, _, key = remainder.partition(ENV_SEPARATOR)
        section = section.lower()
        key = key.lower()
        if not section or not key:
            continue
        result.setdefault(section, {})[key] = raw
    return result


def _merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``overlay`` into a copy of ``base``."""
    merged = dict(base)
    for key, value in overlay.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = _merge(existing, value)
        else:
            merged[key] = value
    return merged


def _validate(raw: dict[str, Any], source: str) -> Settings:
    try:
        return Settings(**raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors(include_input=False, include_url=False)
        )
        raise ConfigError(f"invalid configuration from {source}: {problems}") from None


def load_settings(
    config_path: Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> Settings:
    """Load, merge and validate the configuration.

    Precedence is defaults, then the config file, then the environment.

    ``environ`` exists so tests can supply an isolated environment. It is read
    as a plain mapping and never installed into :data:`os.environ`, because
    clearing the real environment would break anything that resolves paths
    (``Path.home()``, ``PATH``) while the settings are being validated.
    """
    source: Mapping[str, str] = os.environ if environ is None else environ

    raw: dict[str, Any] = {}
    used_path: Path | None = None
    for candidate in _config_search_paths(config_path, source):
        if candidate.is_file():
            raw = _read_toml(candidate)
            used_path = candidate
            break
    if config_path is not None and used_path is None:
        raise ConfigError(f"config file not found: {config_path}")

    raw = _merge(raw, _env_overrides(source))
    settings = _validate(raw, str(used_path) if used_path else "built-in defaults")
    settings.config_path = used_path
    return settings


def config_field_names() -> tuple[str, ...]:
    """Every ``section.key`` this build understands, for docs and tests."""
    names: list[str] = []
    for section, fields in _section_field_types().items():
        names.extend(f"{section}.{key}" for key in fields)
    return tuple(sorted(names))


def profile_values() -> tuple[str, ...]:
    """Accepted detection profile names."""
    annotation = DetectionConfig.model_fields["profile"].annotation
    if get_args(annotation):
        return tuple(str(value) for value in get_args(annotation))
    return ()


__all__ = [
    "BACKEND_ROOT",
    "ENV_PREFIX",
    "ENV_SEPARATOR",
    "ConfigError",
    "CsvList",
    "DetectionConfig",
    "IocConfig",
    "LimitsConfig",
    "LoggingConfig",
    "NetworkConfig",
    "ServerConfig",
    "Settings",
    "StorageConfig",
    "UiConfig",
    "config_field_names",
    "is_loopback_host",
    "load_settings",
    "normalize_host",
    "profile_values",
]

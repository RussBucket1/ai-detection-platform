"""Tests for IOC parsing, classification, and normalization."""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from ioc_enricher.ioc_parser import IOCParser
from ioc_enricher.models.ioc import IOCType


@pytest.fixture
def parser() -> IOCParser:
    """Return a fresh IOCParser instance."""
    return IOCParser()


class TestRefang:
    """Tests for IOCParser.refang() defanging reversal."""

    def test_bracketed_dot(self, parser: IOCParser) -> None:
        assert parser.refang("192[.]168[.]1[.]1") == "192.168.1.1"

    def test_multiple_bracketed_dots(self, parser: IOCParser) -> None:
        assert parser.refang("evil[.]example[.]com") == "evil.example.com"

    def test_hxxp(self, parser: IOCParser) -> None:
        assert parser.refang("hxxp://evil.com") == "http://evil.com"

    def test_hxxps(self, parser: IOCParser) -> None:
        assert parser.refang("hxxps://evil.com/path") == "https://evil.com/path"

    def test_bracketed_colon(self, parser: IOCParser) -> None:
        assert parser.refang("http[:]//evil.com") == "http://evil.com"

    def test_paren_dot(self, parser: IOCParser) -> None:
        assert parser.refang("evil(.)com") == "evil.com"

    def test_at_notation(self, parser: IOCParser) -> None:
        assert parser.refang("user[at]example.com") == "user@example.com"

    def test_no_change_needed(self, parser: IOCParser) -> None:
        assert parser.refang("192.168.1.1") == "192.168.1.1"

    def test_strips_whitespace(self, parser: IOCParser) -> None:
        assert parser.refang("  192.168.1.1  ") == "192.168.1.1"


class TestClassify:
    """Tests for IOCParser.classify() type detection."""

    def test_ipv4(self, parser: IOCParser) -> None:
        assert parser.classify("192.168.1.1") == IOCType.IPV4

    def test_ipv4_public(self, parser: IOCParser) -> None:
        assert parser.classify("8.8.8.8") == IOCType.IPV4

    def test_ipv4_edge(self, parser: IOCParser) -> None:
        assert parser.classify("0.0.0.0") == IOCType.IPV4

    def test_ipv4_broadcast(self, parser: IOCParser) -> None:
        assert parser.classify("255.255.255.255") == IOCType.IPV4

    def test_ipv6_full(self, parser: IOCParser) -> None:
        assert parser.classify("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == IOCType.IPV6

    def test_ipv6_compressed(self, parser: IOCParser) -> None:
        assert parser.classify("2001:db8::1") == IOCType.IPV6

    def test_ipv6_common(self, parser: IOCParser) -> None:
        assert parser.classify("::1") == IOCType.IPV6

    def test_md5(self, parser: IOCParser) -> None:
        assert parser.classify("d41d8cd98f00b204e9800998ecf8427e") == IOCType.MD5

    def test_md5_uppercase(self, parser: IOCParser) -> None:
        assert parser.classify("D41D8CD98F00B204E9800998ECF8427E") == IOCType.MD5

    def test_sha1(self, parser: IOCParser) -> None:
        assert parser.classify("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IOCType.SHA1

    def test_sha256(self, parser: IOCParser) -> None:
        assert parser.classify(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) == IOCType.SHA256

    def test_http_url(self, parser: IOCParser) -> None:
        assert parser.classify("http://evil.com/malware.exe") == IOCType.URL

    def test_https_url(self, parser: IOCParser) -> None:
        assert parser.classify("https://evil.com/path?q=1") == IOCType.URL

    def test_ftp_url(self, parser: IOCParser) -> None:
        assert parser.classify("ftp://files.evil.com/bad.zip") == IOCType.URL

    def test_domain(self, parser: IOCParser) -> None:
        assert parser.classify("evil.com") == IOCType.DOMAIN

    def test_domain_tld_only(self, parser: IOCParser) -> None:
        result = parser.classify("com")
        assert result == IOCType.UNKNOWN

    def test_domain_country_tld(self, parser: IOCParser) -> None:
        assert parser.classify("malware.co.uk") == IOCType.DOMAIN

    def test_email(self, parser: IOCParser) -> None:
        assert parser.classify("attacker@evil.com") == IOCType.EMAIL

    def test_unknown_gibberish(self, parser: IOCParser) -> None:
        assert parser.classify("not-an-ioc-!!!") == IOCType.UNKNOWN

    def test_unknown_empty(self, parser: IOCParser) -> None:
        assert parser.classify("") == IOCType.UNKNOWN

    def test_unknown_partial_ip(self, parser: IOCParser) -> None:
        assert parser.classify("192.168.1") == IOCType.UNKNOWN


class TestParse:
    """Tests for IOCParser.parse() full parse pipeline."""

    def test_parse_defanged_ip(self, parser: IOCParser) -> None:
        ioc = parser.parse("192[.]168[.]1[.]1")
        assert ioc is not None
        assert ioc.value == "192.168.1.1"
        assert ioc.ioc_type == IOCType.IPV4

    def test_parse_defanged_url(self, parser: IOCParser) -> None:
        ioc = parser.parse("hxxps://evil[.]com/path")
        assert ioc is not None
        assert ioc.ioc_type == IOCType.URL
        assert ioc.value.startswith("https://")

    def test_parse_attaches_source(self, parser: IOCParser) -> None:
        ioc = parser.parse("8.8.8.8", source="test-feed")
        assert ioc is not None
        assert ioc.source == "test-feed"

    def test_parse_attaches_tags(self, parser: IOCParser) -> None:
        ioc = parser.parse("8.8.8.8", tags=["dns", "google"])
        assert ioc is not None
        assert "dns" in ioc.tags
        assert "google" in ioc.tags

    def test_parse_empty_returns_none(self, parser: IOCParser) -> None:
        assert parser.parse("") is None
        assert parser.parse("   ") is None

    def test_parse_unknown_still_returns_ioc(self, parser: IOCParser) -> None:
        ioc = parser.parse("definitely-not-an-ioc-###")
        assert ioc is not None
        assert ioc.ioc_type == IOCType.UNKNOWN

    def test_parse_list_deduplicates(self, parser: IOCParser) -> None:
        values = ["8.8.8.8", "8.8.8.8", "1.1.1.1"]
        results = parser.parse_list(values, skip_unknown=False)
        assert len(results) == 2
        assert {r.value for r in results} == {"8.8.8.8", "1.1.1.1"}

    def test_parse_list_skips_unknown_by_default(self, parser: IOCParser) -> None:
        values = ["8.8.8.8", "not-an-ioc-###", "1.1.1.1"]
        results = parser.parse_list(values)
        assert len(results) == 2
        assert all(r.ioc_type != IOCType.UNKNOWN for r in results)

    def test_parse_list_keeps_unknown_when_configured(self, parser: IOCParser) -> None:
        values = ["8.8.8.8", "not-an-ioc-###"]
        results = parser.parse_list(values, skip_unknown=False)
        assert len(results) == 2


class TestParseFile:
    """Tests for IOCParser.parse_file() file ingestion."""

    def test_parse_file_basic(self, parser: IOCParser, tmp_path: Path) -> None:
        ioc_file = tmp_path / "iocs.txt"
        ioc_file.write_text("8.8.8.8\n# this is a comment\nevil.com\n1.1.1.1\n")
        results = parser.parse_file(ioc_file)
        assert len(results) == 3

    def test_parse_file_deduplicates(self, parser: IOCParser, tmp_path: Path) -> None:
        ioc_file = tmp_path / "iocs.txt"
        ioc_file.write_text("8.8.8.8\n8.8.8.8\nevil.com\n")
        results = parser.parse_file(ioc_file)
        assert len(results) == 2

    def test_parse_file_skips_blank_lines(self, parser: IOCParser, tmp_path: Path) -> None:
        ioc_file = tmp_path / "iocs.txt"
        ioc_file.write_text("8.8.8.8\n\n\nevil.com\n")
        results = parser.parse_file(ioc_file)
        assert len(results) == 2

    def test_parse_file_not_found(self, parser: IOCParser) -> None:
        with pytest.raises(FileNotFoundError):
            parser.parse_file("/nonexistent/path/iocs.txt")

    def test_parse_file_defanged(self, parser: IOCParser, tmp_path: Path) -> None:
        ioc_file = tmp_path / "iocs.txt"
        ioc_file.write_text("192[.]168[.]1[.]1\nhxxps://evil[.]com/path\n")
        results = parser.parse_file(ioc_file)
        assert len(results) == 2
        values = {r.value for r in results}
        assert "192.168.1.1" in values


class TestFingerprint:
    """Tests for IOC.fingerprint property."""

    def test_fingerprint_deterministic(self, parser: IOCParser) -> None:
        ioc1 = parser.parse("8.8.8.8")
        ioc2 = parser.parse("8.8.8.8")
        assert ioc1 is not None and ioc2 is not None
        assert ioc1.fingerprint == ioc2.fingerprint

    def test_fingerprint_case_insensitive(self, parser: IOCParser) -> None:
        ioc1 = parser.parse("D41D8CD98F00B204E9800998ECF8427E")
        ioc2 = parser.parse("d41d8cd98f00b204e9800998ecf8427e")
        assert ioc1 is not None and ioc2 is not None
        assert ioc1.fingerprint == ioc2.fingerprint

    def test_fingerprint_different_for_different_values(self, parser: IOCParser) -> None:
        ioc1 = parser.parse("8.8.8.8")
        ioc2 = parser.parse("1.1.1.1")
        assert ioc1 is not None and ioc2 is not None
        assert ioc1.fingerprint != ioc2.fingerprint

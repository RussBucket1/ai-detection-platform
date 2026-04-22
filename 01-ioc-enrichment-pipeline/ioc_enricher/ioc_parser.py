"""IOC parsing, type detection, normalization, and bulk ingestion."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Iterator

import tldextract

from ioc_enricher.models.ioc import IOC, IOCType
from ioc_enricher.utils.logger import get_logger

_log = get_logger(__name__)

_DEFANG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\[?\.\]?", re.IGNORECASE), "."),
    (re.compile(r"\[:\]", re.IGNORECASE), ":"),
    (re.compile(r"hxxps?", re.IGNORECASE), lambda m: m.group(0).lower().replace("hxxp", "http")),  # type: ignore[arg-type]
    (re.compile(r"\(\.\)", re.IGNORECASE), "."),
    (re.compile(r"\[at\]", re.IGNORECASE), "@"),
]

_URL_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9+\-.]*://"
    r"[^\s/$.?#].[^\s]*$",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class IOCParser:
    """Parses, classifies, and normalizes raw IOC values into typed IOC objects."""

    def refang(self, value: str) -> str:
        """Reverse common defanging patterns to restore the original indicator."""
        result = value.strip()
        result = re.sub(r"hxxps", "https", result, flags=re.IGNORECASE)
        result = re.sub(r"hxxp", "http", result, flags=re.IGNORECASE)
        result = result.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[at]", "@")
        return result

    def classify(self, value: str) -> IOCType:
        """Determine the IOCType of a value using priority-ordered heuristics."""
        v = value.strip()
        if not v:
            return IOCType.UNKNOWN

        if _HEX_RE.match(v):
            length = len(v)
            if length == 32:
                return IOCType.MD5
            if length == 40:
                return IOCType.SHA1
            if length == 64:
                return IOCType.SHA256

        try:
            parsed = ipaddress.ip_address(v)
            if isinstance(parsed, ipaddress.IPv4Address):
                return IOCType.IPV4
            return IOCType.IPV6
        except ValueError:
            pass

        if _URL_RE.match(v):
            return IOCType.URL

        if _EMAIL_RE.match(v):
            return IOCType.EMAIL

        ext = tldextract.extract(v)
        if ext.domain and ext.suffix and not re.search(r"[/\s]", v):
            return IOCType.DOMAIN

        return IOCType.UNKNOWN

    def parse(
        self,
        raw_value: str,
        source: str = "manual",
        tags: list[str] | None = None,
    ) -> IOC | None:
        """Parse a raw string into an IOC. Returns None for empty input.

        UNKNOWN types are logged as warnings but still returned.
        """
        if not raw_value or not raw_value.strip():
            return None

        refanged = self.refang(raw_value)
        ioc_type = self.classify(refanged)

        if ioc_type == IOCType.UNKNOWN:
            _log.warning("unknown_ioc_type", value=refanged)

        return IOC(
            value=refanged,
            ioc_type=ioc_type,
            source=source,
            tags=tags or [],
        )

    def parse_list(
        self,
        values: list[str],
        source: str = "list",
        skip_unknown: bool = True,
    ) -> list[IOC]:
        """Parse a list of raw strings into deduplicated IOC objects."""
        seen: set[str] = set()
        results: list[IOC] = []
        for raw in values:
            ioc = self.parse(raw, source=source)
            if ioc is None:
                continue
            if skip_unknown and ioc.ioc_type == IOCType.UNKNOWN:
                continue
            fp = ioc.fingerprint
            if fp not in seen:
                seen.add(fp)
                results.append(ioc)
        return results

    def parse_file(
        self,
        path: str | Path,
        source: str = "file",
        skip_unknown: bool = True,
    ) -> list[IOC]:
        """Parse IOCs from a flat text file (one per line, # comments skipped).

        Raises FileNotFoundError if the path does not exist.
        Returns deduplicated IOC list with parse stats logged.
        """
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"IOC file not found: {file_path}")

        seen: set[str] = set()
        results: list[IOC] = []
        total = 0
        skipped_unknown = 0

        for raw in self._iter_lines(file_path):
            total += 1
            ioc = self.parse(raw, source=source)
            if ioc is None:
                continue
            if skip_unknown and ioc.ioc_type == IOCType.UNKNOWN:
                skipped_unknown += 1
                continue
            fp = ioc.fingerprint
            if fp not in seen:
                seen.add(fp)
                results.append(ioc)

        _log.info(
            "parse_file_complete",
            path=str(file_path),
            total_lines=total,
            parsed=len(results),
            skipped_unknown=skipped_unknown,
            duplicates=total - skipped_unknown - len(results),
        )
        return results

    def _iter_lines(self, path: Path) -> Iterator[str]:
        """Yield non-empty, non-comment lines from a file."""
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    yield stripped

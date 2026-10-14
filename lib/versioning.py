"""Safe version parsing + affected-range evaluation (Pass 3C).

Used by the CVE pipeline to decide whether a *detected* product version
falls into an *affected* range — instead of "the product name exists".

Classification outputs (functions never raise):

- ``affected``   — version provably inside an affected range / exact match
- ``unaffected`` — version provably outside every affected range
- ``unknown``    — version missing/unparseable, or range bounds unevaluable
- ``candidate``  — name-level match only (no usable version evidence)

Nothing here performs validation against live targets; it is pure
string/number logic used before anything is ever claimed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

STATUSES = ("affected", "unaffected", "unknown", "candidate")

_MAX_VERSION_LEN = 64
_RELEASE_RE = re.compile(r"^(\d+(?:\.\d+)*)([^\d].*)?$")


def parse_version(version: str) -> tuple[list[int], str] | None:
    """Split a version into (numeric parts, suffix); ``None`` if unparseable.

    Examples: ``6.0`` -> ([6, 0], ""); ``1.2.3-rc1`` -> ([1, 2, 3], "rc1");
    ``v2.4`` -> ([2, 4], ""); ``not-a-version`` -> None (no leading number).
    """
    s = str(version or "").strip().lower()
    if not s or len(s) > _MAX_VERSION_LEN:
        return None
    s = s.lstrip("v").strip()
    m = _RELEASE_RE.match(s)
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")]
    suffix = (m.group(2) or "").strip(" .-_")
    return nums, suffix


def compare_versions(a: str, b: str) -> int | None:
    """Three-way compare; ``None`` when either side is unparseable.

    Numeric parts compare numerically (zero-padded); a completely empty
    suffix (release) ranks above a non-empty suffix (prerelease).
    """
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return None
    na, sa = pa
    nb, sb = pb
    width = max(len(na), len(nb))
    va = na + [0] * (width - len(na))
    vb = nb + [0] * (width - len(nb))
    if va != vb:
        return -1 if va < vb else 1
    if sa == sb:
        return 0
    if sa == "":
        return 1
    if sb == "":
        return -1
    return -1 if sa < sb else 1


def cpe_fields(criteria: str) -> dict[str, str]:
    """Extract vendor/product/version/update from a CPE 2.3 criteria string."""
    parts = str(criteria or "").split(":")
    if len(parts) >= 5 and parts[0] == "cpe":
        return {
            "vendor": parts[3],
            "product": parts[4],
            "version": parts[5] if len(parts) > 5 else "",
            "update": parts[6] if len(parts) > 6 else "",
        }
    return {"vendor": "", "product": "", "version": "", "update": ""}


def name_tokens(text: str) -> set[str]:
    """Lowercased alphanumeric tokens (pure numbers dropped) for name matching."""
    return {t for t in re.split(r"[^a-z0-9]+", str(text or "").lower()) if t and not t.isdigit()}


@dataclass(frozen=True)
class VersionRange:
    """One affected range (NVD cpeMatch bounds; all optional).

    ``exact`` holds a bare criteria version when the CPE lists a concrete
    version and no numeric bounds.
    """

    start_including: str = ""
    start_excluding: str = ""
    end_including: str = ""
    end_excluding: str = ""
    exact: str = ""

    def is_empty(self) -> bool:
        return not any(
            (self.start_including, self.start_excluding,
             self.end_including, self.end_excluding, self.exact)
        )

    def evaluate(self, version: str) -> str:
        """Return ``affected`` | ``unaffected`` | ``unknown`` for *version*."""
        if self.is_empty() or parse_version(version) is None:
            return "unknown"
        if self.exact and self.exact not in ("*", "-"):
            cmp = compare_versions(version, self.exact)
            if cmp is None:
                return "unknown"
            return "affected" if cmp == 0 else "unaffected"
        for bound, op in (
            (self.start_including, "ge"),
            (self.start_excluding, "gt"),
            (self.end_including, "le"),
            (self.end_excluding, "lt"),
        ):
            if not bound:
                continue
            cmp = compare_versions(version, bound)
            if cmp is None:
                return "unknown"
            ok = (
                (op == "ge" and cmp >= 0)
                or (op == "gt" and cmp > 0)
                or (op == "le" and cmp <= 0)
                or (op == "lt" and cmp < 0)
            )
            if not ok:
                return "unaffected"
        return "affected"

    @classmethod
    def from_cpe_match(cls, entry: dict[str, Any]) -> "VersionRange":
        """Build from one NVD ``cpeMatch`` entry (bounds + criteria version)."""
        fields = cpe_fields(str(entry.get("criteria", "")))
        version = fields.get("version", "")
        bounds = {
            "start_including": str(entry.get("versionStartIncluding", "") or ""),
            "start_excluding": str(entry.get("versionStartExcluding", "") or ""),
            "end_including": str(entry.get("versionEndIncluding", "") or ""),
            "end_excluding": str(entry.get("versionEndExcluding", "") or ""),
        }
        has_bounds = any(bounds.values())
        exact = "" if (has_bounds or version in ("", "*", "-")) else version
        return cls(exact=exact, **bounds)


def aggregate_status(statuses: list[str]) -> str:
    """Combine per-entry verdicts into one overall status.

    ``affected`` wins; then ``unknown`` (conservative); then ``candidate``;
    ``unaffected`` only when every evaluable entry is out of range.
    """
    values = [s for s in statuses if s]
    if not values:
        return "candidate"
    if "affected" in values:
        return "affected"
    if "unknown" in values:
        return "unknown"
    if "candidate" in values:
        return "candidate"
    return "unaffected"

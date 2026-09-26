"""Finding deduplication via normalized fuzzy matching.

Same vulnerability found by multiple tools (e.g. nuclei + dalfox on the
same endpoint) is merged into one finding: tools are unioned, confidence
is boosted (+10 per extra tool, capped at 100), and the strongest
evidence (payload + response snippet) is kept.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlsplit, parse_qsl, urlencode

DEFAULT_FUZZY_THRESHOLD = 0.85
CONFIDENCE_BOOST_PER_TOOL = 10
MAX_CONFIDENCE = 100

# Endpoint normalization ------------------------------------------------------


def normalize_endpoint(endpoint: str) -> str:
    """Normalize an endpoint for comparison.

    Lowercases host, strips scheme, drops default ports, sorts query
    params, strips fragments and trailing slashes.
    """
    raw = (endpoint or "").strip()
    if not raw:
        return ""
    if "://" not in raw and not raw.startswith("/"):
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw.lower().rstrip("/")
    host = (parts.hostname or "").lower()
    port = parts.port
    if port in (80, 443, None):
        netloc = host
    else:
        netloc = f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    path = path.rstrip("/") or ""
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    out = netloc + path
    if query:
        out += "?" + query
    return out


def extract_host(endpoint: str) -> str:
    """Extract lowercase host from an endpoint string."""
    raw = (endpoint or "").strip()
    if "://" in raw:
        try:
            return (urlsplit(raw).hostname or "").lower()
        except ValueError:
            return ""
    if raw.startswith("/"):
        return ""
    return raw.split("/")[0].split(":")[0].lower()


# Deduplication --------------------------------------------------------------


class Deduplicator:
    """Fuzzy deduplicator over raw findings."""

    def __init__(self, fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD):
        self.threshold = fuzzy_threshold

    def dedup(self, findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Deduplicate findings; returns (merged_findings, report).

        Report: {'input_count', 'output_count', 'duplicates_merged',
                 'merges': [{kept, merged_from, tools}]}
        """
        merged: list[dict[str, Any]] = []
        merges: list[dict[str, Any]] = []
        seen_keys: dict[tuple[str, str], list[int]] = {}

        for f in findings:
            endpoint = normalize_endpoint(f.get("endpoint", ""))
            vuln_type = str(f.get("vuln_type", "")).lower().strip()
            key = (endpoint, vuln_type)
            matched_idx = None
            if key in seen_keys:
                matched_idx = seen_keys[key][0]
            else:
                # Fuzzy: same vuln type + similar endpoint
                for (ep, vt), idxs in seen_keys.items():
                    if vt != vuln_type:
                        continue
                    ratio = SequenceMatcher(None, ep, key[0]).ratio()
                    if ratio >= self.threshold:
                        matched_idx = idxs[0]
                        break

            if matched_idx is None:
                stored = dict(f)
                stored["endpoint"] = endpoint or f.get("endpoint", "")
                stored["tools_found"] = list(f.get("tools_found", []) or [])
                stored["confidence"] = int(f.get("confidence", 50))
                merged.append(stored)
                seen_keys[key] = [len(merged) - 1]
            else:
                target = merged[matched_idx]
                old_conf = int(target.get("confidence", 50))
                old_tools = list(target.get("tools_found", []) or [])
                new_tools = list(f.get("tools_found", []) or [])
                combined = old_tools + [t for t in new_tools if t not in old_tools]
                boost = CONFIDENCE_BOOST_PER_TOOL * len(
                    [t for t in new_tools if t not in old_tools]
                )
                target["tools_found"] = combined
                target["confidence"] = min(MAX_CONFIDENCE, old_conf + boost)
                # Keep strongest evidence: prefer longer payload/response.
                if len(str(f.get("payload", ""))) > len(str(target.get("payload", ""))):
                    target["payload"] = f.get("payload", "")
                if len(str(f.get("response_snippet", ""))) > len(str(target.get("response_snippet", ""))):
                    target["response_snippet"] = f.get("response_snippet", "")
                if f.get("severity") and not target.get("severity"):
                    target["severity"] = f.get("severity")
                merges.append({
                    "kept": target.get("endpoint", ""),
                    "merged_from": f.get("endpoint", ""),
                    "tools": combined,
                })

        report = {
            "input_count": len(findings),
            "output_count": len(merged),
            "duplicates_merged": len(merges),
            "merges": merges,
        }
        return merged, report


def deduplicate(findings: list[dict[str, Any]], threshold: float = DEFAULT_FUZZY_THRESHOLD) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Functional wrapper around :class:`Deduplicator`."""
    return Deduplicator(threshold).dedup(findings)

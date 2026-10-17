"""Regression: domain→subdomain linking must use explicit identity, not substrings.

Bug: ``FiltrationPipeline.link_domain_assets`` linked any asset whose
normalized value merely *contained* the root domain as a substring
(``root in asset["normalized"]``). That created false graph edges for
``notexample.com``, ``evilexample.com`` and ``example.com.attacker.test`` —
even though none of them is a subdomain of ``example.com``.

The fix links a child only when it is a **strict label-boundary subdomain**
of the root (``<label>.parent``), reusing the scope validator's host
canonicalization so scheme/port/trailing-dot/case/IPv6-bracket handling is
consistent with the rest of the project. Malformed values are skipped (no
fabricated edge) and no asset/finding record is dropped.
"""
from __future__ import annotations

from core.database import Database
from lib.config import Config
from lib.filtration import FiltrationPipeline
from lib.scope_validator import extract_host


def _pipeline(db: Database, cfg: Config, domain: str = "example.com") -> FiltrationPipeline:
    return FiltrationPipeline(db, cfg.target(domain), scan_id=None)


def _edges(db: Database) -> set[tuple[str, str, str, str]]:
    """Edges projected onto comparable host identity (kind, host)."""
    out: set[tuple[str, str, str, str]] = set()
    for e in db.list_edges():
        src = db.query("SELECT normalized FROM assets WHERE id = ?", (e["src_id"],))[0]["normalized"]
        dst = db.query("SELECT kind, normalized FROM assets WHERE id = ?", (e["dst_id"],))[0]
        out.add((extract_host(src), e["relation"], dst["kind"], extract_host(dst["normalized"])))
    return out


def _link(db: Database, cfg: Config, values, domain="example.com", kind="subdomain"):
    pipe = _pipeline(db, cfg, domain)
    pipe.ingest("dnsx", "discover", list(values), kind=kind)
    return pipe.link_domain_assets(domain, tool="dnsx")


# --- exact matches -----------------------------------------------------------


def test_exact_subdomains_linked_apex_not(db: Database, cfg: Config):
    created = _link(db, cfg, ["sub.example.com", "deep.sub.example.com", "example.com"])
    assert created == 2
    edges = _edges(db)
    assert edges == {
        ("example.com", "has_subdomain", "subdomain", "sub.example.com"),
        ("example.com", "has_subdomain", "subdomain", "deep.sub.example.com"),
    }


# --- schemes, ports, case, trailing dots -------------------------------------


def test_scheme_port_case_and_trailing_dot_normalized(db: Database, cfg: Config):
    _link(
        db,
        cfg,
        [
            "https://api.example.com",   # scheme
            "app.example.com:8443",       # port
            "SUB.Example.COM.",           # case + trailing dot
        ],
    )
    assert {e[3] for e in _edges(db)} == {
        "api.example.com",      # scheme stripped
        "app.example.com",      # port ignored for host identity
        "sub.example.com",      # case folded + trailing dot dropped
    }


def test_apex_with_port_is_not_a_subdomain_of_itself(db: Database, cfg: Config):
    # example.com:8080 is the apex host (ports ignored for host identity)
    created = _link(db, cfg, ["example.com:8080"], kind="host")
    assert created == 0
    assert _edges(db) == set()


# --- deceptive suffix / prefix ----------------------------------------------


def test_deceptive_hosts_not_linked(db: Database, cfg: Config):
    _link(
        db,
        cfg,
        [
            "notexample.com",              # prefix (no label boundary)
            "evilexample.com",             # suffix-ish, no dot boundary
            "example.com.attacker.test",   # deceptive suffix
            "example.com.evil.test",
            "xexample.com",
            "example.comx",
        ],
    )
    assert _edges(db) == set()


# --- parent vs subdomain, similar-but-distinct -------------------------------


def test_parent_not_linked_to_itself_and_no_reverse_edge(db: Database, cfg: Config):
    _link(db, cfg, ["example.com", "sub.example.com"])
    edges = _edges(db)
    assert edges == {("example.com", "has_subdomain", "subdomain", "sub.example.com")}
    # never sub.example.com -> example.com
    assert all(e[0] != "sub.example.com" for e in edges)


def test_similar_but_distinct_domains_not_linked(db: Database, cfg: Config):
    _link(db, cfg, ["sub.example.com", "sub.example.org", "sub.other.com", "api.example.com"])
    assert _edges(db) == {
        ("example.com", "has_subdomain", "subdomain", "sub.example.com"),
        ("example.com", "has_subdomain", "subdomain", "api.example.com"),
    }


# --- IPv4 / IPv6 -------------------------------------------------------------


def test_ip_assets_never_linked_as_subdomains(db: Database, cfg: Config):
    _link(db, cfg, ["192.0.2.5", "10.0.0.1", "[2001:db8::1]"], kind="host")
    assert _edges(db) == set()


def test_subdomain_of_other_parent_domain_not_linked(db: Database, cfg: Config):
    _link(db, cfg, ["a.other.com", "a.example.com"], domain="example.com")
    assert _edges(db) == {("example.com", "has_subdomain", "subdomain", "a.example.com")}


# --- missing / malformed values ---------------------------------------------


def test_malformed_host_values_skipped_without_raising(db: Database, cfg: Config):
    pipe = _pipeline(db, cfg)
    # A backslash-bearing "host" is malformed; extract_host rejects it.
    pipe.ingest("dnsx", "discover", ["ok.example.com", "bad\\host.example.com"], kind="host")
    created = pipe.link_domain_assets("example.com", tool="dnsx")
    assert created == 1
    assert _edges(db) == {("example.com", "has_subdomain", "host", "ok.example.com")}


def test_empty_domain_creates_no_edges(db: Database, cfg: Config):
    pipe = _pipeline(db, cfg)
    pipe.ingest("dnsx", "discover", ["sub.example.com"], kind="subdomain")
    assert pipe.link_domain_assets("", tool="dnsx") == 0
    assert _edges(db) == set()


def test_no_matching_asset_creates_no_edge(db: Database, cfg: Config):
    pipe = _pipeline(db, cfg)
    pipe.ingest("dnsx", "discover", ["unrelated.test"], kind="subdomain")
    assert pipe.link_domain_assets("example.com", tool="dnsx") == 0
    assert _edges(db) == set()


# --- ambiguity / multiple matches -------------------------------------------


def test_multiple_children_all_linked_without_cross_links(db: Database, cfg: Config):
    _link(db, cfg, ["a.example.com", "b.example.com", "c.example.com"])
    edges = _edges(db)
    assert {e[3] for e in edges} == {"a.example.com", "b.example.com", "c.example.com"}
    assert {e[0] for e in edges} == {"example.com"}
    assert all(e[1] == "has_subdomain" for e in edges)


def test_nested_parent_only_matches_its_own_subtree(db: Database, cfg: Config):
    # with the parent being a subdomain, only its subtree links
    _link(db, cfg, ["a.sub.example.com", "a.example.com", "example.com"], domain="sub.example.com")
    assert _edges(db) == {
        ("sub.example.com", "has_subdomain", "subdomain", "a.sub.example.com"),
    }


# --- preservation of existing records ---------------------------------------


def test_records_preserved_and_link_is_idempotent(db: Database, cfg: Config):
    pipe = _pipeline(db, cfg)
    pipe.ingest(
        "dnsx",
        "discover",
        ["sub.example.com", "notexample.com", "example.com.attacker.test"],
        kind="subdomain",
    )
    # the discovered subdomain assets (the inputs to linking) ...
    ingested = {(a["kind"], a["normalized"]) for a in db.list_assets()}
    assert ingested == {
        ("subdomain", "sub.example.com"),
        ("subdomain", "notexample.com"),
        ("subdomain", "example.com.attacker.test"),
    }

    first = pipe.link_domain_assets("example.com", tool="dnsx")
    after_first = {(a["kind"], a["normalized"]) for a in db.list_assets()}
    second = pipe.link_domain_assets("example.com", tool="dnsx")

    # link() reports each resolved pair; the UNIQUE(src,dst,relation) edge is
    # never duplicated, so the graph stays identical on a second pass.
    assert first == 1 and second == 1
    assert len(db.list_edges()) == 1
    # linking only *adds* the root domain asset; every discovered asset is
    # retained and nothing is mutated or dropped.
    assert ingested <= after_first
    assert after_first == {(a["kind"], a["normalized"]) for a in db.list_assets()}
    assert after_first - ingested == {("domain", "example.com")}
    # only the real subdomain is linked
    assert _edges(db) == {("example.com", "has_subdomain", "subdomain", "sub.example.com")}


def test_linking_does_not_alter_findings(db: Database, cfg: Config, tmp_path):
    # a finding produced by ANALYZE must be untouched by graph linking
    from core.analyzer import Analyzer
    from lib.config import load_config
    from pathlib import Path

    cfg2 = load_config(Path(__file__).resolve().parent.parent.parent / "config")
    scan_id = db.create_scan(db.upsert_target("example.com"))
    results = tmp_path / "r"
    results.mkdir()
    Analyzer(cfg2, db).run(
        [{"endpoint": "https://example.com/x", "vuln_type": "xss",
          "confidence": 70, "tools_found": ["nuclei"], "severity": "P2"}],
        cfg2.target("example.com"), scan_id, results,
    )
    findings_before = db.query_findings(scan_id=scan_id)

    pipe = _pipeline(db, cfg2)
    pipe.ingest("dnsx", "discover", ["notexample.com", "sub.example.com"], kind="subdomain")
    pipe.link_domain_assets("example.com", tool="dnsx")

    findings_after = db.query_findings(scan_id=scan_id)
    assert findings_after == findings_before
    assert _edges(db) == {("example.com", "has_subdomain", "subdomain", "sub.example.com")}

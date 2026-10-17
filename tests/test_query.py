"""Tests for the query engine: tokenizer, parser, and evaluator."""

from __future__ import annotations

import pytest

from app.query.engine import (
    TT,
    AndNode,
    CompareNode,
    ExistsNode,
    NotNode,
    OrNode,
    QueryParseError,
    evaluate,
    filter_results,
    flatten,
    parse,
    tokenize,
)

# ── Tokenizer ─────────────────────────────────────────────────────────────────


def test_tokenize_simple_compare():
    tokens = tokenize('dns.A == "1.2.3.4"')
    types = [t.type for t in tokens]
    assert TT.IDENT in types
    assert TT.DOT in types
    assert TT.OP in types
    assert TT.STRING in types


def test_tokenize_hyphenated_field():
    tokens = tokenize('final_headers.x-powered-by contains "PHP"')
    idents = [t.value for t in tokens if t.type == TT.IDENT]
    assert "x-powered-by" in idents


def test_tokenize_keywords():
    tokens = tokenize("a == 1 AND b == 2 OR NOT c exists")
    types = [t.type for t in tokens]
    assert TT.AND in types
    assert TT.OR in types
    assert TT.NOT in types
    assert TT.EXISTS in types


def test_tokenize_numbers():
    tokens = tokenize("final_status == 200")
    num = next(t for t in tokens if t.type == TT.NUMBER)
    assert num.value == 200


def test_tokenize_string_escape():
    tokens = tokenize(r'field == "he said \"hi\""')
    s = next(t for t in tokens if t.type == TT.STRING)
    assert '"hi"' in s.value


# ── Parser ────────────────────────────────────────────────────────────────────


def test_parse_simple_compare():
    ast = parse('dns.A == "1.2.3.4"')
    assert isinstance(ast, CompareNode)
    assert ast.field == "dns.A"
    assert ast.op == "=="
    assert ast.value == "1.2.3.4"


def test_parse_exists():
    ast = parse("whois.registrar exists")
    assert isinstance(ast, ExistsNode)
    assert ast.field == "whois.registrar"
    assert ast.negated is False


def test_parse_not_exists():
    ast = parse("whois.registrar not exists")
    assert isinstance(ast, ExistsNode)
    assert ast.negated is True


def test_parse_and():
    ast = parse('dns.A == "1.2.3.4" AND final_status == 200')
    assert isinstance(ast, AndNode)


def test_parse_or():
    ast = parse('kind == "domain" OR kind == "ip"')
    assert isinstance(ast, OrNode)


def test_parse_not():
    ast = parse("NOT final_status == 200")
    assert isinstance(ast, NotNode)


def test_parse_parentheses():
    ast = parse('(dns.A == "1.2.3.4" OR dns.A == "5.6.7.8") AND final_status == 200')
    assert isinstance(ast, AndNode)
    assert isinstance(ast.left, OrNode)


def test_parse_nested_field():
    ast = parse('bgp.asn.asn_description contains "edgecast"')
    assert isinstance(ast, CompareNode)
    assert ast.field == "bgp.asn.asn_description"


def test_parse_error_missing_value():
    with pytest.raises(QueryParseError):
        parse("dns.A ==")


def test_parse_error_missing_op():
    with pytest.raises(QueryParseError):
        parse('dns.A "1.2.3.4"')


# ── Flatten ───────────────────────────────────────────────────────────────────


def test_flatten_scalar():
    flat = flatten({"a": {"b": "hello"}})
    assert flat["a.b"] == "hello"


def test_flatten_list_of_scalars():
    flat = flatten({"dns": {"A": ["1.2.3.4", "5.6.7.8"]}})
    assert flat["dns.A"] == ["1.2.3.4", "5.6.7.8"]


def test_flatten_list_of_dicts():
    flat = flatten(
        {
            "dns": {
                "MX": [
                    {"priority": 10, "exchange": "mail.x.com"},
                    {"priority": 20, "exchange": "mx2.x.com"},
                ]
            }
        }
    )
    assert isinstance(flat["dns.MX.exchange"], list)
    assert "mail.x.com" in flat["dns.MX.exchange"]
    assert "mx2.x.com" in flat["dns.MX.exchange"]


def test_flatten_nested_dict():
    flat = flatten({"final_headers": {"server": "nginx", "content-type": "text/html"}})
    assert flat["final_headers.server"] == "nginx"
    assert flat["final_headers.content-type"] == "text/html"


# ── Evaluator ─────────────────────────────────────────────────────────────────


def test_eval_simple_match(domain_result):
    assert evaluate("final_status == 200", domain_result)


def test_eval_simple_no_match(domain_result):
    assert not evaluate("final_status == 404", domain_result)


def test_eval_contains(domain_result):
    assert evaluate('final_headers.server contains "nginx"', domain_result)


def test_eval_startswith(domain_result):
    assert evaluate('final_headers.content-type startswith "text/html"', domain_result)


def test_eval_regex(domain_result):
    assert evaluate('final_headers.server ~= "nginx/\\d"', domain_result)


def test_eval_list_any_match(domain_result):
    assert evaluate('dns.A == "93.184.216.34"', domain_result)
    assert not evaluate('dns.A == "0.0.0.0"', domain_result)


def test_eval_mx_nested(domain_result):
    assert evaluate('dns.MX.exchange contains "mail.example"', domain_result)


def test_eval_txt_spf(domain_result):
    assert evaluate('dns.TXT contains "v=spf1"', domain_result)


def test_eval_exists(domain_result):
    assert evaluate("whois.registrar exists", domain_result)
    assert not evaluate("errors exists", domain_result)


def test_eval_not_exists(domain_result):
    assert evaluate("screenshot not exists", domain_result)


def test_eval_and(domain_result):
    assert evaluate('final_status == 200 AND final_headers.server contains "nginx"', domain_result)


def test_eval_or(domain_result):
    assert evaluate("final_status == 404 OR final_status == 200", domain_result)


def test_eval_not(domain_result):
    assert evaluate("NOT final_status == 404", domain_result)


def test_eval_complex(domain_result):
    q = '(dns.A == "93.184.216.34" OR dns.A == "0.0.0.0") AND NOT whois.registrar contains "godaddy"'
    assert evaluate(q, domain_result)


def test_eval_cert_san(domain_result):
    assert evaluate('certs.san contains "www.example.com"', domain_result)


def test_eval_bgp_asn(ip_result):
    assert evaluate('bgp.asn.asn == "AS15133"', ip_result)


def test_eval_bgp_cidr(ip_result):
    assert evaluate('bgp.asn.asn_cidr contains "93.184"', ip_result)


def test_filter_results(domain_result, ip_result):
    results = [domain_result, ip_result]
    assert filter_results('kind == "domain"', results) == [domain_result]
    assert filter_results('kind == "ip"', results) == [ip_result]
    assert len(filter_results("final_status == 200", results)) == 1


# ── root_files query tests ────────────────────────────────────────────────────


def test_eval_root_files_path_exact(domain_result):
    assert evaluate('root_files.path == "/robots.txt"', domain_result)


def test_eval_root_files_path_no_match(domain_result):
    assert not evaluate('root_files.path == "/nonexistent.txt"', domain_result)


def test_eval_root_files_status_code(domain_result):
    assert evaluate("root_files.status_code == 200", domain_result)


def test_eval_root_files_status_404(domain_result):
    assert evaluate("root_files.status_code == 404", domain_result)


def test_eval_root_files_url_contains(domain_result):
    assert evaluate('root_files.url contains "robots"', domain_result)


def test_eval_root_files_content_type_contains(domain_result):
    assert evaluate('root_files.content_type contains "text/plain"', domain_result)


def test_eval_root_files_sha1_exact(domain_result):
    """SHA1 of empty content — field is root_files.sha1 not files.sha1."""
    assert evaluate(
        'root_files.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"',
        domain_result,
    )


def test_eval_root_files_sha1_no_match(domain_result):
    assert not evaluate(
        'root_files.sha1 == "0000000000000000000000000000000000000000"', domain_result
    )


def test_eval_wrong_field_files_sha1_no_match(domain_result):
    """files.sha1 is the wrong field name — must NOT match."""
    assert not evaluate(
        'files.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"',
        domain_result,
    )


def test_eval_root_files_sha1_exists(domain_result):
    assert evaluate("root_files.sha1 exists", domain_result)


def test_eval_root_files_minhash_exists(domain_result):
    assert evaluate("root_files.minhash exists", domain_result)


def test_eval_root_files_minhash_exact(domain_result):
    assert evaluate(
        'root_files.minhash == "a1b2c3d4e5f60718293a4b5c6d7e8f90"',
        domain_result,
    )


def test_eval_root_files_minhash_no_match(domain_result):
    assert not evaluate(
        'root_files.minhash == "0000000000000000000000000000000000000000"', domain_result
    )


def test_eval_root_files_minhash_bands_contains(domain_result):
    assert evaluate('root_files.minhash_bands contains "a1b2"', domain_result)


def test_eval_root_files_minhash_bands_no_match(domain_result):
    assert not evaluate('root_files.minhash_bands contains "zzzz"', domain_result)


def test_eval_screenshot_phash_not_exists(domain_result):
    """Fixture has screenshot_phash=None → should not exist."""
    assert evaluate("screenshot_phash not exists", domain_result)


def test_eval_screenshot_phash_exists():
    """When phash is set it should exist and be queryable."""
    result_with_phash = {
        "_id": "x",
        "target": "example.com",
        "kind": "domain",
        "final_status": 200,
        "final_url": "https://example.com/",
        "final_headers": {},
        "dns": None,
        "whois": None,
        "chain": [],
        "root_files": [],
        "screenshot": "base64data",
        "screenshot_phash": "0f0f0f0f0f0f0f0f",
        "certs": [],
        "errors": {},
    }
    assert evaluate("screenshot_phash exists", result_with_phash)
    assert evaluate('screenshot_phash == "0f0f0f0f0f0f0f0f"', result_with_phash)


def test_eval_root_files_size_compare(domain_result):
    assert evaluate("root_files.size == 25", domain_result)


def test_eval_root_files_combined(domain_result):
    q = 'root_files.path == "/robots.txt" AND root_files.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"'
    assert evaluate(q, domain_result)


# ── GeoIP query tests (domain) ────────────────────────────────────────────────


def test_eval_geo_ips_exists(domain_result):
    assert evaluate("geo_ips exists", domain_result)


def test_eval_geo_ips_country_iso_match(domain_result):
    assert evaluate('geo_ips.country_iso == "US"', domain_result)


def test_eval_geo_ips_country_iso_second_entry(domain_result):
    """Any-match: second A record is DE — must return True."""
    assert evaluate('geo_ips.country_iso == "DE"', domain_result)


def test_eval_geo_ips_country_iso_no_match(domain_result):
    assert not evaluate('geo_ips.country_iso == "RU"', domain_result)


def test_eval_geo_ips_country_name_contains(domain_result):
    assert evaluate('geo_ips.country_name contains "United States"', domain_result)


def test_eval_geo_ips_city_match(domain_result):
    assert evaluate('geo_ips.city == "Norristown"', domain_result)


def test_eval_geo_ips_city_contains(domain_result):
    assert evaluate('geo_ips.city contains "Frankfurt"', domain_result)


def test_eval_geo_ips_city_no_match(domain_result):
    assert not evaluate('geo_ips.city == "Paris"', domain_result)


def test_eval_geo_ips_continent_match(domain_result):
    assert evaluate('geo_ips.continent == "Europe"', domain_result)


def test_eval_geo_ips_timezone_contains(domain_result):
    assert evaluate('geo_ips.timezone contains "America"', domain_result)


def test_eval_geo_ips_timezone_europe(domain_result):
    assert evaluate('geo_ips.timezone contains "Europe"', domain_result)


def test_eval_geo_ips_postal_code(domain_result):
    assert evaluate('geo_ips.postal_code == "19401"', domain_result)


def test_eval_geo_ips_ip_exact(domain_result):
    assert evaluate('geo_ips.ip == "93.184.216.34"', domain_result)
    assert evaluate('geo_ips.ip == "93.184.216.35"', domain_result)
    assert not evaluate('geo_ips.ip == "1.2.3.4"', domain_result)


def test_eval_geo_ips_latitude_exists(domain_result):
    assert evaluate("geo_ips.latitude exists", domain_result)


def test_eval_geo_ips_not_country(domain_result):
    assert not evaluate('NOT geo_ips.country_iso == "US"', domain_result)


def test_eval_geo_ips_country_and_city(domain_result):
    assert evaluate('geo_ips.country_iso == "US" AND geo_ips.city == "Norristown"', domain_result)


def test_eval_geo_ips_or_countries(domain_result):
    assert evaluate('geo_ips.country_iso == "US" OR geo_ips.country_iso == "FR"', domain_result)
    assert not evaluate('geo_ips.country_iso == "RU" OR geo_ips.country_iso == "CN"', domain_result)


def test_eval_geo_ips_regex_city(domain_result):
    assert evaluate('geo_ips.city ~= "^Frank"', domain_result)
    assert not evaluate('geo_ips.city ~= "^London"', domain_result)


def test_eval_geo_ips_not_exists_missing_field(domain_result):
    assert evaluate("geo_ips.nonexistent not exists", domain_result)


def test_eval_geo_ips_and_final_status(domain_result):
    assert evaluate('geo_ips.country_iso == "US" AND final_status == 200', domain_result)
    assert not evaluate('geo_ips.country_iso == "RU" AND final_status == 200', domain_result)


def test_eval_geo_ips_flatten_aggregates_all_ips(domain_result):
    """flatten() must aggregate sub-fields across all geo_ips entries."""
    from app.query.engine import flatten

    flat = flatten(domain_result)
    assert isinstance(flat["geo_ips.country_iso"], list)
    assert "US" in flat["geo_ips.country_iso"]
    assert "DE" in flat["geo_ips.country_iso"]
    assert "93.184.216.34" in flat["geo_ips.ip"]
    assert "93.184.216.35" in flat["geo_ips.ip"]


# ── GeoIP query tests (IP result) ─────────────────────────────────────────────


def test_eval_geo_exists_ip(ip_result):
    assert evaluate("geo exists", ip_result)


def test_eval_geo_country_iso_ip(ip_result):
    assert evaluate('geo.country_iso == "US"', ip_result)


def test_eval_geo_country_iso_no_match_ip(ip_result):
    assert not evaluate('geo.country_iso == "DE"', ip_result)


def test_eval_geo_city_ip(ip_result):
    assert evaluate('geo.city == "Norristown"', ip_result)


def test_eval_geo_continent_ip(ip_result):
    assert evaluate('geo.continent == "North America"', ip_result)


def test_eval_geo_timezone_ip(ip_result):
    assert evaluate('geo.timezone contains "America"', ip_result)


def test_eval_geo_country_name_contains_ip(ip_result):
    assert evaluate('geo.country_name contains "United"', ip_result)


def test_eval_geo_latitude_exists_ip(ip_result):
    assert evaluate("geo.latitude exists", ip_result)


def test_eval_geo_not_country_ip(ip_result):
    assert evaluate('NOT geo.country_iso == "DE"', ip_result)


def test_eval_geo_and_bgp_ip(ip_result):
    assert evaluate('geo.country_iso == "US" AND bgp.asn.asn == "AS15133"', ip_result)


def test_eval_geo_or_ip(ip_result):
    assert evaluate('geo.country_iso == "US" OR geo.country_iso == "DE"', ip_result)
    assert not evaluate('geo.country_iso == "CN" OR geo.country_iso == "RU"', ip_result)


def test_eval_geo_regex_ip(ip_result):
    assert evaluate('geo.city ~= "norris"', ip_result)


def test_eval_no_geo_field_not_exists(ip_result):
    ip_no_geo = dict(ip_result)
    ip_no_geo["geo"] = None
    assert evaluate("geo not exists", ip_no_geo)


# ── filter_results with geo ───────────────────────────────────────────────────


def test_filter_results_by_geo_country(domain_result, ip_result):
    results = [domain_result, ip_result]
    # Both have US entries
    us_matches = filter_results('geo_ips.country_iso == "US" OR geo.country_iso == "US"', results)
    assert domain_result in us_matches
    assert ip_result in us_matches


def test_filter_results_geo_no_match(domain_result, ip_result):
    results = [domain_result, ip_result]
    matches = filter_results('geo_ips.country_iso == "RU"', results)
    assert matches == []


def test_filter_results_geo_domain_only(domain_result, ip_result):
    results = [domain_result, ip_result]
    # DE only exists in domain_result's second A record
    matches = filter_results('geo_ips.country_iso == "DE"', results)
    assert domain_result in matches
    assert ip_result not in matches

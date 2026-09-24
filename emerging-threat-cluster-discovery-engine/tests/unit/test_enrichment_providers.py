from __future__ import annotations

import asyncio

import respx
from httpx import Response

from threat_ingestion.config import Settings
from threat_ingestion.enrichment.providers import (
    AbuseIpdbProvider,
    CensysProvider,
    DnsProvider,
    GreyNoiseProvider,
    OtxProvider,
    RdapProvider,
    ShodanProvider,
    UrlscanProvider,
)


def test_rdap_provider_parses_asn_from_ip_api() -> None:
    settings = Settings()
    provider = RdapProvider(settings)
    with respx.mock:
        respx.get("http://ip-api.com/json/1.2.3.4").mock(
            return_value=Response(200, json={"as": "AS64512 Example Hosting", "asname": "EXAMPLE-AS", "countryCode": "NL"})
        )
        result = asyncio.run(provider.enrich("ip", "1.2.3.4"))
    asyncio.run(provider.client.aclose())

    assert result.error is None
    assert result.asn == 64512
    assert result.country == "NL"


def test_dns_provider_extracts_resolved_ips_and_nameservers() -> None:
    settings = Settings()
    provider = DnsProvider(settings)
    with respx.mock:
        respx.get("https://cloudflare-dns.com/dns-query", params={"name": "bad.test", "type": "A"}).mock(
            return_value=Response(200, json={"Answer": [{"data": "5.6.7.8"}]})
        )
        respx.get("https://cloudflare-dns.com/dns-query", params={"name": "bad.test", "type": "NS"}).mock(
            return_value=Response(200, json={"Answer": [{"data": "ns1.example.test."}]})
        )
        result = asyncio.run(provider.enrich("domain", "bad.test"))
    asyncio.run(provider.client.aclose())

    assert result.resolved_ips == ["5.6.7.8"]
    assert result.related_domains == ["ns1.example.test"]


def test_greynoise_provider_skips_without_api_key() -> None:
    settings = Settings(greynoise_api_key=None)
    provider = GreyNoiseProvider(settings)
    result = asyncio.run(provider.enrich("ip", "1.2.3.4"))
    asyncio.run(provider.client.aclose())

    assert result.error is not None
    assert result.classification is None


def test_urlscan_provider_collects_related_infrastructure() -> None:
    settings = Settings()
    provider = UrlscanProvider(settings)
    with respx.mock:
        respx.get("https://urlscan.io/api/v1/search/").mock(
            return_value=Response(
                200,
                json={
                    "total": 1,
                    "results": [
                        {
                            "page": {"ip": "9.9.9.9", "domain": "other.test", "apexDomain": "other.test"},
                            "tls": {"certSHA1": "ABCDEF1234567890"},
                        }
                    ],
                },
            )
        )
        result = asyncio.run(provider.enrich("domain", "bad.test"))
    asyncio.run(provider.client.aclose())

    assert result.resolved_ips == ["9.9.9.9"]
    assert result.related_domains == ["other.test"]
    assert result.cert_fingerprints == ["abcdef1234567890"]


def test_provider_wraps_transport_errors_without_raising() -> None:
    settings = Settings()
    provider = RdapProvider(settings)
    with respx.mock:
        respx.get("http://ip-api.com/json/10.0.0.1").mock(return_value=Response(500))
        result = asyncio.run(provider.enrich("ip", "10.0.0.1"))
    asyncio.run(provider.client.aclose())

    assert result.error is not None


def test_censys_provider_skips_without_token() -> None:
    settings = Settings(censys_personal_access_token=None)
    provider = CensysProvider(settings)
    result = asyncio.run(provider.enrich("ip", "1.2.3.4"))
    asyncio.run(provider.client.aclose())

    assert result.error is not None
    assert result.asn is None


def test_censys_provider_parses_host_enrichment() -> None:
    settings = Settings(censys_personal_access_token="censys_test_token")
    provider = CensysProvider(settings)
    with respx.mock:
        respx.get("https://api.platform.censys.io/v3/global/asset/enrichment/host/1.2.3.4").mock(
            return_value=Response(
                200,
                json={
                    "result": {
                        "result": {
                            "resource": {
                                "autonomous_system": {"asn": 64512, "name": "EXAMPLE-AS"},
                                "location": {"country_code": "NL"},
                                "greynoise": {"classification": "malicious"},
                                "privacy": [{"vpn": True}],
                                "network": [{"hosting": True}],
                                "services": [],
                                "service_count": 0,
                            }
                        }
                    }
                },
            )
        )
        result = asyncio.run(provider.enrich("ip", "1.2.3.4"))
    asyncio.run(provider.client.aclose())

    assert result.error is None
    assert result.asn == 64512
    assert result.country == "NL"
    assert result.classification == "malicious"
    assert set(result.tags) == {"vpn", "hosting-provider"}


def test_censys_cert_pivot_disabled_by_default() -> None:
    settings = Settings(censys_personal_access_token="censys_test_token")
    provider = CensysProvider(settings)
    hosts = asyncio.run(provider.expand_certificate_hosts("deadbeef"))
    asyncio.run(provider.client.aclose())

    assert hosts == []


def test_censys_cert_pivot_returns_observed_hosts_when_enabled() -> None:
    settings = Settings(censys_personal_access_token="censys_test_token", censys_enable_cert_pivot=True)
    provider = CensysProvider(settings)
    with respx.mock:
        respx.get(
            "https://api.platform.censys.io/v3/threat-hunting/certificate/deadbeef/observations/hosts"
        ).mock(
            return_value=Response(
                200, json={"result": {"result": {"ranges": [{"ip": "9.9.9.9"}, {"ip": "9.9.9.9"}]}}}
            )
        )
        hosts = asyncio.run(provider.expand_certificate_hosts("deadbeef"))
    asyncio.run(provider.client.aclose())

    assert hosts == ["9.9.9.9"]


def test_shodan_provider_skips_without_key() -> None:
    settings = Settings(shodan_api_key=None)
    provider = ShodanProvider(settings)
    result = asyncio.run(provider.enrich("ip", "1.2.3.4"))
    asyncio.run(provider.client.aclose())

    assert result.error is not None
    assert result.asn is None


def test_shodan_provider_parses_host_lookup() -> None:
    settings = Settings(shodan_api_key="test-key")
    provider = ShodanProvider(settings)
    with respx.mock:
        respx.get("https://api.shodan.io/shodan/host/1.2.3.4").mock(
            return_value=Response(
                200,
                json={
                    "asn": "AS64512",
                    "org": "Example Hosting",
                    "country_code": "NL",
                    "hostnames": ["Bad-Host.test"],
                    "tags": ["cloud"],
                    "vulns": ["CVE-2021-44228"],
                    "ports": [443],
                    "data": [
                        {"ssl": {"cert": {"fingerprint": {"sha256": "ABCDEF"}}}},
                    ],
                },
            )
        )
        result = asyncio.run(provider.enrich("ip", "1.2.3.4"))
    asyncio.run(provider.client.aclose())

    assert result.error is None
    assert result.asn == 64512
    assert result.asn_name == "Example Hosting"
    assert result.country == "NL"
    assert result.related_domains == ["bad-host.test"]
    assert result.cert_fingerprints == ["abcdef"]
    assert set(result.tags) == {"cloud", "CVE-2021-44228"}


def test_otx_provider_skips_without_key() -> None:
    settings = Settings(otx_api_key=None)
    provider = OtxProvider(settings)
    result = asyncio.run(provider.enrich("ip", "1.2.3.4"))
    asyncio.run(provider.client.aclose())

    assert result.error is not None


def test_otx_provider_parses_pulse_correlation() -> None:
    settings = Settings(otx_api_key="test-key")
    provider = OtxProvider(settings)
    with respx.mock:
        respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general").mock(
            return_value=Response(
                200,
                json={
                    "pulse_info": {
                        "count": 2,
                        "pulses": [{"tags": ["botnet"], "malware_families": ["Emotet"]}],
                    }
                },
            )
        )
        result = asyncio.run(provider.enrich("ip", "1.2.3.4"))
    asyncio.run(provider.client.aclose())

    assert result.error is None
    assert result.classification == "malicious"
    assert set(result.tags) == {"botnet", "Emotet"}


def test_abuseipdb_provider_skips_without_key() -> None:
    settings = Settings(abuseipdb_api_key=None)
    provider = AbuseIpdbProvider(settings)
    result = asyncio.run(provider.enrich("ip", "1.2.3.4"))
    asyncio.run(provider.client.aclose())

    assert result.error is not None


def test_abuseipdb_provider_classifies_by_confidence_score() -> None:
    settings = Settings(abuseipdb_api_key="test-key")
    provider = AbuseIpdbProvider(settings)
    with respx.mock:
        respx.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=Response(
                200,
                json={
                    "data": {
                        "abuseConfidenceScore": 87,
                        "countryCode": "RU",
                        "totalReports": 12,
                        "domain": "Bad-Domain.test",
                    }
                },
            )
        )
        result = asyncio.run(provider.enrich("ip", "1.2.3.4"))
    asyncio.run(provider.client.aclose())

    assert result.error is None
    assert result.classification == "malicious"
    assert result.country == "RU"
    assert result.related_domains == ["bad-domain.test"]
    assert result.tags == ["abuseipdb-reports:12"]

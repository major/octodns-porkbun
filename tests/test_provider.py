from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from octodns.zone import Zone

from octodns_porkbun import PorkbunProvider
from tests.conftest import make_dns_response


class TestPorkbunProviderInit:
    def test_provider_supports_expected_record_types(self) -> None:
        expected = {
            "A",
            "AAAA",
            "ALIAS",
            "CAA",
            "CNAME",
            "HTTPS",
            "MX",
            "NS",
            "SRV",
            "SSHFP",
            "SVCB",
            "TLSA",
            "TXT",
        }
        assert expected == PorkbunProvider.SUPPORTS

    def test_provider_does_not_support_geo(self) -> None:
        assert PorkbunProvider.SUPPORTS_GEO is False

    def test_provider_does_not_support_dynamic(self) -> None:
        assert PorkbunProvider.SUPPORTS_DYNAMIC is False

    @patch("octodns_porkbun.Piglet")
    def test_init_creates_client(self, mock_piglet_cls: MagicMock) -> None:
        provider = PorkbunProvider("test", api_key="pk1_key", secret_key="sk1_secret")
        mock_piglet_cls.assert_called_once_with(api_key="pk1_key", secret_key="sk1_secret")
        assert provider.id == "test"


class TestNameConversions:
    @pytest.fixture
    def provider(self) -> PorkbunProvider:
        with patch("octodns_porkbun.Piglet"):
            return PorkbunProvider("test", api_key="key", secret_key="secret")

    @pytest.fixture
    def zone(self) -> Zone:
        return Zone("example.com.", [])

    def test_domain_name_strips_trailing_dot(self, provider: PorkbunProvider, zone: Zone) -> None:
        assert provider._domain_name(zone) == "example.com"

    def test_relative_name_root(self, provider: PorkbunProvider, zone: Zone) -> None:
        assert provider._relative_name("example.com", zone) == ""

    def test_relative_name_subdomain(self, provider: PorkbunProvider, zone: Zone) -> None:
        assert provider._relative_name("www.example.com", zone) == "www"

    def test_relative_name_nested(self, provider: PorkbunProvider, zone: Zone) -> None:
        assert provider._relative_name("api.v1.example.com", zone) == "api.v1"

    def test_absolute_name_root(self, provider: PorkbunProvider, zone: Zone) -> None:
        assert provider._absolute_name("", zone) == "example.com"

    def test_absolute_name_subdomain(self, provider: PorkbunProvider, zone: Zone) -> None:
        assert provider._absolute_name("www", zone) == "www.example.com"

    def test_subdomain_name_root_returns_none(self, provider: PorkbunProvider) -> None:
        assert provider._subdomain_name("") is None

    def test_subdomain_name_with_value(self, provider: PorkbunProvider) -> None:
        assert provider._subdomain_name("www") == "www"


class TestPopulate:
    @pytest.fixture
    def provider(self, mock_piglet: MagicMock) -> PorkbunProvider:
        with patch("octodns_porkbun.Piglet", return_value=mock_piglet):
            return PorkbunProvider("test", api_key="key", secret_key="secret")

    @pytest.fixture
    def zone(self) -> Zone:
        return Zone("example.com.", [])

    def test_populate_empty_zone_returns_false(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_piglet.dns.list.return_value = []
        exists = provider.populate(zone, target=True)
        assert exists is False
        assert len(zone.records) == 0

    def test_populate_with_a_records(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_piglet.dns.list.return_value = [
            make_dns_response("1", "example.com", "A", "1.2.3.4"),
            make_dns_response("2", "www.example.com", "A", "1.2.3.4"),
        ]
        exists = provider.populate(zone, target=True)
        assert exists is True
        assert len(zone.records) == 2

    def test_populate_groups_records_by_name_and_type(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_piglet.dns.list.return_value = [
            make_dns_response("1", "example.com", "A", "1.2.3.4"),
            make_dns_response("2", "example.com", "A", "5.6.7.8"),
        ]
        exists = provider.populate(zone, target=True)
        assert exists is True
        assert len(zone.records) == 1
        record = list(zone.records)[0]
        assert len(record.values) == 2

    def test_populate_skips_unsupported_types(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_piglet.dns.list.return_value = [
            make_dns_response("1", "example.com", "A", "1.2.3.4"),
            make_dns_response("2", "example.com", "UNSUPPORTED", "data"),
        ]
        exists = provider.populate(zone, target=True)
        assert exists is True
        assert len(zone.records) == 1


class TestDataConversion:
    @pytest.fixture
    def provider(self) -> PorkbunProvider:
        with patch("octodns_porkbun.Piglet"):
            return PorkbunProvider("test", api_key="key", secret_key="secret")

    def test_data_for_a_record(self, provider: PorkbunProvider) -> None:
        records = [
            make_dns_response("1", "example.com", "A", "1.2.3.4"),
            make_dns_response("2", "example.com", "A", "5.6.7.8"),
        ]
        data = provider._data_for("A", records)
        assert data["type"] == "A"
        assert data["ttl"] == 600
        assert data["values"] == ["1.2.3.4", "5.6.7.8"]

    def test_data_for_cname_adds_trailing_dot(self, provider: PorkbunProvider) -> None:
        records = [make_dns_response("1", "www.example.com", "CNAME", "example.com")]
        data = provider._data_for("CNAME", records)
        assert data["type"] == "CNAME"
        assert data["value"] == "example.com."

    def test_data_for_cname_preserves_existing_dot(self, provider: PorkbunProvider) -> None:
        records = [make_dns_response("1", "www.example.com", "CNAME", "example.com.")]
        data = provider._data_for("CNAME", records)
        assert data["value"] == "example.com."

    def test_data_for_mx(self, provider: PorkbunProvider) -> None:
        records = [
            make_dns_response("1", "example.com", "MX", "mail1.example.com", priority=10),
            make_dns_response("2", "example.com", "MX", "mail2.example.com", priority=20),
        ]
        data = provider._data_for("MX", records)
        assert data["type"] == "MX"
        assert len(data["values"]) == 2
        assert data["values"][0]["preference"] == 10
        assert data["values"][0]["exchange"] == "mail1.example.com."

    def test_data_for_txt(self, provider: PorkbunProvider) -> None:
        records = [make_dns_response("1", "example.com", "TXT", "v=spf1 -all")]
        data = provider._data_for("TXT", records)
        assert data["type"] == "TXT"
        assert data["values"] == ["v=spf1 -all"]

    def test_data_for_srv(self, provider: PorkbunProvider) -> None:
        records = [
            make_dns_response(
                "1", "_sip._tcp.example.com", "SRV", "5 5060 sipserver.example.com", priority=10
            )
        ]
        data = provider._data_for("SRV", records)
        assert data["type"] == "SRV"
        assert len(data["values"]) == 1
        assert data["values"][0]["priority"] == 10
        assert data["values"][0]["weight"] == 5
        assert data["values"][0]["port"] == 5060
        assert data["values"][0]["target"] == "sipserver.example.com."

    def test_data_for_caa(self, provider: PorkbunProvider) -> None:
        records = [make_dns_response("1", "example.com", "CAA", '0 issue "letsencrypt.org"')]
        data = provider._data_for("CAA", records)
        assert data["type"] == "CAA"
        assert len(data["values"]) == 1
        assert data["values"][0]["flags"] == 0
        assert data["values"][0]["tag"] == "issue"
        assert data["values"][0]["value"] == "letsencrypt.org"


class TestApply:
    @pytest.fixture
    def provider(self, mock_piglet: MagicMock) -> PorkbunProvider:
        with patch("octodns_porkbun.Piglet", return_value=mock_piglet):
            return PorkbunProvider("test", api_key="key", secret_key="secret")

    @pytest.fixture
    def zone(self) -> Zone:
        return Zone("example.com.", [])

    def test_apply_delete_calls_delete_by_name_type(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_record = MagicMock()
        mock_record.name = "www"
        mock_record._type = "A"

        mock_change = MagicMock()
        mock_change.existing = mock_record

        provider._apply_Delete(mock_change, zone)

        mock_piglet.dns.delete_by_name_type.assert_called_once_with("example.com", "A", "www")

    def test_apply_delete_root_passes_none(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_record = MagicMock()
        mock_record.name = ""
        mock_record._type = "A"

        mock_change = MagicMock()
        mock_change.existing = mock_record

        provider._apply_Delete(mock_change, zone)

        mock_piglet.dns.delete_by_name_type.assert_called_once_with("example.com", "A", None)

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

    def test_apply_create_calls_dns_create(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_record = MagicMock()
        mock_record.name = "www"
        mock_record._type = "A"
        mock_record.ttl = 600
        mock_record.values = ["1.2.3.4"]

        mock_change = MagicMock()
        mock_change.new = mock_record

        provider._apply_Create(mock_change, zone)

        mock_piglet.dns.create.assert_called_once()
        call_args = mock_piglet.dns.create.call_args
        assert call_args[0][0] == "example.com"

    def test_apply_create_multiple_values(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_record = MagicMock()
        mock_record.name = ""
        mock_record._type = "A"
        mock_record.ttl = 600
        mock_record.values = ["1.2.3.4", "5.6.7.8"]

        mock_change = MagicMock()
        mock_change.new = mock_record

        provider._apply_Create(mock_change, zone)

        assert mock_piglet.dns.create.call_count == 2

    def test_apply_update_deletes_then_creates(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_existing = MagicMock()
        mock_existing.name = "www"
        mock_existing._type = "A"

        mock_new = MagicMock()
        mock_new.name = "www"
        mock_new._type = "A"
        mock_new.ttl = 600
        mock_new.values = ["5.6.7.8"]

        mock_change = MagicMock()
        mock_change.existing = mock_existing
        mock_change.new = mock_new

        provider._apply_Update(mock_change, zone)

        mock_piglet.dns.delete_by_name_type.assert_called_once_with("example.com", "A", "www")
        mock_piglet.dns.create.assert_called_once()

    def test_apply_dispatches_to_correct_method(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_record = MagicMock()
        mock_record.name = "www"
        mock_record._type = "A"
        mock_record.ttl = 600
        mock_record.values = ["1.2.3.4"]

        mock_change = MagicMock()
        mock_change.__class__.__name__ = "Create"
        mock_change.new = mock_record

        mock_plan = MagicMock()
        mock_plan.desired = zone
        mock_plan.changes = [mock_change]

        provider._apply(mock_plan)

        mock_piglet.dns.create.assert_called_once()


class TestGenRecords:
    @pytest.fixture
    def provider(self) -> PorkbunProvider:
        with patch("octodns_porkbun.Piglet"):
            return PorkbunProvider("test", api_key="key", secret_key="secret")

    @pytest.fixture
    def zone(self) -> Zone:
        return Zone("example.com.", [])

    def test_gen_records_a(self, provider: PorkbunProvider, zone: Zone) -> None:
        mock_record = MagicMock()
        mock_record.name = "www"
        mock_record._type = "A"
        mock_record.ttl = 600
        mock_record.values = ["1.2.3.4", "5.6.7.8"]

        records = provider._gen_records(mock_record, zone)

        assert len(records) == 2
        assert records[0].content == "1.2.3.4"
        assert records[1].content == "5.6.7.8"
        assert records[0].name == "www"

    def test_gen_records_aaaa(self, provider: PorkbunProvider, zone: Zone) -> None:
        mock_record = MagicMock()
        mock_record.name = ""
        mock_record._type = "AAAA"
        mock_record.ttl = 600
        mock_record.values = ["2001:db8::1"]

        records = provider._gen_records(mock_record, zone)

        assert len(records) == 1
        assert records[0].content == "2001:db8::1"
        assert records[0].name is None

    def test_gen_records_cname(self, provider: PorkbunProvider, zone: Zone) -> None:
        mock_record = MagicMock()
        mock_record.name = "www"
        mock_record._type = "CNAME"
        mock_record.ttl = 600
        mock_record.value = "example.com."

        records = provider._gen_records(mock_record, zone)

        assert len(records) == 1
        assert records[0].content == "example.com"

    def test_gen_records_alias(self, provider: PorkbunProvider, zone: Zone) -> None:
        mock_record = MagicMock()
        mock_record.name = ""
        mock_record._type = "ALIAS"
        mock_record.ttl = 600
        mock_record.value = "target.example.com."

        records = provider._gen_records(mock_record, zone)

        assert len(records) == 1
        assert records[0].content == "target.example.com"

    def test_gen_records_mx(self, provider: PorkbunProvider, zone: Zone) -> None:
        mock_value = MagicMock()
        mock_value.exchange = "mail.example.com."
        mock_value.preference = 10

        mock_record = MagicMock()
        mock_record.name = ""
        mock_record._type = "MX"
        mock_record.ttl = 600
        mock_record.values = [mock_value]

        records = provider._gen_records(mock_record, zone)

        assert len(records) == 1
        assert records[0].content == "mail.example.com"
        assert records[0].priority == 10

    def test_gen_records_ns(self, provider: PorkbunProvider, zone: Zone) -> None:
        mock_record = MagicMock()
        mock_record.name = "sub"
        mock_record._type = "NS"
        mock_record.ttl = 600
        mock_record.values = ["ns1.example.com.", "ns2.example.com."]

        records = provider._gen_records(mock_record, zone)

        assert len(records) == 2
        assert records[0].content == "ns1.example.com"
        assert records[1].content == "ns2.example.com"

    def test_gen_records_txt(self, provider: PorkbunProvider, zone: Zone) -> None:
        mock_record = MagicMock()
        mock_record.name = ""
        mock_record._type = "TXT"
        mock_record.ttl = 600
        mock_record.values = ["v=spf1 -all"]

        records = provider._gen_records(mock_record, zone)

        assert len(records) == 1
        assert records[0].content == "v=spf1 -all"

    def test_gen_records_srv(self, provider: PorkbunProvider, zone: Zone) -> None:
        mock_value = MagicMock()
        mock_value.priority = 10
        mock_value.weight = 5
        mock_value.port = 5060
        mock_value.target = "sipserver.example.com."

        mock_record = MagicMock()
        mock_record.name = "_sip._tcp"
        mock_record._type = "SRV"
        mock_record.ttl = 600
        mock_record.values = [mock_value]

        records = provider._gen_records(mock_record, zone)

        assert len(records) == 1
        assert records[0].content == "5 5060 sipserver.example.com"
        assert records[0].priority == 10

    def test_gen_records_caa(self, provider: PorkbunProvider, zone: Zone) -> None:
        mock_value = MagicMock()
        mock_value.flags = 0
        mock_value.tag = "issue"
        mock_value.value = "letsencrypt.org"

        mock_record = MagicMock()
        mock_record.name = ""
        mock_record._type = "CAA"
        mock_record.ttl = 600
        mock_record.values = [mock_value]

        records = provider._gen_records(mock_record, zone)

        assert len(records) == 1
        assert records[0].content == '0 issue "letsencrypt.org"'

    def test_gen_records_sshfp(self, provider: PorkbunProvider, zone: Zone) -> None:
        mock_value = MagicMock()
        mock_value.algorithm = 1
        mock_value.fingerprint_type = 2
        mock_value.fingerprint = "abc123"

        mock_record = MagicMock()
        mock_record.name = ""
        mock_record._type = "SSHFP"
        mock_record.ttl = 600
        mock_record.values = [mock_value]

        records = provider._gen_records(mock_record, zone)

        assert len(records) == 1
        assert records[0].content == "1 2 abc123"

    def test_gen_records_tlsa(self, provider: PorkbunProvider, zone: Zone) -> None:
        mock_value = MagicMock()
        mock_value.certificate_usage = 3
        mock_value.selector = 1
        mock_value.matching_type = 1
        mock_value.certificate_association_data = "abc123def456"

        mock_record = MagicMock()
        mock_record.name = "_443._tcp"
        mock_record._type = "TLSA"
        mock_record.ttl = 600
        mock_record.values = [mock_value]

        records = provider._gen_records(mock_record, zone)

        assert len(records) == 1
        assert records[0].content == "3 1 1 abc123def456"

    def test_gen_records_https(self, provider: PorkbunProvider, zone: Zone) -> None:
        mock_value = MagicMock()
        mock_value.priority = 1
        mock_value.target = "."
        mock_value.params = "alpn=h2"

        mock_record = MagicMock()
        mock_record.name = ""
        mock_record._type = "HTTPS"
        mock_record.ttl = 600
        mock_record.values = [mock_value]

        records = provider._gen_records(mock_record, zone)

        assert len(records) == 1
        assert records[0].priority == 1

    def test_gen_records_svcb(self, provider: PorkbunProvider, zone: Zone) -> None:
        mock_value = MagicMock()
        mock_value.priority = 1
        mock_value.target = "svc.example.com."

        mock_record = MagicMock()
        mock_record.name = "_foo"
        mock_record._type = "SVCB"
        mock_record.ttl = 600
        mock_record.values = [mock_value]

        with patch.object(
            mock_value,
            "__getattribute__",
            side_effect=lambda x: "" if x == "params" else getattr(mock_value, x),
        ):
            records = provider._gen_records(mock_record, zone)

        assert len(records) == 1


class TestDataConversionExtended:
    @pytest.fixture
    def provider(self) -> PorkbunProvider:
        with patch("octodns_porkbun.Piglet"):
            return PorkbunProvider("test", api_key="key", secret_key="secret")

    def test_data_for_sshfp(self, provider: PorkbunProvider) -> None:
        records = [make_dns_response("1", "example.com", "SSHFP", "1 2 abc123def456")]
        data = provider._data_for("SSHFP", records)
        assert data["type"] == "SSHFP"
        assert len(data["values"]) == 1
        assert data["values"][0]["algorithm"] == 1
        assert data["values"][0]["fingerprint_type"] == 2
        assert data["values"][0]["fingerprint"] == "abc123def456"

    def test_data_for_tlsa(self, provider: PorkbunProvider) -> None:
        records = [make_dns_response("1", "_443._tcp.example.com", "TLSA", "3 1 1 abc123")]
        data = provider._data_for("TLSA", records)
        assert data["type"] == "TLSA"
        assert len(data["values"]) == 1
        assert data["values"][0]["certificate_usage"] == 3
        assert data["values"][0]["selector"] == 1
        assert data["values"][0]["matching_type"] == 1
        assert data["values"][0]["certificate_association_data"] == "abc123"

    def test_data_for_https(self, provider: PorkbunProvider) -> None:
        records = [make_dns_response("1", "example.com", "HTTPS", ". alpn=h2", priority=1)]
        data = provider._data_for("HTTPS", records)
        assert data["type"] == "HTTPS"
        assert len(data["values"]) == 1
        assert data["values"][0]["priority"] == 1
        assert data["values"][0]["target"] == "."
        assert data["values"][0]["params"] == "alpn=h2"

    def test_data_for_svcb(self, provider: PorkbunProvider) -> None:
        records = [
            make_dns_response("1", "_foo.example.com", "SVCB", "target.example.com", priority=1)
        ]
        data = provider._data_for("SVCB", records)
        assert data["type"] == "SVCB"
        assert len(data["values"]) == 1
        assert data["values"][0]["priority"] == 1
        assert data["values"][0]["target"] == "target.example.com."

    def test_data_for_alias(self, provider: PorkbunProvider) -> None:
        records = [make_dns_response("1", "example.com", "ALIAS", "target.example.com")]
        data = provider._data_for("ALIAS", records)
        assert data["type"] == "ALIAS"
        assert data["value"] == "target.example.com."

    def test_data_for_ns(self, provider: PorkbunProvider) -> None:
        records = [
            make_dns_response("1", "sub.example.com", "NS", "ns1.example.com"),
            make_dns_response("2", "sub.example.com", "NS", "ns2.example.com"),
        ]
        data = provider._data_for("NS", records)
        assert data["type"] == "NS"
        assert data["values"] == ["ns1.example.com", "ns2.example.com"]

    def test_data_for_aaaa(self, provider: PorkbunProvider) -> None:
        records = [make_dns_response("1", "example.com", "AAAA", "2001:db8::1")]
        data = provider._data_for("AAAA", records)
        assert data["type"] == "AAAA"
        assert data["values"] == ["2001:db8::1"]


class TestPopulateExceptionHandling:
    @pytest.fixture
    def provider(self, mock_piglet: MagicMock) -> PorkbunProvider:
        with patch("octodns_porkbun.Piglet", return_value=mock_piglet):
            return PorkbunProvider("test", api_key="key", secret_key="secret")

    @pytest.fixture
    def zone(self) -> Zone:
        return Zone("example.com.", [])

    def test_populate_handles_not_found_error(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_piglet.dns.list.side_effect = Exception("Domain not found")
        exists = provider.populate(zone, target=True)
        assert exists is False

    def test_populate_handles_invalid_domain_error(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_piglet.dns.list.side_effect = Exception("Invalid domain provided")
        exists = provider.populate(zone, target=True)
        assert exists is False

    def test_populate_raises_other_errors(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_piglet.dns.list.side_effect = Exception("Connection timeout")
        with pytest.raises(Exception, match="Connection timeout"):
            provider.populate(zone, target=True)

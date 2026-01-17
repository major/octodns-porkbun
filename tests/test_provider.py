from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from octodns.zone import Zone

from octodns_porkbun import PorkbunProvider
from tests.conftest import make_dns_response


@pytest.fixture
def provider(mock_piglet: MagicMock) -> PorkbunProvider:
    with patch("octodns_porkbun.Piglet", return_value=mock_piglet):
        return PorkbunProvider("test", api_key="key", secret_key="secret")


@pytest.fixture
def zone() -> Zone:
    return Zone("example.com.", [])


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
    @pytest.mark.parametrize(
        ("record_name", "expected"),
        [
            ("example.com", ""),
            ("www.example.com", "www"),
            ("api.v1.example.com", "api.v1"),
        ],
    )
    def test_relative_name(
        self, provider: PorkbunProvider, zone: Zone, record_name: str, expected: str
    ) -> None:
        assert provider._relative_name(record_name, zone) == expected

    @pytest.mark.parametrize(
        ("relative_name", "expected"),
        [
            ("", "example.com"),
            ("www", "www.example.com"),
        ],
    )
    def test_absolute_name(
        self, provider: PorkbunProvider, zone: Zone, relative_name: str, expected: str
    ) -> None:
        assert provider._absolute_name(relative_name, zone) == expected

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("", None),
            ("www", "www"),
        ],
    )
    def test_subdomain_name(
        self, provider: PorkbunProvider, name: str, expected: str | None
    ) -> None:
        assert provider._subdomain_name(name) == expected

    def test_domain_name_strips_trailing_dot(self, provider: PorkbunProvider, zone: Zone) -> None:
        assert provider._domain_name(zone) == "example.com"


class TestPopulate:
    def test_populate_empty_zone_returns_false(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_piglet.dns.list.return_value = []
        assert provider.populate(zone, target=True) is False
        assert len(zone.records) == 0

    def test_populate_with_records_returns_true(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_piglet.dns.list.return_value = [
            make_dns_response("1", "example.com", "A", "1.2.3.4"),
            make_dns_response("2", "www.example.com", "A", "1.2.3.4"),
        ]
        assert provider.populate(zone, target=True) is True
        assert len(zone.records) == 2

    def test_populate_groups_records_by_name_and_type(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_piglet.dns.list.return_value = [
            make_dns_response("1", "example.com", "A", "1.2.3.4"),
            make_dns_response("2", "example.com", "A", "5.6.7.8"),
        ]
        provider.populate(zone, target=True)
        assert len(zone.records) == 1
        assert len(list(zone.records)[0].values) == 2

    def test_populate_skips_unsupported_types(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_piglet.dns.list.return_value = [
            make_dns_response("1", "example.com", "A", "1.2.3.4"),
            make_dns_response("2", "example.com", "UNSUPPORTED", "data"),
        ]
        provider.populate(zone, target=True)
        assert len(zone.records) == 1

    @pytest.mark.parametrize(
        "error_message",
        ["Domain not found", "Invalid domain provided"],
    )
    def test_populate_handles_known_errors(
        self,
        provider: PorkbunProvider,
        zone: Zone,
        mock_piglet: MagicMock,
        error_message: str,
    ) -> None:
        mock_piglet.dns.list.side_effect = Exception(error_message)
        assert provider.populate(zone, target=True) is False

    def test_populate_raises_unknown_errors(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_piglet.dns.list.side_effect = Exception("Connection timeout")
        with pytest.raises(Exception, match="Connection timeout"):
            provider.populate(zone, target=True)


class TestDataForConversion:
    @pytest.mark.parametrize(
        ("record_type", "content", "expected_key", "expected_value"),
        [
            ("A", "1.2.3.4", "values", ["1.2.3.4"]),
            ("AAAA", "2001:db8::1", "values", ["2001:db8::1"]),
            ("NS", "ns1.example.com", "values", ["ns1.example.com"]),
            ("TXT", "v=spf1 -all", "values", ["v=spf1 -all"]),
        ],
    )
    def test_data_for_simple_multi_value_types(
        self,
        provider: PorkbunProvider,
        record_type: str,
        content: str,
        expected_key: str,
        expected_value: list[str],
    ) -> None:
        records = [make_dns_response("1", "example.com", record_type, content)]
        data = provider._data_for(record_type, records)
        assert data["type"] == record_type
        assert data[expected_key] == expected_value

    @pytest.mark.parametrize(
        ("record_type", "content", "expected_value"),
        [
            ("CNAME", "example.com", "example.com."),
            ("CNAME", "example.com.", "example.com."),
            ("ALIAS", "target.example.com", "target.example.com."),
        ],
    )
    def test_data_for_single_value_types(
        self,
        provider: PorkbunProvider,
        record_type: str,
        content: str,
        expected_value: str,
    ) -> None:
        records = [make_dns_response("1", "www.example.com", record_type, content)]
        data = provider._data_for(record_type, records)
        assert data["type"] == record_type
        assert data["value"] == expected_value

    def test_data_for_mx(self, provider: PorkbunProvider) -> None:
        records = [
            make_dns_response("1", "example.com", "MX", "mail1.example.com", priority=10),
            make_dns_response("2", "example.com", "MX", "mail2.example.com", priority=20),
        ]
        data = provider._data_for("MX", records)
        assert data["values"][0] == {"preference": 10, "exchange": "mail1.example.com."}
        assert data["values"][1] == {"preference": 20, "exchange": "mail2.example.com."}

    def test_data_for_srv(self, provider: PorkbunProvider) -> None:
        records = [
            make_dns_response(
                "1", "_sip._tcp.example.com", "SRV", "5 5060 sipserver.example.com", priority=10
            )
        ]
        data = provider._data_for("SRV", records)
        assert data["values"][0] == {
            "priority": 10,
            "weight": 5,
            "port": 5060,
            "target": "sipserver.example.com.",
        }

    def test_data_for_caa(self, provider: PorkbunProvider) -> None:
        records = [make_dns_response("1", "example.com", "CAA", '0 issue "letsencrypt.org"')]
        data = provider._data_for("CAA", records)
        assert data["values"][0] == {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}

    def test_data_for_sshfp(self, provider: PorkbunProvider) -> None:
        records = [make_dns_response("1", "example.com", "SSHFP", "1 2 abc123def456")]
        data = provider._data_for("SSHFP", records)
        assert data["values"][0] == {
            "algorithm": 1,
            "fingerprint_type": 2,
            "fingerprint": "abc123def456",
        }

    def test_data_for_tlsa(self, provider: PorkbunProvider) -> None:
        records = [make_dns_response("1", "_443._tcp.example.com", "TLSA", "3 1 1 abc123")]
        data = provider._data_for("TLSA", records)
        assert data["values"][0] == {
            "certificate_usage": 3,
            "selector": 1,
            "matching_type": 1,
            "certificate_association_data": "abc123",
        }

    def test_data_for_https(self, provider: PorkbunProvider) -> None:
        records = [make_dns_response("1", "example.com", "HTTPS", ". alpn=h2", priority=1)]
        data = provider._data_for("HTTPS", records)
        assert data["values"][0] == {"priority": 1, "target": ".", "params": "alpn=h2"}

    def test_data_for_svcb(self, provider: PorkbunProvider) -> None:
        records = [
            make_dns_response("1", "_foo.example.com", "SVCB", "target.example.com", priority=1)
        ]
        data = provider._data_for("SVCB", records)
        assert data["values"][0]["priority"] == 1
        assert data["values"][0]["target"] == "target.example.com."


class TestApply:
    @pytest.mark.parametrize(
        ("name", "expected_subdomain"),
        [
            ("www", "www"),
            ("", None),
        ],
    )
    def test_apply_delete(
        self,
        provider: PorkbunProvider,
        zone: Zone,
        mock_piglet: MagicMock,
        name: str,
        expected_subdomain: str | None,
    ) -> None:
        mock_record = MagicMock(name=name, _type="A")
        mock_record.name = name
        mock_change = MagicMock(existing=mock_record)

        provider._apply_Delete(mock_change, zone)

        mock_piglet.dns.delete_by_name_type.assert_called_once_with(
            "example.com", "A", expected_subdomain
        )

    def test_apply_create(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_record = MagicMock(name="www", _type="A", ttl=600, values=["1.2.3.4", "5.6.7.8"])
        mock_change = MagicMock(new=mock_record)

        provider._apply_Create(mock_change, zone)

        assert mock_piglet.dns.create.call_count == 2
        assert mock_piglet.dns.create.call_args[0][0] == "example.com"

    def test_apply_update_deletes_then_creates(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_existing = MagicMock(name="www", _type="A")
        mock_existing.name = "www"
        mock_new = MagicMock(name="www", _type="A", ttl=600, values=["5.6.7.8"])
        mock_change = MagicMock(existing=mock_existing, new=mock_new)

        provider._apply_Update(mock_change, zone)

        mock_piglet.dns.delete_by_name_type.assert_called_once()
        mock_piglet.dns.create.assert_called_once()

    def test_apply_dispatches_correctly(
        self, provider: PorkbunProvider, zone: Zone, mock_piglet: MagicMock
    ) -> None:
        mock_record = MagicMock(name="www", _type="A", ttl=600, values=["1.2.3.4"])
        mock_change = MagicMock(new=mock_record)
        mock_change.__class__.__name__ = "Create"

        mock_plan = MagicMock(desired=zone, changes=[mock_change])
        provider._apply(mock_plan)

        mock_piglet.dns.create.assert_called_once()


class TestGenRecords:
    @pytest.fixture
    def mock_octodns_record(self) -> MagicMock:
        return MagicMock(ttl=600)

    @pytest.mark.parametrize(
        ("record_type", "values", "expected_contents"),
        [
            ("A", ["1.2.3.4", "5.6.7.8"], ["1.2.3.4", "5.6.7.8"]),
            ("AAAA", ["2001:db8::1"], ["2001:db8::1"]),
            (
                "NS",
                ["ns1.example.com.", "ns2.example.com."],
                ["ns1.example.com", "ns2.example.com"],
            ),
            ("TXT", ["v=spf1 -all"], ["v=spf1 -all"]),
        ],
    )
    def test_gen_records_multi_value(
        self,
        provider: PorkbunProvider,
        zone: Zone,
        mock_octodns_record: MagicMock,
        record_type: str,
        values: list[str],
        expected_contents: list[str],
    ) -> None:
        mock_octodns_record.name = "www"
        mock_octodns_record._type = record_type
        mock_octodns_record.values = values

        records = provider._gen_records(mock_octodns_record, zone)

        assert len(records) == len(expected_contents)
        for record, expected in zip(records, expected_contents, strict=True):
            assert record.content == expected

    @pytest.mark.parametrize(
        ("record_type", "value", "expected_content"),
        [
            ("CNAME", "example.com.", "example.com"),
            ("ALIAS", "target.example.com.", "target.example.com"),
        ],
    )
    def test_gen_records_single_value(
        self,
        provider: PorkbunProvider,
        zone: Zone,
        mock_octodns_record: MagicMock,
        record_type: str,
        value: str,
        expected_content: str,
    ) -> None:
        mock_octodns_record.name = "www"
        mock_octodns_record._type = record_type
        mock_octodns_record.value = value

        records = provider._gen_records(mock_octodns_record, zone)

        assert len(records) == 1
        assert records[0].content == expected_content

    def test_gen_records_mx(
        self, provider: PorkbunProvider, zone: Zone, mock_octodns_record: MagicMock
    ) -> None:
        mock_value = MagicMock(exchange="mail.example.com.", preference=10)
        mock_octodns_record.name = ""
        mock_octodns_record._type = "MX"
        mock_octodns_record.values = [mock_value]

        records = provider._gen_records(mock_octodns_record, zone)

        assert records[0].content == "mail.example.com"
        assert records[0].priority == 10

    def test_gen_records_srv(
        self, provider: PorkbunProvider, zone: Zone, mock_octodns_record: MagicMock
    ) -> None:
        mock_value = MagicMock(priority=10, weight=5, port=5060, target="sipserver.example.com.")
        mock_octodns_record.name = "_sip._tcp"
        mock_octodns_record._type = "SRV"
        mock_octodns_record.values = [mock_value]

        records = provider._gen_records(mock_octodns_record, zone)

        assert records[0].content == "5 5060 sipserver.example.com"
        assert records[0].priority == 10

    def test_gen_records_caa(
        self, provider: PorkbunProvider, zone: Zone, mock_octodns_record: MagicMock
    ) -> None:
        mock_value = MagicMock(flags=0, tag="issue", value="letsencrypt.org")
        mock_octodns_record.name = ""
        mock_octodns_record._type = "CAA"
        mock_octodns_record.values = [mock_value]

        records = provider._gen_records(mock_octodns_record, zone)

        assert records[0].content == '0 issue "letsencrypt.org"'

    def test_gen_records_sshfp(
        self, provider: PorkbunProvider, zone: Zone, mock_octodns_record: MagicMock
    ) -> None:
        mock_value = MagicMock(algorithm=1, fingerprint_type=2, fingerprint="abc123")
        mock_octodns_record.name = ""
        mock_octodns_record._type = "SSHFP"
        mock_octodns_record.values = [mock_value]

        records = provider._gen_records(mock_octodns_record, zone)

        assert records[0].content == "1 2 abc123"

    def test_gen_records_tlsa(
        self, provider: PorkbunProvider, zone: Zone, mock_octodns_record: MagicMock
    ) -> None:
        mock_value = MagicMock(
            certificate_usage=3,
            selector=1,
            matching_type=1,
            certificate_association_data="abc123def456",
        )
        mock_octodns_record.name = "_443._tcp"
        mock_octodns_record._type = "TLSA"
        mock_octodns_record.values = [mock_value]

        records = provider._gen_records(mock_octodns_record, zone)

        assert records[0].content == "3 1 1 abc123def456"

    def test_gen_records_https(
        self, provider: PorkbunProvider, zone: Zone, mock_octodns_record: MagicMock
    ) -> None:
        mock_value = MagicMock(priority=1, target=".", params="alpn=h2")
        mock_octodns_record.name = ""
        mock_octodns_record._type = "HTTPS"
        mock_octodns_record.values = [mock_value]

        records = provider._gen_records(mock_octodns_record, zone)

        assert len(records) == 1
        assert records[0].priority == 1

    def test_gen_records_svcb(
        self, provider: PorkbunProvider, zone: Zone, mock_octodns_record: MagicMock
    ) -> None:
        mock_value = MagicMock(priority=1, target="svc.example.com.")
        mock_octodns_record.name = "_foo"
        mock_octodns_record._type = "SVCB"
        mock_octodns_record.values = [mock_value]

        with patch.object(
            mock_value,
            "__getattribute__",
            side_effect=lambda x: "" if x == "params" else getattr(mock_value, x),
        ):
            records = provider._gen_records(mock_octodns_record, zone)

        assert len(records) == 1

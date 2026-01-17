"""Porkbun DNS provider for octoDNS."""

from __future__ import annotations

from collections import defaultdict
from logging import getLogger
from typing import TYPE_CHECKING, Any, Literal

from octodns.provider.base import BaseProvider
from octodns.record import Record
from oinker import Piglet
from oinker.dns import (
    CAARecord,
    HTTPSRecord,
    MXRecord,
    SRVRecord,
    SSHFPRecord,
    SVCBRecord,
    TLSARecord,
    create_record,
)

if TYPE_CHECKING:
    from octodns.provider.plan import Plan
    from octodns.zone import Zone
    from oinker.dns import DNSRecord, DNSRecordResponse

__version__ = "0.0.1"
__all__ = ["PorkbunProvider"]

RecordType = Literal[
    "A", "AAAA", "ALIAS", "CAA", "CNAME", "HTTPS", "MX", "NS", "SRV", "SSHFP", "SVCB", "TLSA", "TXT"
]

SINGLE_VALUE_TYPES: frozenset[str] = frozenset({"CNAME", "ALIAS"})
PRIORITY_TYPES: frozenset[str] = frozenset({"MX", "SRV", "HTTPS", "SVCB"})


class PorkbunProvider(BaseProvider):
    """octoDNS provider for Porkbun DNS using the oinker library."""

    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = False
    SUPPORTS: set[str] = {
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

    def __init__(
        self,
        id: str,
        api_key: str | None = None,
        secret_key: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self.log = getLogger(f"PorkbunProvider[{id}]")
        self.log.debug("__init__: id=%s", id)
        super().__init__(id, *args, **kwargs)

        self._client = Piglet(api_key=api_key, secret_key=secret_key)
        self._zone_records: dict[str, list[DNSRecordResponse]] = {}

    def _domain_name(self, zone: Zone) -> str:
        """Extract domain name from zone (removes trailing dot)."""
        return zone.name.rstrip(".")

    def _relative_name(self, record_name: str, zone: Zone) -> str:
        """Convert absolute record name to relative name for octoDNS."""
        domain = self._domain_name(zone)
        if record_name == domain:
            return ""
        if record_name.endswith(f".{domain}"):
            return record_name[: -(len(domain) + 1)]
        return record_name

    def _absolute_name(self, relative_name: str, zone: Zone) -> str:
        """Convert relative name to absolute name for Porkbun API."""
        domain = self._domain_name(zone)
        if not relative_name or relative_name == "":
            return domain
        return f"{relative_name}.{domain}"

    def _subdomain_name(self, relative_name: str) -> str | None:
        """Convert relative name to subdomain for oinker (None for root)."""
        if not relative_name or relative_name == "":
            return None
        return relative_name

    def populate(self, zone: Zone, target: bool = False, lenient: bool = False) -> bool:
        """Load DNS records from Porkbun into zone."""
        self.log.debug("populate: name=%s, target=%s, lenient=%s", zone.name, target, lenient)

        before = len(zone.records)
        exists = False
        domain = self._domain_name(zone)

        try:
            with self._client:
                records = self._client.dns.list(domain)

            if records:
                exists = True
                self._zone_records[zone.name] = records

                grouped: dict[tuple[str, str], list[DNSRecordResponse]] = defaultdict(list)
                for record in records:
                    if record.record_type not in self.SUPPORTS:
                        self.log.debug(
                            "populate: skipping unsupported record type %s", record.record_type
                        )
                        continue
                    relative = self._relative_name(record.name, zone)
                    grouped[(relative, record.record_type)].append(record)

                for (name, record_type), recs in grouped.items():
                    data = self._data_for(record_type, recs)
                    record = Record.new(zone, name, data, source=self, lenient=lenient)
                    zone.add_record(record, lenient=lenient)

        except Exception as e:
            if "not found" in str(e).lower() or "invalid domain" in str(e).lower():
                self.log.debug("populate: zone %s not found", zone.name)
                exists = False
            else:
                raise

        self.log.info(
            "populate: found %d records, exists=%s",
            len(zone.records) - before,
            exists,
        )
        return exists

    def _data_for(self, record_type: str, records: list[DNSRecordResponse]) -> dict[str, Any]:
        """Convert Porkbun API records to octoDNS data format."""
        ttl = records[0].ttl
        handlers: dict[str, Any] = {
            "A": self._data_for_simple,
            "AAAA": self._data_for_simple,
            "NS": self._data_for_simple,
            "TXT": self._data_for_simple,
            "CNAME": self._data_for_single,
            "ALIAS": self._data_for_single,
            "MX": self._data_for_mx,
            "SRV": self._data_for_srv,
            "CAA": self._data_for_caa,
            "SSHFP": self._data_for_sshfp,
            "TLSA": self._data_for_tlsa,
            "HTTPS": self._data_for_svcb,
            "SVCB": self._data_for_svcb,
        }
        handler = handlers.get(record_type, self._data_for_simple)
        return handler(record_type, ttl, records)

    def _data_for_simple(
        self, record_type: str, ttl: int, records: list[DNSRecordResponse]
    ) -> dict[str, Any]:
        """Handle simple multi-value record types (A, AAAA, NS, TXT)."""
        return {
            "type": record_type,
            "ttl": ttl,
            "values": [r.content for r in records],
        }

    def _data_for_single(
        self, record_type: str, ttl: int, records: list[DNSRecordResponse]
    ) -> dict[str, Any]:
        """Handle single-value record types with trailing dot (CNAME, ALIAS)."""
        content = records[0].content
        if not content.endswith("."):
            content = f"{content}."
        return {
            "type": record_type,
            "ttl": ttl,
            "value": content,
        }

    def _data_for_mx(
        self, record_type: str, ttl: int, records: list[DNSRecordResponse]
    ) -> dict[str, Any]:
        """Handle MX records."""
        values = []
        for r in records:
            exchange = r.content
            if not exchange.endswith("."):
                exchange = f"{exchange}."
            values.append({"preference": r.priority, "exchange": exchange})
        return {"type": record_type, "ttl": ttl, "values": values}

    def _data_for_srv(
        self, record_type: str, ttl: int, records: list[DNSRecordResponse]
    ) -> dict[str, Any]:
        """Handle SRV records."""
        values = []
        for r in records:
            parts = r.content.split()
            if len(parts) >= 3:
                target = parts[2]
                if not target.endswith("."):
                    target = f"{target}."
                values.append(
                    {
                        "priority": r.priority,
                        "weight": int(parts[0]),
                        "port": int(parts[1]),
                        "target": target,
                    }
                )
        return {"type": record_type, "ttl": ttl, "values": values}

    def _data_for_caa(
        self, record_type: str, ttl: int, records: list[DNSRecordResponse]
    ) -> dict[str, Any]:
        """Handle CAA records."""
        values = []
        for r in records:
            parts = r.content.split(None, 2)
            if len(parts) >= 3:
                value = parts[2].strip('"')
                values.append({"flags": int(parts[0]), "tag": parts[1], "value": value})
        return {"type": record_type, "ttl": ttl, "values": values}

    def _data_for_sshfp(
        self, record_type: str, ttl: int, records: list[DNSRecordResponse]
    ) -> dict[str, Any]:
        """Handle SSHFP records."""
        values = []
        for r in records:
            parts = r.content.split()
            if len(parts) >= 3:
                values.append(
                    {
                        "algorithm": int(parts[0]),
                        "fingerprint_type": int(parts[1]),
                        "fingerprint": parts[2],
                    }
                )
        return {"type": record_type, "ttl": ttl, "values": values}

    def _data_for_tlsa(
        self, record_type: str, ttl: int, records: list[DNSRecordResponse]
    ) -> dict[str, Any]:
        """Handle TLSA records."""
        values = []
        for r in records:
            parts = r.content.split()
            if len(parts) >= 4:
                values.append(
                    {
                        "certificate_usage": int(parts[0]),
                        "selector": int(parts[1]),
                        "matching_type": int(parts[2]),
                        "certificate_association_data": parts[3],
                    }
                )
        return {"type": record_type, "ttl": ttl, "values": values}

    def _data_for_svcb(
        self, record_type: str, ttl: int, records: list[DNSRecordResponse]
    ) -> dict[str, Any]:
        """Handle HTTPS/SVCB records."""
        values = []
        for r in records:
            parts = r.content.split(None, 1)
            if len(parts) >= 1:
                target = parts[0]
                if not target.endswith("."):
                    target = f"{target}."
                value: dict[str, Any] = {"priority": r.priority, "target": target}
                if len(parts) > 1:
                    value["params"] = parts[1]
                values.append(value)
        return {"type": record_type, "ttl": ttl, "values": values}

    def _apply(self, plan: Plan) -> None:
        """Apply changes to Porkbun."""
        desired = plan.desired
        changes = plan.changes

        self.log.debug("_apply: zone=%s, len(changes)=%d", desired.name, len(changes))

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f"_apply_{class_name}")(change, desired)

    def _apply_Create(self, change: Any, zone: Zone) -> None:
        """Create new DNS records."""
        record = change.new
        domain = self._domain_name(zone)

        self.log.debug("_apply_Create: %s %s", record._type, record.name)

        with self._client:
            for oinker_record in self._gen_records(record, zone):
                self._client.dns.create(domain, oinker_record)

    def _apply_Update(self, change: Any, zone: Zone) -> None:
        """Update DNS records (delete + create)."""
        self.log.debug("_apply_Update: %s %s", change.existing._type, change.existing.name)
        self._apply_Delete(change, zone)
        self._apply_Create(change, zone)

    def _apply_Delete(self, change: Any, zone: Zone) -> None:
        """Delete DNS records."""
        record = change.existing
        domain = self._domain_name(zone)
        subdomain = self._subdomain_name(record.name)

        self.log.debug("_apply_Delete: %s %s", record._type, record.name)

        with self._client:
            self._client.dns.delete_by_name_type(domain, record._type, subdomain)

    def _gen_records(self, record: Any, zone: Zone) -> list[DNSRecord]:
        """Generate oinker DNS records from octoDNS record."""
        subdomain = self._subdomain_name(record.name)
        ttl = record.ttl
        record_type = record._type

        generators: dict[str, Any] = {
            "A": self._gen_simple,
            "AAAA": self._gen_simple,
            "NS": self._gen_simple,
            "TXT": self._gen_simple,
            "CNAME": self._gen_single,
            "ALIAS": self._gen_single,
            "MX": self._gen_mx,
            "SRV": self._gen_srv,
            "CAA": self._gen_caa,
            "SSHFP": self._gen_sshfp,
            "TLSA": self._gen_tlsa,
            "HTTPS": self._gen_svcb,
            "SVCB": self._gen_svcb,
        }
        generator = generators.get(record_type)
        if generator:
            return generator(record, subdomain, ttl)
        return []

    def _gen_simple(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate simple multi-value records (A, AAAA, NS, TXT)."""
        record_type = record._type
        result: list[DNSRecord] = []
        for value in record.values:
            content = value.rstrip(".") if record_type == "NS" else value
            result.append(create_record(record_type, content, name=subdomain, ttl=ttl))
        return result

    def _gen_single(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate single-value records (CNAME, ALIAS)."""
        content = record.value.rstrip(".")
        return [create_record(record._type, content, name=subdomain, ttl=ttl)]

    def _gen_mx(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate MX records."""
        result: list[DNSRecord] = []
        for value in record.values:
            exchange = value.exchange.rstrip(".")
            result.append(
                MXRecord(content=exchange, priority=value.preference, name=subdomain, ttl=ttl)
            )
        return result

    def _gen_srv(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate SRV records."""
        result: list[DNSRecord] = []
        for value in record.values:
            target = value.target.rstrip(".")
            content = f"{value.weight} {value.port} {target}"
            result.append(
                SRVRecord(content=content, priority=value.priority, name=subdomain, ttl=ttl)
            )
        return result

    def _gen_caa(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate CAA records."""
        result: list[DNSRecord] = []
        for value in record.values:
            content = f'{value.flags} {value.tag} "{value.value}"'
            result.append(CAARecord(content=content, name=subdomain, ttl=ttl))
        return result

    def _gen_sshfp(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate SSHFP records."""
        result: list[DNSRecord] = []
        for value in record.values:
            content = f"{value.algorithm} {value.fingerprint_type} {value.fingerprint}"
            result.append(SSHFPRecord(content=content, name=subdomain, ttl=ttl))
        return result

    def _gen_tlsa(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate TLSA records."""
        result: list[DNSRecord] = []
        for value in record.values:
            content = (
                f"{value.certificate_usage} {value.selector} "
                f"{value.matching_type} {value.certificate_association_data}"
            )
            result.append(TLSARecord(content=content, name=subdomain, ttl=ttl))
        return result

    def _gen_svcb(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate HTTPS/SVCB records."""
        record_cls = HTTPSRecord if record._type == "HTTPS" else SVCBRecord
        result: list[DNSRecord] = []
        for value in record.values:
            target = value.target.rstrip(".")
            params = getattr(value, "params", "")
            content = f"{target} {params}".strip() if params else target
            result.append(
                record_cls(content=content, priority=value.priority, name=subdomain, ttl=ttl)
            )
        return result

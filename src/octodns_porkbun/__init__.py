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


def _ensure_trailing_dot(value: str) -> str:
    """Add trailing dot to hostname if not present (for FQDN format)."""
    return value if value.endswith(".") else f"{value}."


def _strip_trailing_dot(value: str) -> str:
    """Remove trailing dot from hostname (for Porkbun API format)."""
    return value.rstrip(".")


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

    _HANDLER_SUFFIX: dict[str, str] = {
        "A": "simple",
        "AAAA": "simple",
        "NS": "simple",
        "TXT": "simple",
        "CNAME": "single",
        "ALIAS": "single",
        "MX": "mx",
        "SRV": "srv",
        "CAA": "caa",
        "SSHFP": "sshfp",
        "TLSA": "tlsa",
        "HTTPS": "svcb",
        "SVCB": "svcb",
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
        suffix = self._HANDLER_SUFFIX.get(record_type, "simple")
        handler = getattr(self, f"_data_for_{suffix}")
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
        return {
            "type": record_type,
            "ttl": ttl,
            "value": _ensure_trailing_dot(records[0].content),
        }

    def _data_for_mx(
        self, record_type: str, ttl: int, records: list[DNSRecordResponse]
    ) -> dict[str, Any]:
        """Handle MX records."""
        values = [
            {"preference": r.priority, "exchange": _ensure_trailing_dot(r.content)} for r in records
        ]
        return {"type": record_type, "ttl": ttl, "values": values}

    def _data_for_srv(
        self, record_type: str, ttl: int, records: list[DNSRecordResponse]
    ) -> dict[str, Any]:
        """Handle SRV records."""
        values = []
        for r in records:
            parts = r.content.split()
            if len(parts) >= 3:
                values.append(
                    {
                        "priority": r.priority,
                        "weight": int(parts[0]),
                        "port": int(parts[1]),
                        "target": _ensure_trailing_dot(parts[2]),
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
                value: dict[str, Any] = {
                    "priority": r.priority,
                    "target": _ensure_trailing_dot(parts[0]),
                }
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

        suffix = self._HANDLER_SUFFIX.get(record_type)
        if suffix:
            generator = getattr(self, f"_gen_{suffix}")
            return generator(record, subdomain, ttl)
        return []

    def _gen_simple(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate simple multi-value records (A, AAAA, NS, TXT)."""
        record_type = record._type
        return [
            create_record(
                record_type,
                _strip_trailing_dot(value) if record_type == "NS" else value,
                name=subdomain,
                ttl=ttl,
            )
            for value in record.values
        ]

    def _gen_single(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate single-value records (CNAME, ALIAS)."""
        return [
            create_record(record._type, _strip_trailing_dot(record.value), name=subdomain, ttl=ttl)
        ]

    def _gen_mx(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate MX records."""
        return [
            MXRecord(
                content=_strip_trailing_dot(value.exchange),
                priority=value.preference,
                name=subdomain,
                ttl=ttl,
            )
            for value in record.values
        ]

    def _gen_srv(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate SRV records."""
        return [
            SRVRecord(
                content=f"{value.weight} {value.port} {_strip_trailing_dot(value.target)}",
                priority=value.priority,
                name=subdomain,
                ttl=ttl,
            )
            for value in record.values
        ]

    def _gen_caa(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate CAA records."""
        return [
            CAARecord(
                content=f'{value.flags} {value.tag} "{value.value}"',
                name=subdomain,
                ttl=ttl,
            )
            for value in record.values
        ]

    def _gen_sshfp(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate SSHFP records."""
        return [
            SSHFPRecord(
                content=f"{value.algorithm} {value.fingerprint_type} {value.fingerprint}",
                name=subdomain,
                ttl=ttl,
            )
            for value in record.values
        ]

    def _gen_tlsa(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate TLSA records."""
        return [
            TLSARecord(
                content=(
                    f"{value.certificate_usage} {value.selector} "
                    f"{value.matching_type} {value.certificate_association_data}"
                ),
                name=subdomain,
                ttl=ttl,
            )
            for value in record.values
        ]

    def _gen_svcb(self, record: Any, subdomain: str | None, ttl: int) -> list[DNSRecord]:
        """Generate HTTPS/SVCB records."""
        record_cls = HTTPSRecord if record._type == "HTTPS" else SVCBRecord
        result: list[DNSRecord] = []
        for value in record.values:
            target = _strip_trailing_dot(value.target)
            params = getattr(value, "params", "")
            content = f"{target} {params}".strip() if params else target
            result.append(
                record_cls(content=content, priority=value.priority, name=subdomain, ttl=ttl)
            )
        return result

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from .. import utils
from .kinds import Kind

if TYPE_CHECKING:
    from ..npmplus_client import NPMplusClient


@dataclass
class CertificateItem:
    kind: ClassVar[Kind] = Kind.CERTIFICATES

    api: NPMplusClient
    nice_name: str
    id: int = -1
    provider: str = ""
    domain_names: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def natural_index(self) -> str:
        return self.nice_name

    @classmethod
    def from_json(cls, api: NPMplusClient, data: Mapping[str, Any]) -> CertificateItem:
        nice = utils.certificate_nice_name_from_value(data.get("nice_name"))
        if not nice:
            nice = ""
        domains = data.get("domain_names")
        domain_names: list[str] = []
        if isinstance(domains, list):
            domain_names = [s for d in domains if (s := str(d).strip())]
        meta = data.get("meta")
        meta_dict: dict[str, Any] = dict(meta) if isinstance(meta, Mapping) else {}
        return cls(
            api=api,
            id=utils.normalize_int(data.get("id")),
            nice_name=nice,
            provider=str(data.get("provider") or "").strip(),
            domain_names=domain_names,
            meta=meta_dict,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "nice_name": self.nice_name,
            "provider": self.provider,
            "domain_names": list(self.domain_names),
            "meta": dict(self.meta),
        }

    def delete(self) -> None:
        if self.id <= 0:
            raise ValueError(f"Cannot delete {self.kind.value}: invalid id={self.id}")
        self.api.delete_certificate(self.id)

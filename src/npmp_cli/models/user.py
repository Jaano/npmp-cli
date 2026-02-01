from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from .. import utils
from .kinds import Kind

if TYPE_CHECKING:
    from ..npmplus_client import NPMplusClient


class UserItem:
    kind: ClassVar[Kind] = Kind.USERS

    def __init__(
        self,
        *,
        api: NPMplusClient,
        id: int,
        email: str,
        name: str,
        nickname: str,
        is_disabled: object = False,
        roles: list[str] | None = None,
        permissions: list[str] | None = None,
    ) -> None:
        self.api = api
        self.id = id
        self.email = email
        self.name = name
        self.nickname = nickname
        self.is_disabled = is_disabled
        self.roles = [] if roles is None else roles
        self.permissions = [] if permissions is None else permissions

    @property
    def enabled(self) -> bool:
        return not self.is_disabled

    @property
    def natural_index(self) -> str:
        return self.nickname.strip()

    @classmethod
    def from_json(cls, api: NPMplusClient, data: dict[str, Any]) -> UserItem:
        return cls(
            api=api,
            id=int(str(data.get("id", -1)).strip()) if data.get("id") is not None else -1,
            email=str(data.get("email", "")).strip(),
            name=str(data.get("name", "")).strip(),
            nickname=str(data.get("nickname", "")).strip(),
            is_disabled=utils.bool_or(data.get("is_disabled", False), default=False),
            roles=list(data.get("roles", [])),
            permissions=list(data.get("permissions", [])),
        )

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not value or "@" not in value:
            raise ValueError("Invalid email address")
        self._email = value.strip()

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        if not value:
            raise ValueError("Name cannot be empty")
        self._name = value.strip()

    @property
    def nickname(self) -> str:
        return self._nickname

    @nickname.setter
    def nickname(self, value: str) -> None:
        if not value:
            raise ValueError("Nickname cannot be empty")
        self._nickname = value.strip()

    @property
    def is_disabled(self) -> bool:
        return self._is_disabled

    @is_disabled.setter
    def is_disabled(self, value: object) -> None:
        self._is_disabled = utils.bool_or(value, default=False)

    @property
    def roles(self) -> list[str]:
        return self._roles

    @roles.setter
    def roles(self, value: object) -> None:
        if not isinstance(value, list):
            raise ValueError("Roles must be a list")
        self._roles = [str(r).strip() for r in value if r]

    @property
    def permissions(self) -> list[str]:
        return self._permissions

    @permissions.setter
    def permissions(self, value: object) -> None:
        if not isinstance(value, list):
            raise ValueError("Permissions must be a list")
        self._permissions = [str(p).strip() for p in value if p]

    def to_json(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "name": self.name,
            "nickname": self.nickname,
            "is_disabled": self.is_disabled,
            "roles": self.roles,
            "permissions": self.permissions,
        }

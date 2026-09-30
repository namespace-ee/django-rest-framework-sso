from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rest_framework_sso.models import SessionToken


@dataclass(frozen=True)
class JWTCredentials(Mapping):
    """
    Decoded JWT token exposed as ``request.auth`` after successful authentication.

    ``payload`` holds the verified claims, ``header`` the JOSE header the token was
    signed with, and ``session_token`` the session the token belongs to (``None``
    when session tokens are not verified).

    The object is a read-only mapping over ``payload``, so ``request.auth.get(claims.X)``
    keeps working alongside ``request.auth.payload``.
    """

    payload: dict[str, Any]
    header: dict[str, Any] = field(default_factory=dict)
    session_token: SessionToken | None = None

    def __getitem__(self, key):
        return self.payload[key]

    def __iter__(self):
        return iter(self.payload)

    def __len__(self):
        return len(self.payload)

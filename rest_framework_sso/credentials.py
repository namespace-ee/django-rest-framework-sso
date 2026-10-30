from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rest_framework_sso.models import SessionToken


@dataclass(frozen=True, kw_only=True)
class JWTCredentials(Mapping):
    """
    Decoded JWT token exposed as ``request.auth`` after successful authentication.

    ``header`` holds the JOSE header the token was signed with and ``payload`` the
    verified claims.

    The object is a read-only mapping over ``payload``, so ``request.auth.get(claims.X)``
    keeps working alongside ``request.auth.payload``.
    """

    header: dict[str, Any]
    payload: dict[str, Any]

    def __getitem__(self, key):
        return self.payload[key]

    def __iter__(self):
        return iter(self.payload)

    def __len__(self):
        return len(self.payload)


@dataclass(frozen=True, kw_only=True)
class SessionTokenCredentials(JWTCredentials):
    """
    JWT credentials whose session was verified against ``session_token``.
    """

    session_token: SessionToken

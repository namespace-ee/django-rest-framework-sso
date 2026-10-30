from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError

from rest_framework_sso import claims

if TYPE_CHECKING:
    from rest_framework_sso.models import SessionToken


@dataclass(frozen=True, kw_only=True)
class JWTCredentials:
    """
    Decoded JWT token exposed as ``request.auth`` after successful authentication.

    ``header`` holds the JOSE header the token was signed with and ``payload`` the
    verified claims; read claims through ``payload``, e.g. ``request.auth.payload.get(claims.X)``.
    """

    header: dict[str, Any]
    payload: dict[str, Any]

    def __post_init__(self):
        if not isinstance(self.header, dict):
            raise TypeError(f"header must be a dict, not {type(self.header).__name__}")
        if not isinstance(self.payload, dict):
            raise TypeError(f"payload must be a dict, not {type(self.payload).__name__}")


@dataclass(frozen=True, kw_only=True)
class VerifiedSessionCredentials(JWTCredentials):
    """
    JWT credentials whose session was verified against ``session_token``.
    """

    session_token: SessionToken

    def __post_init__(self):
        super().__post_init__()
        from rest_framework_sso.models import SessionToken

        if not isinstance(self.session_token, SessionToken):
            raise TypeError(f"session_token must be a SessionToken, not {type(self.session_token).__name__}")
        opts = self.session_token._meta  # ty: ignore[unresolved-attribute]
        try:
            session_id = opts.pk.to_python(self.payload.get(claims.SESSION_ID))
            user_id = opts.get_field("user").target_field.to_python(self.payload.get(claims.USER_ID))
        except ValidationError:
            session_id = user_id = None
        if session_id != self.session_token.pk:
            raise ValueError("session_token does not match the sid claim")
        if user_id != self.session_token.user_id:
            raise ValueError("session_token does not match the uid claim")


@dataclass(frozen=True, kw_only=True)
class SessionTokenCredentials(VerifiedSessionCredentials):
    """
    Session-verified credentials of a session token.
    """

    def __post_init__(self):
        super().__post_init__()
        if self.payload.get(claims.TOKEN) != claims.TOKEN_SESSION:
            raise ValueError("SessionTokenCredentials requires the 'session' token type")


@dataclass(frozen=True, kw_only=True)
class AuthorizationTokenCredentials(VerifiedSessionCredentials):
    """
    Session-verified credentials of an authorization token.
    """

    def __post_init__(self):
        super().__post_init__()
        if self.payload.get(claims.TOKEN) != claims.TOKEN_AUTHORIZATION:
            raise ValueError("AuthorizationTokenCredentials requires the 'auth' token type")

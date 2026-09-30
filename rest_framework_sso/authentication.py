import logging
from dataclasses import replace

import jwt.exceptions
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header

from rest_framework_sso import claims
from rest_framework_sso.models import SessionToken
from rest_framework_sso.settings import api_settings

logger = logging.getLogger(__name__)

decode_jwt_token = api_settings.DECODE_JWT_TOKEN


class JWTAuthentication(BaseAuthentication):
    """
    JWT token based authentication.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "JWT ".  For example:

        Authorization: JWT eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb2NhbG...

    On success ``request.auth`` is a ``JWTCredentials`` instance carrying the
    decoded ``payload``, the token ``header`` and the matching ``session_token``.
    """

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        authenticate_header = self.authenticate_header(request=request)

        if not auth or auth[0].lower() != authenticate_header.lower().encode():
            return None

        if len(auth) == 1:
            msg = _("Invalid token header. No credentials provided.")
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _("Invalid token header. Token string should not contain spaces.")
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1].decode()
        except UnicodeError:
            msg = _("Invalid token header. Token string should not contain invalid characters.")
            raise exceptions.AuthenticationFailed(msg)

        try:
            credentials = decode_jwt_token(token=token)
        except jwt.exceptions.ExpiredSignatureError:
            msg = _("Signature has expired.")
            raise exceptions.AuthenticationFailed(msg)
        except jwt.exceptions.DecodeError:
            msg = _("Error decoding signature.")
            raise exceptions.AuthenticationFailed(msg)
        except jwt.exceptions.InvalidKeyError:
            msg = _("Unauthorized token signing key.")
            raise exceptions.AuthenticationFailed(msg)
        except jwt.exceptions.InvalidTokenError:
            raise exceptions.AuthenticationFailed()

        return self.authenticate_credentials(credentials=credentials, request=request)

    def authenticate_credentials(self, credentials, request=None):
        """
        Resolve the decoded token into ``(user, credentials)``, where the returned
        credentials carry the verified session token.
        """
        session_token = self.get_session_token(credentials=credentials, request=request)
        user = self.get_user(credentials=credentials, session_token=session_token)

        if not user.is_active:
            raise exceptions.AuthenticationFailed(_("User inactive or deleted."))

        return user, replace(credentials, session_token=session_token)

    def get_session_token(self, credentials, request=None):
        """
        Look up and touch the active session token the credentials refer to.

        Returns ``None`` when session token verification is disabled.
        """
        if not api_settings.VERIFY_SESSION_TOKEN:
            return None

        try:
            session_token = (
                SessionToken.objects.active()
                .select_related("user")
                .get(pk=credentials.get(claims.SESSION_ID), user_id=credentials.get(claims.USER_ID))
            )
        except SessionToken.DoesNotExist:
            raise exceptions.AuthenticationFailed(_("Invalid token."))

        if api_settings.VERIFY_TOKEN_ISSUED_AT and session_token.last_issued_at is not None:
            iat = credentials.get(claims.ISSUED_AT)
            if iat is None or iat < int(session_token.last_issued_at.timestamp()):
                raise exceptions.AuthenticationFailed(_("Token has been superseded."))

        update_fields = ["last_used_at"]
        if request is not None:
            session_token.update_attributes(request=request)
            update_fields += ["ip_address", "user_agent", "version"]
        session_token.last_used_at = timezone.now()
        session_token.save(update_fields=update_fields)
        return session_token

    def get_user(self, credentials, session_token=None):
        """
        Resolve the user for the credentials. Override this to get-or-create users
        from the token claims in services that do not share the user database.
        """
        if session_token is not None:
            return session_token.user

        user_model = get_user_model()
        try:
            return user_model.objects.get(pk=credentials.get(claims.USER_ID))
        except user_model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_("Invalid token."))

    def authenticate_header(self, request):
        return api_settings.AUTHENTICATE_HEADER

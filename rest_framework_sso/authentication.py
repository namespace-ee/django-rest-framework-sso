# coding: utf-8
from __future__ import absolute_import, unicode_literals

import jwt.exceptions
from django.utils.encoding import smart_str
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header

from rest_framework_sso.settings import api_settings

import logging

logger = logging.getLogger(__name__)

decode_jwt_token = api_settings.DECODE_JWT_TOKEN
authenticate_payload = api_settings.AUTHENTICATE_PAYLOAD


class JWTAuthentication(BaseAuthentication):
    """
    JWT token based authentication.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "JWT ".  For example:

        Authorization: JWT eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJsb2NhbG...
    """

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        authenticate_header = self.authenticate_header(request=request)

        if not auth or smart_str(auth[0].lower()) != authenticate_header.lower():
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
            payload = decode_jwt_token(token=token)
        except jwt.exceptions.ExpiredSignature:
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

        return self.authenticate_credentials(payload=payload, request=request)

    def authenticate_credentials(self, payload, request=None):
        user = authenticate_payload(payload=payload, request=request)
        return user, payload

    def authenticate_header(self, request):
        return api_settings.AUTHENTICATE_HEADER

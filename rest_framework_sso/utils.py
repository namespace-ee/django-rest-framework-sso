# coding: utf-8
from __future__ import absolute_import, unicode_literals

from datetime import datetime

import jwt
from django.contrib.auth import get_user_model
from django.core.serializers.json import DjangoJSONEncoder
from django.utils import six
from django.utils.translation import gettext_lazy as _
from jwt.exceptions import MissingRequiredClaimError, InvalidIssuerError
from rest_framework import exceptions

from rest_framework_sso import claims
from rest_framework_sso.settings import api_settings


def create_session_payload(session_token, user, **kwargs):
    return {
        claims.TOKEN: claims.TOKEN_SESSION,
        claims.SESSION_ID: session_token.pk,
        claims.USER_ID: user.pk,
        claims.EMAIL: user.email,
    }


def create_authorization_payload(session_token, user, **kwargs):
    return {
        claims.TOKEN: claims.TOKEN_AUTHORIZATION,
        claims.SESSION_ID: session_token.pk,
        claims.USER_ID: user.pk,
        claims.EMAIL: user.email,
        claims.SCOPES: [],
    }


def encode_jwt_token(payload):
    if payload.get(claims.TOKEN) not in (claims.TOKEN_SESSION, claims.TOKEN_AUTHORIZATION):
        raise RuntimeError('Unknown token type')

    if not payload.get(claims.ISSUER):
        if api_settings.IDENTITY is not None:
            payload[claims.ISSUER] = api_settings.IDENTITY
        else:
            raise RuntimeError('IDENTITY must be specified in settings')

    if not payload.get(claims.AUDIENCE):
        if payload.get(claims.TOKEN) == claims.TOKEN_SESSION and api_settings.SESSION_AUDIENCE is not None:
            payload[claims.AUDIENCE] = api_settings.SESSION_AUDIENCE
        elif payload.get(claims.TOKEN) == claims.TOKEN_AUTHORIZATION and api_settings.AUTHORIZATION_AUDIENCE is not None:
            payload[claims.AUDIENCE] = api_settings.AUTHORIZATION_AUDIENCE
        elif api_settings.IDENTITY is not None:
            payload[claims.AUDIENCE] = [api_settings.IDENTITY]
        else:
            raise RuntimeError('SESSION_AUDIENCE must be specified in settings')

    if not payload.get(claims.EXPIRATION_TIME):
        if payload.get(claims.TOKEN) == claims.TOKEN_SESSION and api_settings.SESSION_EXPIRATION is not None:
            payload[claims.EXPIRATION_TIME] = datetime.utcnow() + api_settings.SESSION_EXPIRATION
        elif payload.get(claims.TOKEN) == claims.TOKEN_AUTHORIZATION and api_settings.AUTHORIZATION_EXPIRATION is not None:
            payload[claims.EXPIRATION_TIME] = datetime.utcnow() + api_settings.AUTHORIZATION_EXPIRATION

    if payload[claims.ISSUER] not in api_settings.PRIVATE_KEYS:
        raise RuntimeError('Private key for specified issuer was not found in settings')

    private_key = open(api_settings.PRIVATE_KEYS.get(payload[claims.ISSUER]), 'rt').read()

    return jwt.encode(
        payload=payload,
        key=private_key,
        algorithm=api_settings.ENCODE_ALGORITHM,
        json_encoder=DjangoJSONEncoder,
    ).decode('utf-8')


def decode_jwt_token(token):
    unverified_claims = jwt.decode(token, verify=False)

    if claims.ISSUER not in unverified_claims:
        raise MissingRequiredClaimError(claims.ISSUER)

    unverified_issuer = six.text_type(unverified_claims[claims.ISSUER])

    if api_settings.ACCEPTED_ISSUERS is not None and unverified_issuer not in api_settings.ACCEPTED_ISSUERS:
        raise InvalidIssuerError('Invalid issuer')
    if unverified_issuer not in api_settings.PUBLIC_KEYS:
        raise InvalidIssuerError('Invalid issuer')

    public_key = open(api_settings.PUBLIC_KEYS.get(unverified_issuer), 'rt').read()

    options = {
        'verify_exp': api_settings.VERIFY_EXPIRATION,
        'verify_aud': True,
        'verify_iss': True,
    }

    return jwt.decode(
        jwt=token,
        key=public_key,
        verify=api_settings.VERIFY_SIGNATURE,
        algorithms=api_settings.DECODE_ALGORITHMS or [api_settings.ENCODE_ALGORITHM],
        options=options,
        leeway=api_settings.EXPIRATION_LEEWAY,
        audience=api_settings.IDENTITY,
        issuer=unverified_issuer,
    )


def authenticate_payload(payload):
    from rest_framework_sso.models import SessionToken

    user_model = get_user_model()

    if api_settings.VERIFY_SESSION_TOKEN:
        try:
            session_token = SessionToken.objects.\
                active().\
                select_related('user').\
                get(pk=payload.get(claims.SESSION_ID), user_id=payload.get(claims.USER_ID))
            user = session_token.user
        except SessionToken.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))
    else:
        try:
            user = user_model.objects.get(pk=payload.get(claims.USER_ID))
        except user_model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))

    if not user.is_active:
        raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

    return user

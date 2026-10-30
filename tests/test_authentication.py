from dataclasses import FrozenInstanceError

import pytest
from rest_framework.exceptions import AuthenticationFailed

from rest_framework_sso import claims
from rest_framework_sso.authentication import JWTAuthentication
from rest_framework_sso.credentials import AuthorizationTokenCredentials, JWTCredentials, SessionTokenCredentials
from rest_framework_sso.models import SessionToken
from rest_framework_sso.settings import api_settings
from rest_framework_sso.utils import encode_jwt_token


def _request_with_token(api_factory, session_token, user):
    payload = {claims.TOKEN: claims.TOKEN_SESSION, claims.SESSION_ID: str(session_token.pk), claims.USER_ID: user.pk}
    token = encode_jwt_token(payload=payload)
    return api_factory.get("/", HTTP_AUTHORIZATION=f"JWT {token}")


def test_credentials_are_frozen_and_keyword_only():
    credentials = JWTCredentials(header={claims.KEY_ID: "k"}, payload={claims.USER_ID: 1})
    assert credentials.payload == {claims.USER_ID: 1}
    assert credentials.header == {claims.KEY_ID: "k"}
    with pytest.raises(FrozenInstanceError):
        credentials.header = {}  # ty: ignore[invalid-assignment]
    with pytest.raises(TypeError):
        JWTCredentials({}, {})  # ty: ignore[missing-argument, too-many-positional-arguments]


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"header": None, "payload": {}}, "header must be a dict, not NoneType"),
        ({"header": {}, "payload": "claims"}, "payload must be a dict, not str"),
    ],
)
def test_credentials_require_dict_header_and_payload(kwargs, message):
    with pytest.raises(TypeError, match=message):
        JWTCredentials(**kwargs)


@pytest.mark.django_db
@pytest.mark.parametrize("credentials_class", [SessionTokenCredentials, AuthorizationTokenCredentials])
@pytest.mark.parametrize("session_token", [None, "00000000-0000-0000-0000-000000000001"])
def test_verified_session_credentials_require_session_token(credentials_class, session_token):
    with pytest.raises(TypeError, match="session_token must be a SessionToken"):
        credentials_class(header={}, payload={}, session_token=session_token)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "credentials_class, overrides, message",
    [
        (SessionTokenCredentials, {claims.TOKEN: claims.TOKEN_AUTHORIZATION}, "requires the 'session' token type"),
        (AuthorizationTokenCredentials, {}, "requires the 'auth' token type"),
        (SessionTokenCredentials, {claims.SESSION_ID: "00000000-0000-0000-0000-000000000000"}, "match the sid claim"),
        (SessionTokenCredentials, {claims.USER_ID: 999}, "match the uid claim"),
    ],
)
def test_verified_session_credentials_must_match_claims(user, credentials_class, overrides, message):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    payload = {claims.TOKEN: claims.TOKEN_SESSION, claims.SESSION_ID: str(session_token.pk), claims.USER_ID: user.pk}
    with pytest.raises(ValueError, match=message):
        credentials_class(header={}, payload={**payload, **overrides}, session_token=session_token)


@pytest.mark.django_db
def test_authenticate_request_end_to_end(user, api_factory):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    request = _request_with_token(api_factory, session_token, user)
    authenticated_user, credentials = JWTAuthentication().authenticate(request)
    assert authenticated_user == user
    assert isinstance(credentials, SessionTokenCredentials)
    assert credentials.session_token == session_token
    assert credentials.header[claims.KEY_ID]
    assert credentials.payload[claims.ISSUER] == api_settings.IDENTITY
    assert credentials.payload.get(claims.SESSION_ID) == str(session_token.pk)


@pytest.mark.django_db
def test_authenticate_validates_payload(user, api_factory):
    token = encode_jwt_token(payload={claims.TOKEN: claims.TOKEN_SESSION, claims.USER_ID: user.pk})
    request = api_factory.get("/", HTTP_AUTHORIZATION=f"JWT {token}")
    with pytest.raises(AuthenticationFailed, match="Session ID is missing."):
        JWTAuthentication().authenticate(request)

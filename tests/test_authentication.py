from dataclasses import FrozenInstanceError

import jwt
import pytest
from rest_framework.exceptions import AuthenticationFailed

from rest_framework_sso import authentication, claims
from rest_framework_sso.authentication import JWTAuthentication
from rest_framework_sso.credentials import JWTCredentials
from rest_framework_sso.keys import get_private_key_and_key_id
from rest_framework_sso.models import SessionToken
from rest_framework_sso.settings import api_settings
from rest_framework_sso.utils import encode_jwt_token


def _request_with_token(api_factory, session_token, user):
    payload = {claims.TOKEN: claims.TOKEN_SESSION, claims.SESSION_ID: str(session_token.pk), claims.USER_ID: user.pk}
    token = encode_jwt_token(payload=payload)
    return api_factory.get("/", HTTP_AUTHORIZATION=f"JWT {token}")


def test_credentials_is_read_only_mapping_over_payload():
    credentials = JWTCredentials(header={claims.KEY_ID: "k"}, payload={claims.USER_ID: 1})
    assert credentials.get(claims.USER_ID) == 1
    assert credentials[claims.USER_ID] == 1
    assert credentials.get(claims.SESSION_ID) is None
    assert claims.USER_ID in credentials
    assert dict(credentials) == {claims.USER_ID: 1}
    assert credentials.header == {claims.KEY_ID: "k"}
    assert credentials.session_token is None
    with pytest.raises(FrozenInstanceError):
        credentials.session_token = object()


@pytest.mark.django_db
def test_authenticate_request_end_to_end(user, api_factory):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    request = _request_with_token(api_factory, session_token, user)
    authenticated_user, credentials = JWTAuthentication().authenticate(request)
    assert authenticated_user == user
    assert isinstance(credentials, JWTCredentials)
    assert credentials.session_token == session_token
    assert credentials.header[claims.KEY_ID]
    assert credentials.payload[claims.ISSUER] == api_settings.IDENTITY
    assert credentials.get(claims.SESSION_ID) == str(session_token.pk)


@pytest.mark.django_db
def test_legacy_authenticate_payload_returning_only_user(user, api_factory, monkeypatch):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    monkeypatch.setattr(authentication, "authenticate_payload", lambda payload, request=None: user)
    request = _request_with_token(api_factory, session_token, user)
    authenticated_user, credentials = JWTAuthentication().authenticate(request)
    assert authenticated_user == user
    assert isinstance(credentials, JWTCredentials)
    assert credentials.session_token is None
    assert credentials.header[claims.KEY_ID]
    assert credentials.get(claims.SESSION_ID) == str(session_token.pk)


@pytest.mark.django_db
def test_legacy_decode_jwt_token_returning_dict(user, api_factory, monkeypatch):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    original_decode = authentication.decode_jwt_token
    monkeypatch.setattr(authentication, "decode_jwt_token", lambda token: dict(original_decode(token=token)))
    request = _request_with_token(api_factory, session_token, user)
    authenticated_user, credentials = JWTAuthentication().authenticate(request)
    assert authenticated_user == user
    assert isinstance(credentials, JWTCredentials)
    assert credentials.session_token == session_token
    assert credentials.header == {}
    assert credentials.get(claims.SESSION_ID) == str(session_token.pk)


def _request_with_raw_payload(api_factory, payload):
    # Signs with a trusted key but skips encode_jwt_token, which refuses unknown token types.
    private_key, key_id = get_private_key_and_key_id(issuer=api_settings.IDENTITY)
    payload = {claims.ISSUER: api_settings.IDENTITY, claims.AUDIENCE: [api_settings.IDENTITY], **payload}
    token = jwt.encode(payload, private_key, algorithm=api_settings.ENCODE_ALGORITHM, headers={claims.KEY_ID: key_id})
    return api_factory.get("/", HTTP_AUTHORIZATION=f"JWT {token}")


def _invalid_payloads(session_token, user):
    valid = {claims.TOKEN: claims.TOKEN_SESSION, claims.SESSION_ID: str(session_token.pk), claims.USER_ID: user.pk}
    return [
        ({**valid, claims.TOKEN: "bogus"}, "Unknown token type."),
        ({k: v for k, v in valid.items() if k != claims.TOKEN}, "Unknown token type."),
        ({k: v for k, v in valid.items() if k != claims.SESSION_ID}, "Session ID is missing."),
        ({k: v for k, v in valid.items() if k != claims.USER_ID}, "User ID is missing."),
    ]


@pytest.mark.django_db
def test_rejects_invalid_claims(user, api_factory):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    for payload, message in _invalid_payloads(session_token, user):
        with pytest.raises(AuthenticationFailed, match=message):
            JWTAuthentication().authenticate(_request_with_raw_payload(api_factory, payload))


@pytest.mark.django_db
def test_custom_authenticate_payload_keeps_claim_validation(user, api_factory, monkeypatch):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    monkeypatch.setattr(authentication, "authenticate_payload", lambda payload, request=None: (user, payload))
    for payload, message in _invalid_payloads(session_token, user):
        with pytest.raises(AuthenticationFailed, match=message):
            JWTAuthentication().authenticate(_request_with_raw_payload(api_factory, payload))


@pytest.mark.django_db
def test_custom_decode_jwt_token_keeps_claim_validation(user, api_factory, monkeypatch):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    original_decode = authentication.decode_jwt_token
    monkeypatch.setattr(authentication, "decode_jwt_token", lambda token: dict(original_decode(token=token)))
    for payload, message in _invalid_payloads(session_token, user):
        with pytest.raises(AuthenticationFailed, match=message):
            JWTAuthentication().authenticate(_request_with_raw_payload(api_factory, payload))


@pytest.mark.django_db
def test_custom_validate_payload_replaces_default(user, api_factory, monkeypatch):
    payload = {claims.TOKEN: "service", claims.USER_ID: user.pk}
    monkeypatch.setattr(authentication, "validate_payload", lambda payload: None)
    monkeypatch.setattr(authentication, "authenticate_payload", lambda payload, request=None: (user, payload))
    authenticated_user, credentials = JWTAuthentication().authenticate(_request_with_raw_payload(api_factory, payload))
    assert authenticated_user == user
    assert credentials.get(claims.TOKEN) == "service"

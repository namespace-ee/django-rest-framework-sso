from datetime import datetime, timedelta, timezone

import pytest
import time_machine
from rest_framework.exceptions import AuthenticationFailed

from rest_framework_sso import claims
from rest_framework_sso.credentials import JWTCredentials
from rest_framework_sso.models import SessionToken
from rest_framework_sso.settings import api_settings
from rest_framework_sso.utils import authenticate_payload, decode_jwt_token, encode_jwt_token


def _base_payload(token_type=claims.TOKEN_SESSION):
    return {
        claims.TOKEN: token_type,
        claims.SESSION_ID: "00000000-0000-0000-0000-000000000001",
        claims.USER_ID: 1,
    }


def test_caller_supplied_iat_preserved():
    iat = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    payload = _base_payload()
    payload[claims.ISSUED_AT] = iat
    encode_jwt_token(payload=payload)
    assert payload[claims.ISSUED_AT] == iat


def test_fallback_iat_truncated_to_whole_seconds():
    fixed = datetime(2026, 5, 13, 10, 30, 45, 123456, tzinfo=timezone.utc)
    payload = _base_payload()
    with time_machine.travel(fixed, tick=False):
        encode_jwt_token(payload=payload)
    assert payload[claims.ISSUED_AT] == fixed.replace(microsecond=0)
    assert payload[claims.ISSUED_AT].microsecond == 0


def test_session_exp_derived_from_iat():
    payload = _base_payload(claims.TOKEN_SESSION)
    encode_jwt_token(payload=payload)
    assert payload[claims.EXPIRATION_TIME] - payload[claims.ISSUED_AT] == api_settings.SESSION_EXPIRATION


def test_authorization_exp_derived_from_iat():
    payload = _base_payload(claims.TOKEN_AUTHORIZATION)
    encode_jwt_token(payload=payload)
    assert payload[claims.EXPIRATION_TIME] - payload[claims.ISSUED_AT] == api_settings.AUTHORIZATION_EXPIRATION


def test_caller_supplied_iat_drives_exp():
    caller_iat = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    fallback_now = datetime(2030, 6, 15, 9, 0, 0, tzinfo=timezone.utc)
    payload = _base_payload(claims.TOKEN_SESSION)
    payload[claims.ISSUED_AT] = caller_iat
    with time_machine.travel(fallback_now, tick=False):
        encode_jwt_token(payload=payload)
    assert payload[claims.EXPIRATION_TIME] == caller_iat + api_settings.SESSION_EXPIRATION


def test_caller_supplied_exp_preserved():
    caller_exp = datetime(2027, 3, 14, 0, 0, 0, tzinfo=timezone.utc)
    payload = _base_payload(claims.TOKEN_SESSION)
    payload[claims.EXPIRATION_TIME] = caller_exp
    payload[claims.ISSUED_AT] = caller_exp - timedelta(days=365)
    encode_jwt_token(payload=payload)
    assert payload[claims.EXPIRATION_TIME] == caller_exp


def _auth_payload(session_token, user, iat=None):
    payload = {
        claims.TOKEN: claims.TOKEN_SESSION,
        claims.SESSION_ID: session_token.pk,
        claims.USER_ID: user.pk,
    }
    if iat is not None:
        payload[claims.ISSUED_AT] = iat
    return JWTCredentials(header={}, payload=payload)


@pytest.mark.django_db
def test_authenticate_rejects_iat_before_last_issued_at(user):
    last = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=last)
    payload = _auth_payload(session_token, user, iat=int(last.timestamp()) - 1)
    with pytest.raises(AuthenticationFailed):
        authenticate_payload(payload=payload)


@pytest.mark.django_db
def test_authenticate_accepts_iat_equal_last_issued_at(user):
    last = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=last)
    payload = _auth_payload(session_token, user, iat=int(last.timestamp()))
    authenticated_user, credentials = authenticate_payload(payload=payload)
    assert authenticated_user == user


@pytest.mark.django_db
def test_authenticate_accepts_iat_after_last_issued_at(user):
    last = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=last)
    payload = _auth_payload(session_token, user, iat=int(last.timestamp()) + 1)
    authenticated_user, credentials = authenticate_payload(payload=payload)
    assert authenticated_user == user


@pytest.mark.django_db
def test_authenticate_skips_check_when_last_issued_at_is_none(user):
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=None)
    payload = _auth_payload(session_token, user, iat=None)
    authenticated_user, credentials = authenticate_payload(payload=payload)
    assert authenticated_user == user


@pytest.mark.django_db
def test_authenticate_rejects_payload_missing_iat(user):
    last = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=last)
    payload = _auth_payload(session_token, user, iat=None)
    with pytest.raises(AuthenticationFailed):
        authenticate_payload(payload=payload)


@pytest.mark.django_db
def test_authenticate_does_not_unrevoke_concurrently_revoked_token(user, monkeypatch):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    revoked_at = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    original_save = SessionToken.save

    def save_after_concurrent_revocation(self, *args, **kwargs):
        SessionToken.objects.filter(pk=self.pk).update(revoked_at=revoked_at)
        return original_save(self, *args, **kwargs)

    monkeypatch.setattr(SessionToken, "save", save_after_concurrent_revocation)
    authenticated_user, credentials = authenticate_payload(payload=_auth_payload(session_token, user))
    assert authenticated_user == user
    session_token.refresh_from_db()
    assert session_token.revoked_at == revoked_at


@pytest.mark.django_db
def test_authenticate_persists_request_attributes_and_last_used_at(user, api_factory):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    request = api_factory.get("/", HTTP_USER_AGENT="test-agent", REMOTE_ADDR="10.1.2.3")
    authenticated_user, credentials = authenticate_payload(payload=_auth_payload(session_token, user), request=request)
    assert authenticated_user == user
    session_token.refresh_from_db()
    assert session_token.ip_address == "10.1.2.3"
    assert session_token.user_agent == "test-agent"
    assert session_token.last_used_at is not None


@pytest.mark.django_db
def test_authenticate_skips_check_when_verify_disabled(user, monkeypatch):
    monkeypatch.setattr(api_settings, "VERIFY_TOKEN_ISSUED_AT", False)
    last = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=last)
    payload = _auth_payload(session_token, user, iat=int(last.timestamp()) - 100)
    authenticated_user, credentials = authenticate_payload(payload=payload)
    assert authenticated_user == user


@pytest.mark.django_db
def test_authenticate_attaches_session_token_to_credentials(user):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    credentials = _auth_payload(session_token, user)
    authenticated_user, returned = authenticate_payload(payload=credentials)
    assert authenticated_user == user
    assert isinstance(returned, JWTCredentials)
    assert returned.session_token == session_token
    assert returned.header == credentials.header
    assert returned.payload == credentials.payload


@pytest.mark.django_db
def test_authenticate_without_session_verification_leaves_session_token_empty(user, monkeypatch):
    monkeypatch.setattr(api_settings, "VERIFY_SESSION_TOKEN", False)
    session_token = SessionToken.objects.create(user=user, created_by=user)
    authenticated_user, returned = authenticate_payload(payload=_auth_payload(session_token, user))
    assert authenticated_user == user
    assert returned.session_token is None


def test_decode_returns_credentials_with_header_and_payload():
    payload = _base_payload()
    credentials = decode_jwt_token(encode_jwt_token(payload=payload))
    assert isinstance(credentials, JWTCredentials)
    assert credentials.header[claims.ALGORITHM] == api_settings.ENCODE_ALGORITHM
    assert credentials.header[claims.KEY_ID]
    assert credentials.payload[claims.SESSION_ID] == payload[claims.SESSION_ID]
    assert credentials.session_token is None

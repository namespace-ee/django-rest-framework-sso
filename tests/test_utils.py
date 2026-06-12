from datetime import datetime, timedelta, timezone

import pytest
import time_machine
from rest_framework.exceptions import AuthenticationFailed

from rest_framework_sso import claims
from rest_framework_sso.models import SessionToken
from rest_framework_sso.settings import api_settings
from rest_framework_sso.utils import authenticate_payload, encode_jwt_token


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
    return payload


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
    assert authenticate_payload(payload=payload) == user


@pytest.mark.django_db
def test_authenticate_accepts_iat_after_last_issued_at(user):
    last = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=last)
    payload = _auth_payload(session_token, user, iat=int(last.timestamp()) + 1)
    assert authenticate_payload(payload=payload) == user


@pytest.mark.django_db
def test_authenticate_skips_check_when_last_issued_at_is_none(user):
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=None)
    payload = _auth_payload(session_token, user, iat=None)
    assert authenticate_payload(payload=payload) == user


@pytest.mark.django_db
def test_authenticate_rejects_payload_missing_iat(user):
    last = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=last)
    payload = _auth_payload(session_token, user, iat=None)
    with pytest.raises(AuthenticationFailed):
        authenticate_payload(payload=payload)


@pytest.mark.django_db
def test_authenticate_skips_check_when_verify_disabled(user, monkeypatch):
    monkeypatch.setattr(api_settings, "VERIFY_TOKEN_ISSUED_AT", False)
    last = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=last)
    payload = _auth_payload(session_token, user, iat=int(last.timestamp()) - 100)
    assert authenticate_payload(payload=payload) == user

from datetime import UTC, datetime, timedelta

import time_machine

from rest_framework_sso import claims
from rest_framework_sso.settings import api_settings
from rest_framework_sso.utils import encode_jwt_token


def _base_payload(token_type=claims.TOKEN_SESSION):
    return {
        claims.TOKEN: token_type,
        claims.SESSION_ID: "00000000-0000-0000-0000-000000000001",
        claims.USER_ID: 1,
    }


def test_caller_supplied_iat_preserved():
    iat = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    payload = _base_payload()
    payload[claims.ISSUED_AT] = iat
    encode_jwt_token(payload=payload)
    assert payload[claims.ISSUED_AT] == iat


def test_fallback_iat_truncated_to_whole_seconds():
    fixed = datetime(2026, 5, 13, 10, 30, 45, 123456, tzinfo=UTC)
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
    caller_iat = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    fallback_now = datetime(2030, 6, 15, 9, 0, 0, tzinfo=UTC)
    payload = _base_payload(claims.TOKEN_SESSION)
    payload[claims.ISSUED_AT] = caller_iat
    with time_machine.travel(fallback_now, tick=False):
        encode_jwt_token(payload=payload)
    assert payload[claims.EXPIRATION_TIME] == caller_iat + api_settings.SESSION_EXPIRATION


def test_caller_supplied_exp_preserved():
    caller_exp = datetime(2027, 3, 14, 0, 0, 0, tzinfo=UTC)
    payload = _base_payload(claims.TOKEN_SESSION)
    payload[claims.EXPIRATION_TIME] = caller_exp
    payload[claims.ISSUED_AT] = caller_exp - timedelta(days=365)
    encode_jwt_token(payload=payload)
    assert payload[claims.EXPIRATION_TIME] == caller_exp

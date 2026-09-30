from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import force_authenticate

from rest_framework_sso import claims
from rest_framework_sso.authentication import JWTAuthentication
from rest_framework_sso.credentials import JWTCredentials
from rest_framework_sso.models import SessionToken
from rest_framework_sso.settings import api_settings
from rest_framework_sso.utils import encode_jwt_token
from rest_framework_sso.views import ObtainAuthorizationTokenView


def _credentials(session_token, user, iat=None):
    payload = {
        claims.TOKEN: claims.TOKEN_SESSION,
        claims.SESSION_ID: session_token.pk,
        claims.USER_ID: user.pk,
    }
    if iat is not None:
        payload[claims.ISSUED_AT] = iat
    return JWTCredentials(payload=payload)


def _authenticate(session_token, user, iat=None, request=None):
    return JWTAuthentication().authenticate_credentials(
        credentials=_credentials(session_token, user, iat=iat), request=request
    )


def test_credentials_is_read_only_mapping_over_payload():
    credentials = JWTCredentials(payload={claims.USER_ID: 1}, header={claims.KEY_ID: "k"})
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
def test_authenticate_attaches_session_token_to_credentials(user):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    authenticated_user, credentials = _authenticate(session_token, user)
    assert authenticated_user == user
    assert isinstance(credentials, JWTCredentials)
    assert credentials.session_token == session_token
    assert credentials.session_token.user == user
    assert credentials.payload[claims.SESSION_ID] == session_token.pk


@pytest.mark.django_db
def test_authenticate_request_end_to_end(user, api_factory):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    payload = {claims.TOKEN: claims.TOKEN_SESSION, claims.SESSION_ID: str(session_token.pk), claims.USER_ID: user.pk}
    token = encode_jwt_token(payload=payload)
    request = api_factory.get("/", HTTP_AUTHORIZATION=f"JWT {token}")
    authenticated_user, credentials = JWTAuthentication().authenticate(request)
    assert authenticated_user == user
    assert credentials.session_token == session_token
    assert credentials.header[claims.KEY_ID]
    assert credentials.payload[claims.ISSUER] == api_settings.IDENTITY
    assert credentials.get(claims.SESSION_ID) == str(session_token.pk)


@pytest.mark.django_db
def test_authenticate_without_session_verification_leaves_session_token_empty(user, monkeypatch):
    monkeypatch.setattr(api_settings, "VERIFY_SESSION_TOKEN", False)
    session_token = SessionToken.objects.create(user=user, created_by=user)
    authenticated_user, credentials = _authenticate(session_token, user)
    assert authenticated_user == user
    assert credentials.session_token is None


@pytest.mark.django_db
def test_authenticate_rejects_inactive_user(user):
    user.is_active = False
    user.save()
    session_token = SessionToken.objects.create(user=user, created_by=user)
    with pytest.raises(AuthenticationFailed):
        _authenticate(session_token, user)


@pytest.mark.django_db
def test_authenticate_rejects_revoked_session_token(user):
    session_token = SessionToken.objects.create(user=user, created_by=user, revoked_at=datetime.now(tz=timezone.utc))
    with pytest.raises(AuthenticationFailed):
        _authenticate(session_token, user)


@pytest.mark.django_db
def test_get_user_override_receives_credentials_and_session_token(user):
    seen = {}

    class CustomAuthentication(JWTAuthentication):
        def get_user(self, credentials, session_token=None):
            seen["credentials"] = credentials
            seen["session_token"] = session_token
            return user

    session_token = SessionToken.objects.create(user=user, created_by=user)
    credentials = _credentials(session_token, user)
    authenticated_user, returned = CustomAuthentication().authenticate_credentials(credentials=credentials)
    assert authenticated_user == user
    assert seen["credentials"] is credentials
    assert seen["session_token"] == session_token
    assert returned.session_token == session_token


@pytest.mark.django_db
def test_authenticate_rejects_iat_before_last_issued_at(user):
    last = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=last)
    with pytest.raises(AuthenticationFailed):
        _authenticate(session_token, user, iat=int(last.timestamp()) - 1)


@pytest.mark.django_db
def test_authenticate_accepts_iat_equal_last_issued_at(user):
    last = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=last)
    assert _authenticate(session_token, user, iat=int(last.timestamp()))[0] == user


@pytest.mark.django_db
def test_authenticate_accepts_iat_after_last_issued_at(user):
    last = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=last)
    assert _authenticate(session_token, user, iat=int(last.timestamp()) + 1)[0] == user


@pytest.mark.django_db
def test_authenticate_skips_check_when_last_issued_at_is_none(user):
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=None)
    assert _authenticate(session_token, user, iat=None)[0] == user


@pytest.mark.django_db
def test_authenticate_rejects_payload_missing_iat(user):
    last = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=last)
    with pytest.raises(AuthenticationFailed):
        _authenticate(session_token, user, iat=None)


@pytest.mark.django_db
def test_authenticate_does_not_unrevoke_concurrently_revoked_token(user, monkeypatch):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    revoked_at = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    original_save = SessionToken.save

    def save_after_concurrent_revocation(self, *args, **kwargs):
        SessionToken.objects.filter(pk=self.pk).update(revoked_at=revoked_at)
        return original_save(self, *args, **kwargs)

    monkeypatch.setattr(SessionToken, "save", save_after_concurrent_revocation)
    assert _authenticate(session_token, user)[0] == user
    session_token.refresh_from_db()
    assert session_token.revoked_at == revoked_at


@pytest.mark.django_db
def test_authenticate_persists_request_attributes_and_last_used_at(user, api_factory):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    request = api_factory.get("/", HTTP_USER_AGENT="test-agent", REMOTE_ADDR="10.1.2.3")
    _, credentials = _authenticate(session_token, user, request=request)
    session_token.refresh_from_db()
    assert session_token.ip_address == "10.1.2.3"
    assert session_token.user_agent == "test-agent"
    assert session_token.last_used_at is not None
    assert credentials.session_token.last_used_at == session_token.last_used_at


@pytest.mark.django_db
def test_authenticate_skips_check_when_verify_disabled(user, monkeypatch):
    monkeypatch.setattr(api_settings, "VERIFY_TOKEN_ISSUED_AT", False)
    last = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(user=user, created_by=user, last_issued_at=last)
    assert _authenticate(session_token, user, iat=int(last.timestamp()) - 100)[0] == user


@pytest.mark.django_db
def test_authorization_view_reuses_attached_session_token(user, api_factory, django_assert_num_queries):
    session_token = SessionToken.objects.create(user=user, client_id="web", created_by=user)
    credentials = JWTCredentials(payload={claims.SESSION_ID: str(session_token.pk)}, session_token=session_token)
    request = api_factory.post("/authorize/", data={}, format="json")
    force_authenticate(request, user=user, token=credentials)
    # Only the attribute update on the attached token, no session token lookup.
    with django_assert_num_queries(1):
        response = ObtainAuthorizationTokenView.as_view()(request)
    assert response.status_code == 200


def test_removed_authenticate_payload_setting_is_rejected():
    with pytest.raises(ImproperlyConfigured, match="AUTHENTICATE_PAYLOAD"):
        with override_settings(REST_FRAMEWORK_SSO={"AUTHENTICATE_PAYLOAD": "myapp.authenticate_payload"}):
            pass

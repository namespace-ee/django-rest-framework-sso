import json
from datetime import datetime, timezone

import pytest
import time_machine
from rest_framework.test import force_authenticate

from rest_framework_sso import claims
from rest_framework_sso.models import SessionToken
from rest_framework_sso.utils import decode_jwt_token
from rest_framework_sso.views import ObtainAuthorizationTokenView, ObtainSessionTokenView


def _post_session(api_factory, data):
    request = api_factory.post("/authenticate/", data=data, format="json")
    return ObtainSessionTokenView.as_view()(request)


def _decode(response):
    body = json.loads(response.rendered_content)
    return decode_jwt_token(body["token"])


@pytest.mark.django_db
def test_session_post_creates_token_with_last_issued_at(user, api_factory):
    response = _post_session(api_factory, {"username": "alice", "password": "pw", "client_id": "web"})
    assert response.status_code == 200
    session_token = SessionToken.objects.get(user=user, client_id="web")
    assert session_token.last_issued_at is not None
    assert session_token.last_issued_at.microsecond == 0


@pytest.mark.django_db
def test_session_post_iat_matches_last_issued_at(user, api_factory):
    fixed = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    with time_machine.travel(fixed, tick=False):
        response = _post_session(api_factory, {"username": "alice", "password": "pw", "client_id": "web"})
        decoded = _decode(response)
    session_token = SessionToken.objects.get(user=user, client_id="web")
    assert decoded[claims.ISSUED_AT] == int(session_token.last_issued_at.timestamp())
    assert decoded[claims.ISSUED_AT] == int(fixed.timestamp())


@pytest.mark.django_db
def test_session_post_reuse_advances_last_issued_at(user, api_factory):
    t1 = datetime(2026, 5, 13, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 5, 13, 10, 0, 5, tzinfo=timezone.utc)
    with time_machine.travel(t1, tick=False):
        _post_session(api_factory, {"username": "alice", "password": "pw", "client_id": "web"})
    first = SessionToken.objects.get(user=user, client_id="web")
    first_pk, first_created = first.pk, first.created_at
    assert first.last_issued_at == t1

    with time_machine.travel(t2, tick=False):
        _post_session(api_factory, {"username": "alice", "password": "pw", "client_id": "web"})
    second = SessionToken.objects.get(user=user, client_id="web")
    assert second.pk == first_pk
    assert second.created_at == first_created
    assert second.last_issued_at == t2


def _save_with_concurrent_revocation(revoked_at):
    original_save = SessionToken.save

    def save(self, *args, **kwargs):
        SessionToken.objects.filter(pk=self.pk).update(revoked_at=revoked_at)
        return original_save(self, *args, **kwargs)

    return save


@pytest.mark.django_db
def test_session_post_does_not_unrevoke_concurrently_revoked_token(user, api_factory, monkeypatch):
    session_token = SessionToken.objects.create(user=user, client_id="web", created_by=user)
    revoked_at = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(SessionToken, "save", _save_with_concurrent_revocation(revoked_at))
    response = _post_session(api_factory, {"username": "alice", "password": "pw", "client_id": "web"})
    assert response.status_code == 200
    session_token.refresh_from_db()
    assert session_token.revoked_at == revoked_at


@pytest.mark.django_db
def test_authorization_post_does_not_unrevoke_concurrently_revoked_token(user, api_factory, monkeypatch):
    session_token = SessionToken.objects.create(user=user, client_id="web", created_by=user)
    revoked_at = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(SessionToken, "save", _save_with_concurrent_revocation(revoked_at))
    request = api_factory.post("/authorize/", data={}, format="json")
    force_authenticate(request, user=user, token={claims.SESSION_ID: str(session_token.pk)})
    response = ObtainAuthorizationTokenView.as_view()(request)
    assert response.status_code == 200
    session_token.refresh_from_db()
    assert session_token.revoked_at == revoked_at


@pytest.mark.django_db
def test_authorization_post_does_not_touch_last_issued_at(user, api_factory):
    original_last_issued_at = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    session_token = SessionToken.objects.create(
        user=user, client_id="web", created_by=user, last_issued_at=original_last_issued_at
    )
    request = api_factory.post("/authorize/", data={}, format="json")
    force_authenticate(request, user=user, token={claims.SESSION_ID: str(session_token.pk)})
    response = ObtainAuthorizationTokenView.as_view()(request)
    assert response.status_code == 200
    session_token.refresh_from_db()
    assert session_token.last_issued_at == original_last_issued_at

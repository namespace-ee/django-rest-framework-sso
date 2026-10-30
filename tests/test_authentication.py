from dataclasses import FrozenInstanceError

import pytest
from rest_framework.exceptions import AuthenticationFailed

from rest_framework_sso import claims
from rest_framework_sso.authentication import JWTAuthentication
from rest_framework_sso.credentials import JWTCredentials, SessionTokenCredentials
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
    with pytest.raises(FrozenInstanceError):
        credentials.header = {}
    with pytest.raises(TypeError):
        JWTCredentials({}, {})


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
    assert credentials.get(claims.SESSION_ID) == str(session_token.pk)


@pytest.mark.django_db
def test_authenticate_validates_payload(user, api_factory):
    token = encode_jwt_token(payload={claims.TOKEN: claims.TOKEN_SESSION, claims.USER_ID: user.pk})
    request = api_factory.get("/", HTTP_AUTHORIZATION=f"JWT {token}")
    with pytest.raises(AuthenticationFailed, match="Session ID is missing."):
        JWTAuthentication().authenticate(request)

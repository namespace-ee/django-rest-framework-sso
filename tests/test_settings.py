import pytest
from django.test import override_settings
from rest_framework.exceptions import AuthenticationFailed

from rest_framework_sso import claims, utils
from rest_framework_sso.authentication import JWTAuthentication
from rest_framework_sso.models import SessionToken
from rest_framework_sso.settings import api_settings


def reject_payload(*, credentials):
    raise AuthenticationFailed("Rejected by the overridden hook.")


def test_override_is_seen_by_modules_that_imported_api_settings(settings):
    settings.REST_FRAMEWORK_SSO = {**settings.REST_FRAMEWORK_SSO, "IDENTITY": "overridden-issuer"}
    assert utils.api_settings.IDENTITY == "overridden-issuer"


def test_override_is_reverted_after_the_override_ends(settings):
    with override_settings(REST_FRAMEWORK_SSO={**settings.REST_FRAMEWORK_SSO, "IDENTITY": "overridden-issuer"}):
        assert api_settings.IDENTITY == "overridden-issuer"
    assert api_settings.IDENTITY == "test-issuer"


@pytest.mark.django_db
def test_overridden_hook_is_called_by_jwt_authentication(settings, user, api_factory):
    session_token = SessionToken.objects.create(user=user, created_by=user)
    token = utils.encode_jwt_token(
        payload={claims.TOKEN: claims.TOKEN_SESSION, claims.SESSION_ID: str(session_token.pk), claims.USER_ID: user.pk}
    )
    request = api_factory.get("/", HTTP_AUTHORIZATION=f"JWT {token}")
    settings.REST_FRAMEWORK_SSO = {
        **settings.REST_FRAMEWORK_SSO,
        "VALIDATE_PAYLOAD": "tests.test_settings.reject_payload",
    }
    with pytest.raises(AuthenticationFailed, match="Rejected by the overridden hook."):
        JWTAuthentication().authenticate(request)

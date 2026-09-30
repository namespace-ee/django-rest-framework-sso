import datetime

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.test.signals import setting_changed
from rest_framework.settings import APISettings

USER_SETTINGS = getattr(settings, "REST_FRAMEWORK_SSO", None)

DEFAULTS = {
    "CREATE_SESSION_PAYLOAD": "rest_framework_sso.utils.create_session_payload",
    "CREATE_AUTHORIZATION_PAYLOAD": "rest_framework_sso.utils.create_authorization_payload",
    "ENCODE_JWT_TOKEN": "rest_framework_sso.utils.encode_jwt_token",
    "DECODE_JWT_TOKEN": "rest_framework_sso.utils.decode_jwt_token",
    "ENCODE_ALGORITHM": "RS256",
    "DECODE_ALGORITHMS": None,
    "VERIFY_SIGNATURE": True,
    "VERIFY_EXPIRATION": True,
    "VERIFY_ISSUER": True,
    "VERIFY_AUDIENCE": True,
    "VERIFY_SESSION_TOKEN": True,
    "VERIFY_TOKEN_ISSUED_AT": True,
    "EXPIRATION_LEEWAY": 0,
    "SESSION_EXPIRATION": None,
    "AUTHORIZATION_EXPIRATION": datetime.timedelta(seconds=300),
    "IDENTITY": None,
    "SESSION_AUDIENCE": None,
    "AUTHORIZATION_AUDIENCE": None,
    "ACCEPTED_ISSUERS": None,
    "KEY_STORE_ROOT": None,
    "PUBLIC_KEYS": {},
    "PRIVATE_KEYS": {},
    "AUTHENTICATE_HEADER": "JWT",
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    "CREATE_SESSION_PAYLOAD",
    "CREATE_AUTHORIZATION_PAYLOAD",
    "ENCODE_JWT_TOKEN",
    "DECODE_JWT_TOKEN",
)

# Settings that have been removed, mapped to the replacement users should migrate to.
REMOVED_SETTINGS = {
    "AUTHENTICATE_PAYLOAD": (
        "subclass rest_framework_sso.authentication.JWTAuthentication and override "
        "get_session_token(), get_user() or authenticate_credentials()"
    ),
}


def check_removed_settings(user_settings):
    for name, replacement in REMOVED_SETTINGS.items():
        if user_settings and name in user_settings:
            raise ImproperlyConfigured(f"The REST_FRAMEWORK_SSO setting '{name}' has been removed; {replacement}.")


check_removed_settings(USER_SETTINGS)

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)


def reload_api_settings(*args, **kwargs):
    global api_settings
    setting, value = kwargs["setting"], kwargs["value"]
    if setting == "REST_FRAMEWORK_SSO":
        check_removed_settings(value)
        api_settings = APISettings(value, DEFAULTS, IMPORT_STRINGS)


setting_changed.connect(reload_api_settings)

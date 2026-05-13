import datetime
import os

DEBUG_PROPAGATE_EXCEPTIONS = True
SECRET_KEY = "drf-sso"
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework_sso",
]
REST_FRAMEWORK_SSO = {
    "KEY_STORE_ROOT": os.path.join(os.path.dirname(__file__), "keys"),
    "PRIVATE_KEYS": {"test-issuer": ["test-2048.pem", "test-1024.pem"]},
    "PUBLIC_KEYS": {"test-issuer": ["test-2048.pem", "test-1024.pem"]},
    "IDENTITY": "test-issuer",
    "SESSION_EXPIRATION": datetime.timedelta(seconds=3600),
}

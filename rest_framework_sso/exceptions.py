from django.core.exceptions import ImproperlyConfigured


class KeyLoadError(ImproperlyConfigured):
    """A configured key file could not be loaded.

    Deliberately not an InvalidKeyError: that one means the token names an unknown issuer or key id (HTTP 401),
    while this one is a server misconfiguration and must surface as HTTP 500.
    """

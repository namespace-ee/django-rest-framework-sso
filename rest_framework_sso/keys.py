import functools
import logging
import os

import pem
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from django.core.exceptions import ImproperlyConfigured
from jwt.exceptions import InvalidKeyError

from rest_framework_sso.settings import api_settings

logger = logging.getLogger(__name__)


class KeyLoadError(ImproperlyConfigured):
    """A configured key file could not be loaded.

    Deliberately not an InvalidKeyError: that one means the token names an unknown issuer or key id (HTTP 401),
    while this one is a server misconfiguration and must surface as HTTP 500.
    """


def read_key_file(file_name):
    if api_settings.KEY_STORE_ROOT:
        file_path = os.path.abspath(os.path.join(api_settings.KEY_STORE_ROOT, file_name))
    else:
        file_path = os.path.abspath(file_name)
    return pem.parse_file(file_path)


@functools.cache
def load_private_key(file_name):
    key_data = next((o.as_bytes() for o in read_key_file(file_name=file_name) if isinstance(o, pem.PrivateKey)), None)
    if key_data is None:
        raise KeyLoadError(f"No private key found in key file {file_name!r}")
    return load_pem_private_key(key_data, password=None)


@functools.cache
def load_public_key(file_name):
    key_data = next((o.as_bytes() for o in read_key_file(file_name=file_name) if isinstance(o, pem.PublicKey)), None)
    if key_data is None:
        raise KeyLoadError(f"No public key found in key file {file_name!r}")
    return load_pem_public_key(key_data)


def get_key_id(file_name):
    suffixes = [".pem"]
    for suffix in suffixes:
        if file_name.lower().endswith(suffix):
            return file_name[: -len(suffix)]
    return file_name


def get_key_file_name(keys, issuer, key_id=None):
    if not keys.get(issuer):
        raise InvalidKeyError("No keys defined for the given issuer")
    issuer_keys = keys.get(issuer)
    if isinstance(issuer_keys, str):
        issuer_keys = [issuer_keys]
    if key_id:
        issuer_keys = [ik for ik in issuer_keys if key_id in (ik, get_key_id(ik))]
    if len(issuer_keys) < 1:
        raise InvalidKeyError("No key matches the given key_id")
    return issuer_keys[0]


def get_private_key_and_key_id(issuer, key_id=None):
    file_name = get_key_file_name(keys=api_settings.PRIVATE_KEYS, issuer=issuer, key_id=key_id)
    return load_private_key(file_name=file_name), get_key_id(file_name=file_name)


def get_public_key_and_key_id(issuer, key_id=None):
    file_name = get_key_file_name(keys=api_settings.PUBLIC_KEYS, issuer=issuer, key_id=key_id)
    return load_public_key(file_name=file_name), get_key_id(file_name=file_name)

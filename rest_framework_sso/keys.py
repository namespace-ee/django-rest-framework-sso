# coding: utf-8
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from django.utils import six
from jwt.exceptions import InvalidKeyError

from rest_framework_sso.settings import api_settings

import logging

logger = logging.getLogger(__name__)


def read_key_file(file_name):
    if api_settings.KEY_STORE_ROOT:
        file_path = os.path.abspath(os.path.join(api_settings.KEY_STORE_ROOT, file_name))
    else:
        file_path = os.path.abspath(file_name)
    with open(file_path, "rb") as file_obj:
        return file_obj.read()


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
    if isinstance(issuer_keys, (str, six.text_type)):
        issuer_keys = [issuer_keys]
    if key_id:
        issuer_keys = [ik for ik in issuer_keys if key_id in (ik, get_key_id(ik))]
    if len(issuer_keys) < 1:
        raise InvalidKeyError("No key matches the given key_id")
    return issuer_keys[0]


def get_private_key_and_key_id(issuer, key_id=None):
    file_name = get_key_file_name(keys=api_settings.PRIVATE_KEYS, issuer=issuer, key_id=key_id)
    file_data = read_key_file(file_name=file_name)
    key = load_pem_private_key(file_data, password=None, backend=default_backend())
    return key, get_key_id(file_name=file_name)


def get_public_key_and_key_id(issuer, key_id=None):
    file_name = get_key_file_name(keys=api_settings.PUBLIC_KEYS, issuer=issuer, key_id=key_id)
    file_data = read_key_file(file_name=file_name)
    key = load_pem_public_key(file_data, backend=default_backend())
    return key, get_key_id(file_name=file_name)

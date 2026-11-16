from __future__ import annotations

import functools
import logging
import os
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

import pem
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from jwt.exceptions import InvalidKeyError

from rest_framework_sso.exceptions import KeyLoadError
from rest_framework_sso.settings import api_settings

if TYPE_CHECKING:
    from jwt.algorithms import AllowedPrivateKeys, AllowedPublicKeys

logger = logging.getLogger(__name__)

# Key types PyJWT supports at all (jwt.algorithms.AllowedPrivateKeys / AllowedPublicKeys)
PYJWT_PRIVATE_KEY_TYPES = (RSAPrivateKey, EllipticCurvePrivateKey, Ed25519PrivateKey, Ed448PrivateKey)
PYJWT_PUBLIC_KEY_TYPES = (RSAPublicKey, EllipticCurvePublicKey, Ed25519PublicKey, Ed448PublicKey)


def read_key_file(file_name: str) -> list[pem.AbstractPEMObject]:
    if api_settings.KEY_STORE_ROOT:
        file_path = os.path.abspath(os.path.join(api_settings.KEY_STORE_ROOT, file_name))
    else:
        file_path = os.path.abspath(file_name)
    return pem.parse_file(file_path)


@functools.cache
def load_private_key(file_name: str) -> AllowedPrivateKeys:
    for obj in read_key_file(file_name=file_name):
        if isinstance(obj, pem.PrivateKey):
            key = load_pem_private_key(obj.as_bytes(), password=None)
            if not isinstance(key, PYJWT_PRIVATE_KEY_TYPES):
                raise KeyLoadError(f"{type(key).__name__} in key file {file_name!r} is not supported by PyJWT")
            return key
    raise KeyLoadError(f"No private key found in key file {file_name!r}")


@functools.cache
def load_public_key(file_name: str) -> AllowedPublicKeys:
    for obj in read_key_file(file_name=file_name):
        if isinstance(obj, pem.PublicKey):
            key = load_pem_public_key(obj.as_bytes())
            if not isinstance(key, PYJWT_PUBLIC_KEY_TYPES):
                raise KeyLoadError(f"{type(key).__name__} in key file {file_name!r} is not supported by PyJWT")
            return key
    raise KeyLoadError(f"No public key found in key file {file_name!r}")


def get_key_id(file_name: str) -> str:
    suffixes = [".pem"]
    for suffix in suffixes:
        if file_name.lower().endswith(suffix):
            return file_name[: -len(suffix)]
    return file_name


def get_key_file_name(keys: Mapping[str, str | Sequence[str]], issuer: str, key_id: str | None = None) -> str:
    issuer_keys = keys.get(issuer)
    if not issuer_keys:
        raise InvalidKeyError("No keys defined for the given issuer")
    if isinstance(issuer_keys, str):
        issuer_keys = [issuer_keys]
    if key_id:
        issuer_keys = [ik for ik in issuer_keys if key_id in (ik, get_key_id(ik))]
    if len(issuer_keys) < 1:
        raise InvalidKeyError("No key matches the given key_id")
    return issuer_keys[0]


def get_private_key_and_key_id(issuer: str, key_id: str | None = None) -> tuple[AllowedPrivateKeys, str]:
    file_name = get_key_file_name(keys=api_settings.PRIVATE_KEYS, issuer=issuer, key_id=key_id)
    return load_private_key(file_name=file_name), get_key_id(file_name=file_name)


def get_public_key_and_key_id(issuer: str, key_id: str | None = None) -> tuple[AllowedPublicKeys, str]:
    file_name = get_key_file_name(keys=api_settings.PUBLIC_KEYS, issuer=issuer, key_id=key_id)
    return load_public_key(file_name=file_name), get_key_id(file_name=file_name)

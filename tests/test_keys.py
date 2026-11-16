import pathlib
from unittest import mock

import pem
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from django.test import TestCase
from jwt.exceptions import InvalidKeyError

from rest_framework_sso import keys
from rest_framework_sso.exceptions import KeyLoadError
from rest_framework_sso.settings import api_settings

KEYS_DIR = pathlib.Path(__file__).parent / "keys"


class TestReadKeyFile(TestCase):
    def test_read(self):
        pem_objects = keys.read_key_file("test-2048.pem")
        self.assertIsInstance(pem_objects, list)
        pem_types = {type(obj) for obj in pem_objects}
        self.assertIn(pem.PrivateKey, pem_types)
        self.assertIn(pem.PublicKey, pem_types)


class TestGetKeyId(TestCase):
    def test_root_simple(self):
        key_id = keys.get_key_id(file_name="keyfile")
        self.assertEqual(key_id, "keyfile")

    def test_root_pem_extension(self):
        key_id = keys.get_key_id(file_name="keyfile.pem")
        self.assertEqual(key_id, "keyfile")

    def test_subfolder_simple(self):
        key_id = keys.get_key_id(file_name="subfolder/keyfile")
        self.assertEqual(key_id, "subfolder/keyfile")

    def test_subfolder_pem_extension(self):
        key_id = keys.get_key_id(file_name="subfolder/keyfile.pem")
        self.assertEqual(key_id, "subfolder/keyfile")


class TestGetKeyFileName(TestCase):
    def test_empty_keys(self):
        with self.assertRaisesMessage(InvalidKeyError, "No keys defined for the given issuer"):
            keys.get_key_file_name(keys={}, issuer="test-issuer")

    def test_other_issuer_keys(self):
        with self.assertRaisesMessage(InvalidKeyError, "No keys defined for the given issuer"):
            keys.get_key_file_name(keys={"other-issuer": ["other-key.pem"]}, issuer="test-issuer")

    def test_one_key_string(self):
        file_name = keys.get_key_file_name(keys={"test-issuer": "first-key.pem"}, issuer="test-issuer")
        self.assertEqual(file_name, "first-key.pem")

    def test_one_key_list(self):
        file_name = keys.get_key_file_name(keys={"test-issuer": ["first-key.pem"]}, issuer="test-issuer")
        self.assertEqual(file_name, "first-key.pem")

    def test_one_key_with_key_id(self):
        file_name = keys.get_key_file_name(keys={"test-issuer": ["first-key.pem"]}, issuer="test-issuer")
        self.assertEqual(file_name, "first-key.pem")

    def test_one_key_incorrect_key_id(self):
        with self.assertRaisesMessage(InvalidKeyError, "No key matches the given key_id"):
            keys.get_key_file_name(
                keys={"test-issuer": ["first-key.pem"]}, issuer="test-issuer", key_id="incorrect-key"
            )

    def test_two_keys_no_key_id(self):
        file_name = keys.get_key_file_name(
            keys={"test-issuer": ["first-key.pem", "second-key.pem"]}, issuer="test-issuer"
        )
        self.assertEqual(file_name, "first-key.pem")

    def test_two_keys_with_key_id_1_exact(self):
        file_name = keys.get_key_file_name(
            keys={"test-issuer": ["first-key.pem", "second-key.pem"]}, issuer="test-issuer", key_id="first-key.pem"
        )
        self.assertEqual(file_name, "first-key.pem")

    def test_two_keys_with_key_id_1_no_pem(self):
        file_name = keys.get_key_file_name(
            keys={"test-issuer": ["first-key.pem", "second-key.pem"]}, issuer="test-issuer", key_id="first-key"
        )
        self.assertEqual(file_name, "first-key.pem")

    def test_two_keys_with_key_id_2_exact(self):
        file_name = keys.get_key_file_name(
            keys={"test-issuer": ["first-key.pem", "second-key.pem"]}, issuer="test-issuer", key_id="second-key.pem"
        )
        self.assertEqual(file_name, "second-key.pem")

    def test_two_keys_with_key_id_2_no_pem(self):
        file_name = keys.get_key_file_name(
            keys={"test-issuer": ["first-key.pem", "second-key.pem"]}, issuer="test-issuer", key_id="second-key"
        )
        self.assertEqual(file_name, "second-key.pem")

    def test_two_keys_incorrect_key_id(self):
        with self.assertRaisesMessage(InvalidKeyError, "No key matches the given key_id"):
            keys.get_key_file_name(
                keys={"test-issuer": ["first-key.pem", "second-key.pem"]}, issuer="test-issuer", key_id="incorrect-key"
            )


class TestGetPrivateKeyAndKeyId(TestCase):
    def test_empty_keys(self):
        with self.assertRaisesMessage(InvalidKeyError, "No keys defined for the given issuer"):
            keys.get_private_key_and_key_id(issuer="other-issuer")

    def test_first_key(self):
        private_key, key_id = keys.get_private_key_and_key_id(issuer="test-issuer")
        self.assertIsInstance(private_key, RSAPrivateKey)
        self.assertEqual(key_id, "test-2048")

    def test_second_key(self):
        private_key, key_id = keys.get_private_key_and_key_id(issuer="test-issuer", key_id="test-1024")
        self.assertIsInstance(private_key, RSAPrivateKey)
        self.assertEqual(key_id, "test-1024")


class TestGetPublicKeyAndKeyId(TestCase):
    def test_empty_keys(self):
        with self.assertRaisesMessage(InvalidKeyError, "No keys defined for the given issuer"):
            keys.get_public_key_and_key_id(issuer="other-issuer")

    def test_first_key(self):
        public_key, key_id = keys.get_public_key_and_key_id(issuer="test-issuer")
        self.assertIsInstance(public_key, RSAPublicKey)
        self.assertEqual(key_id, "test-2048")

    def test_second_key(self):
        public_key, key_id = keys.get_public_key_and_key_id(issuer="test-issuer", key_id="test-1024")
        self.assertIsInstance(public_key, RSAPublicKey)
        self.assertEqual(key_id, "test-1024")


class TestKeyCache(TestCase):
    def setUp(self):
        keys.load_private_key.cache_clear()
        keys.load_public_key.cache_clear()

    def test_repeated_lookups_parse_the_key_file_once(self):
        with mock.patch.object(keys.pem, "parse_file", wraps=keys.pem.parse_file) as parse_file:
            for _ in range(3):
                keys.get_public_key_and_key_id(issuer="test-issuer")
                keys.get_private_key_and_key_id(issuer="test-issuer")
        self.assertEqual(parse_file.call_count, 2)


@pytest.fixture
def key_store(tmp_path, monkeypatch):
    monkeypatch.setattr(api_settings, "KEY_STORE_ROOT", str(tmp_path))
    keys.load_private_key.cache_clear()
    keys.load_public_key.cache_clear()
    yield tmp_path
    keys.load_private_key.cache_clear()
    keys.load_public_key.cache_clear()


def _corrupt_pem(label):
    return f"-----BEGIN {label}-----\nbm90IGEga2V5\n-----END {label}-----\n"


def _pem_sections():
    private_key = keys.load_pem_private_key((KEYS_DIR / "test-2048.pem").read_bytes(), password=None)
    public_key = private_key.public_key()
    enc = serialization.Encoding.PEM
    return {
        "private": private_key.private_bytes(enc, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        "public": public_key.public_bytes(enc, serialization.PublicFormat.SubjectPublicKeyInfo),
        "rsa-private": private_key.private_bytes(
            enc, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        ),
        "rsa-public": public_key.public_bytes(enc, serialization.PublicFormat.PKCS1),
        "certificate": b"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n",
        "garbage": b"not a pem file\n",
    }


@pytest.mark.parametrize(
    "layout, has_private, has_public",
    [
        (["private", "public"], True, True),
        (["public", "private"], True, True),
        (["private"], True, False),
        (["public"], False, True),
        (["rsa-private", "rsa-public"], True, True),
        (["certificate", "private", "garbage", "public"], True, True),
        (["certificate"], False, False),
        (["garbage"], False, False),
        ([], False, False),
    ],
    ids=lambda v: "+".join(v) or "empty" if isinstance(v, list) else None,
)
def test_load_key_by_file_layout(key_store, layout, has_private, has_public):
    sections = _pem_sections()
    (key_store / "key.pem").write_bytes(b"".join(sections[name] for name in layout))
    for load_key, key_class, expected, name in [
        (keys.load_private_key, RSAPrivateKey, has_private, "private"),
        (keys.load_public_key, RSAPublicKey, has_public, "public"),
    ]:
        if expected:
            assert isinstance(load_key(file_name="key.pem"), key_class)
        else:
            with pytest.raises(KeyLoadError, match=f"No {name} key found in key file 'key.pem'"):
                load_key(file_name="key.pem")


def _write_key(path, private_key):
    enc = serialization.Encoding.PEM
    path.write_bytes(
        private_key.private_bytes(enc, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        + private_key.public_key().public_bytes(enc, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


@pytest.mark.parametrize(
    "key_type, encode_algorithm, decode_algorithms, private_ok, public_ok",
    [
        ("rsa", "RS256", None, True, True),
        ("rsa", "PS256", None, True, True),
        ("rsa", "ES256", None, False, False),
        ("rsa", "ES256", ["ES256", "RS256"], False, True),
        ("rsa", "RS256", ["ES256"], True, False),
        ("rsa", "HS256", None, False, False),
        ("ec", "ES256", None, True, True),
        ("ec", "RS256", None, False, False),
        ("dsa", "RS256", None, False, False),
    ],
)
def test_load_key_must_match_configured_algorithms(
    key_store, monkeypatch, key_type, encode_algorithm, decode_algorithms, private_ok, public_ok
):
    monkeypatch.setattr(api_settings, "ENCODE_ALGORITHM", encode_algorithm)
    monkeypatch.setattr(api_settings, "DECODE_ALGORITHMS", decode_algorithms)
    generate = {
        "rsa": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "ec": lambda: ec.generate_private_key(ec.SECP256R1()),
        "dsa": lambda: dsa.generate_private_key(key_size=2048),
    }[key_type]
    _write_key(key_store / "key.pem", generate())
    for load_key, ok in [(keys.load_private_key, private_ok), (keys.load_public_key, public_ok)]:
        if ok:
            load_key(file_name="key.pem")
        else:
            with pytest.raises(KeyLoadError, match="in key file 'key.pem' does not match"):
                load_key(file_name="key.pem")


def test_load_key_propagates_unknown_algorithm(key_store, monkeypatch):
    monkeypatch.setattr(api_settings, "ENCODE_ALGORITHM", "XX256")
    (key_store / "key.pem").write_bytes((KEYS_DIR / "test-2048.pem").read_bytes())
    with pytest.raises(NotImplementedError):
        keys.load_private_key(file_name="key.pem")


def test_load_key_propagates_file_errors(key_store):
    with pytest.raises(FileNotFoundError):
        keys.load_public_key(file_name="missing.pem")
    (key_store / "corrupt.pem").write_text("-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n")
    with pytest.raises(ValueError):
        keys.load_public_key(file_name="corrupt.pem")


def test_load_key_failure_is_not_cached(key_store):
    (key_store / "test-2048.pem").write_text("")
    with pytest.raises(KeyLoadError):
        keys.load_public_key(file_name="test-2048.pem")
    (key_store / "test-2048.pem").write_bytes((KEYS_DIR / "test-2048.pem").read_bytes())
    assert isinstance(keys.load_public_key(file_name="test-2048.pem"), RSAPublicKey)

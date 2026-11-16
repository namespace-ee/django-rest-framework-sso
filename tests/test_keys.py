import os
import pathlib
from unittest import mock

import pem
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from django.test import TestCase
from jwt.exceptions import InvalidKeyError

from rest_framework_sso import keys
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


@pytest.mark.parametrize(
    "load_key, label", [(keys.load_private_key, "PRIVATE KEY"), (keys.load_public_key, "PUBLIC KEY")]
)
@pytest.mark.parametrize(
    "content, message",
    [
        (None, "No such file or directory"),
        ("", "found in key file"),
        ("not a pem file", "found in key file"),
        ("corrupt", "Unable to load"),
    ],
    ids=["missing", "empty", "no-pem-block", "corrupt"],
)
def test_load_key_raises_key_load_error(key_store, load_key, label, content, message):
    if content is not None:
        (key_store / "broken.pem").write_text(_corrupt_pem(label) if content == "corrupt" else content)
    with pytest.raises(keys.KeyLoadError, match=message) as exc_info:
        load_key(file_name="broken.pem")
    assert not isinstance(exc_info.value, InvalidKeyError)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_load_key_raises_key_load_error_for_unreadable_file(key_store):
    key_file = key_store / "unreadable.pem"
    key_file.write_text("")
    key_file.chmod(0)
    with pytest.raises(keys.KeyLoadError, match="Permission denied"):
        keys.load_public_key(file_name="unreadable.pem")


def test_load_key_raises_key_load_error_for_missing_key_type(key_store):
    public_only = "".join(
        str(o) for o in keys.pem.parse_file(KEYS_DIR / "test-2048.pem") if isinstance(o, pem.PublicKey)
    )
    (key_store / "public-only.pem").write_text(public_only)
    assert isinstance(keys.load_public_key(file_name="public-only.pem"), RSAPublicKey)
    with pytest.raises(keys.KeyLoadError, match="No PrivateKey found in key file 'public-only.pem'"):
        keys.load_private_key(file_name="public-only.pem")


def test_load_key_failure_is_not_cached(key_store):
    with pytest.raises(keys.KeyLoadError):
        keys.load_public_key(file_name="test-2048.pem")
    (key_store / "test-2048.pem").write_bytes((KEYS_DIR / "test-2048.pem").read_bytes())
    assert isinstance(keys.load_public_key(file_name="test-2048.pem"), RSAPublicKey)

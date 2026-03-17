# coding: utf-8
from __future__ import absolute_import, unicode_literals

import pem
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from django.test import TestCase
from jwt.exceptions import InvalidKeyError

from rest_framework_sso import keys


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

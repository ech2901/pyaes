import unittest

from AES import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt, pcbc_encrypt, pcbc_decrypt


class TestECB(unittest.TestCase):

    def test_128_base(self):
        plaintext = b'Hello, world!'
        password = b'test key please ignore'
        size = 128
        salt = b'No salt please'

        ciphertext, _ = ecb_encrypt(plaintext, password, size, salt=salt)

        new_plaintext = ecb_decrypt(ciphertext, password, size, salt=salt)

        self.assertEqual(plaintext, new_plaintext)

    def test_192_base(self):
        plaintext = b'Hello, world!'
        password = b'test key please ignore'
        size = 192
        salt = b'No salt please'

        ciphertext, _ = ecb_encrypt(plaintext, password, size, salt=salt)

        new_plaintext = ecb_decrypt(ciphertext, password, size, salt=salt)

        self.assertEqual(plaintext, new_plaintext)

    def test_256_base(self):
        plaintext = b'Hello, world!'
        password = b'test key please ignore'
        size = 256
        salt = b'No salt please'

        ciphertext, _ = ecb_encrypt(plaintext, password, size, salt=salt)

        new_plaintext = ecb_decrypt(ciphertext, password, size, salt=salt)

        self.assertEqual(plaintext, new_plaintext)

class TestCBC(unittest.TestCase):

    def test_128_base(self):
        plaintext = b'Hello, world!'
        password = b'test key please ignore'
        size = 128
        iv = b'this is a bad IV'
        salt = b'No salt please'

        ciphertext, _, _ = cbc_encrypt(plaintext, password, size, iv=iv, salt=salt)

        new_plaintext = cbc_decrypt(ciphertext, password, size, iv=iv, salt=salt)

        self.assertEqual(plaintext, new_plaintext)

    def test_192_base(self):
        plaintext = b'Hello, world!'
        password = b'test key please ignore'
        size = 192
        iv = b'this is a bad IV'
        salt = b'No salt please'

        ciphertext, _, _ = cbc_encrypt(plaintext, password, size, iv=iv, salt=salt)

        new_plaintext = cbc_decrypt(ciphertext, password, size, iv=iv, salt=salt)

        self.assertEqual(plaintext, new_plaintext)

    def test_256_base(self):
        plaintext = b'Hello, world!'
        password = b'test key please ignore'
        size = 256
        iv = b'this is a bad IV'
        salt = b'No salt please'

        ciphertext, _, _ = cbc_encrypt(plaintext, password, size, iv=iv, salt=salt)

        new_plaintext = cbc_decrypt(ciphertext, password, size, iv=iv, salt=salt)

        self.assertEqual(plaintext, new_plaintext)

class TestPCBC(unittest.TestCase):

    def test_128_base(self):
        plaintext = b'Hello, world!'
        password = b'test key please ignore'
        size = 128
        iv = b'this is a bad IV'
        salt = b'No salt please'

        ciphertext, _, _ = pcbc_encrypt(plaintext, password, size, iv=iv, salt=salt)

        new_plaintext = pcbc_decrypt(ciphertext, password, size, iv=iv, salt=salt)

        self.assertEqual(plaintext, new_plaintext)

    def test_192_base(self):
        plaintext = b'Hello, world!'
        password = b'test key please ignore'
        size = 192
        iv = b'this is a bad IV'
        salt = b'No salt please'

        ciphertext, _, _ = pcbc_encrypt(plaintext, password, size, iv=iv, salt=salt)

        new_plaintext = pcbc_decrypt(ciphertext, password, size, iv=iv, salt=salt)

        self.assertEqual(plaintext, new_plaintext)

    def test_256_base(self):
        plaintext = b'Hello, world!'
        password = b'test key please ignore'
        size = 256
        iv = b'this is a bad IV'
        salt = b'No salt please'

        ciphertext, _, _ = pcbc_encrypt(plaintext, password, size, iv=iv, salt=salt)

        new_plaintext = pcbc_decrypt(ciphertext, password, size, iv=iv, salt=salt)

        self.assertEqual(plaintext, new_plaintext)

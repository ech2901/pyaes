import unittest

import AESCore as Core
from Field import GF
from Key import iter_key


# TODO comment code
# TODO create docstrings
# TODO format according to PEP 8


# Test encryption data from known good inputs
# Text vectors from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf


# Helper function to turn inputs from given hex values
# To a list of GF instances
def hex_to_arr(data):
    data = bytes.fromhex(data)
    return [GF(i) for i in data]


class TestEncrypt128(unittest.TestCase):
    def test_input_1(self):
        plaintext = hex_to_arr(r'00112233445566778899aabbccddeeff')
        key = hex_to_arr(r'000102030405060708090a0b0c0d0e0f')
        expected_out = hex_to_arr(r'69c4e0d86a7b0430d8cdb78070b4c55a')

        test_out = Core.encrypt_128(plaintext, iter_key(key, 128))

        for expected, test in zip(expected_out, test_out):
            self.assertEqual(expected, test)


class TestDecrypt128(unittest.TestCase):
    def test_input_1(self):
        ciphertext = hex_to_arr(r'69c4e0d86a7b0430d8cdb78070b4c55a')
        key = hex_to_arr(r'000102030405060708090a0b0c0d0e0f')
        expected_out = hex_to_arr(r'00112233445566778899aabbccddeeff')

        test_out = Core.decrypt_128(ciphertext, iter_key(key, 128, reverse=True))

        for expected, test in zip(expected_out, test_out):
            self.assertEqual(expected, test)


class TestEncrypt192(unittest.TestCase):
    def test_input_1(self):
        plaintext = hex_to_arr(r'00112233445566778899aabbccddeeff')
        key = hex_to_arr(r'000102030405060708090a0b0c0d0e0f1011121314151617')
        expected_out = hex_to_arr(r'dda97ca4864cdfe06eaf70a0ec0d7191')

        test_out = Core.encrypt_192(plaintext, iter_key(key, 192))

        for expected, test in zip(expected_out, test_out):
            self.assertEqual(expected, test)


class TestDecrypt192(unittest.TestCase):
    def test_input_1(self):
        ciphertext = hex_to_arr(r'dda97ca4864cdfe06eaf70a0ec0d7191')
        key = hex_to_arr(r'000102030405060708090a0b0c0d0e0f1011121314151617')
        expected_out = hex_to_arr(r'00112233445566778899aabbccddeeff')

        test_out = Core.decrypt_192(ciphertext, iter_key(key, 192, reverse=True))

        for expected, test in zip(expected_out, test_out):
            self.assertEqual(expected, test)


class TestEncrypt256(unittest.TestCase):
    def test_input_1(self):
        plaintext = hex_to_arr(r'00112233445566778899aabbccddeeff')
        key = hex_to_arr(r'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
        expected_out = hex_to_arr(r'8ea2b7ca516745bfeafc49904b496089')

        test_out = Core.encrypt_256(plaintext, iter_key(key, 256))

        for expected, test in zip(expected_out, test_out):
            self.assertEqual(expected, test)


class TestDecrypt256(unittest.TestCase):
    def test_input_1(self):
        ciphertext = hex_to_arr(r'8ea2b7ca516745bfeafc49904b496089')
        key = hex_to_arr(r'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
        expected_out = hex_to_arr(r'00112233445566778899aabbccddeeff')

        test_out = Core.decrypt_256(ciphertext, iter_key(key, 256, reverse=True))

        for expected, test in zip(expected_out, test_out):
            self.assertEqual(expected, test)


if __name__ == '__main__':

    Core_Suite = unittest.TestSuite()

    Core_Suite.addTest(TestEncrypt128())
    Core_Suite.addTest(TestEncrypt128())

    Core_Suite.addTest(TestEncrypt192())
    Core_Suite.addTest(TestEncrypt192())

    Core_Suite.addTest(TestEncrypt256())
    Core_Suite.addTest(TestEncrypt256())

    Core_Suite.run(unittest.TestResult())

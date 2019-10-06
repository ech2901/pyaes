# Import base encryption and decryption functions
# Import pbkdf2_hmac to generage passwords of a fixed size based on inputs
from functools import wraps
from hashlib import pbkdf2_hmac as phash
# Import urandom to get cryptographically secure random bytes
from os import urandom

from pyaes.AESCore import encrypt_128, encrypt_192, encrypt_256, decrypt_128, decrypt_192, decrypt_256
# Import Finite(Galois) Field class
# This handles most of the math operated on values
from pyaes.Field import GF
# Import key generation function
# Generates the key schedule for a given AES size (128, 192, 256) and loops over the schedule repeatedly
# So that the keys can be used for each block of plaintext
from pyaes.Key import iter_key


# GOALS: Rework each mode of encryption into it's own class inheriting common functions from a base class.


class BaseAES(object):
    def __init__(self, salt_size=64, hash_algo='sha256', hash_iters=1_000_000):
        """
        Base class for AES encryption modes

        :param hash_algo: str
        :param hash_iters: int
        """
        self.salt_size = salt_size
        self.hash_algo = hash_algo
        self.hash_iters = hash_iters

    def _encrypt_(self, blocks, key, iv, func):
        raise NotImplementedError

    def _decrypt_(self, blocks, key, iv, func):
        raise NotImplementedError

    @staticmethod
    def to_blocks(text):

        # Create a list of GF objects
        data = [GF(i) for i in text]

        while len(data) % 16 != 0:
            # Pad at end of plaintext to make sure it always has blocks with 16 bytes of data
            data.append(GF(0))

        # Return a list of lists. Each internal list has 16 GF object elements.
        return [data[i:i + 16] for i in range(0, len(data), 16)]

    @staticmethod
    def from_blocks(blocks, strip):
        out = ''
        for block in blocks:
            for item in block:
                out = out + str(item)
        return bytes.fromhex(out).rstrip(b'\x00') if strip else bytes.fromhex(out)

    def stream(self, plaintext, password, size, salt=None, iv=None):


        # Ultimately this is just to make it more convinient to use stream modes
        return self.encrypt(plaintext, password, size, salt, iv)

    def encrypt(self, plaintext, password, size, salt=None, iv=None):

        blocks = self.to_blocks(plaintext)

        if salt is None:
            salt = urandom(self.salt_size)

        key = iter_key([GF(i) for i in phash(self.hash_algo, password, salt, self.hash_iters, size / 8)], size)

        if iv is None:
            iv = [GF(i) for i in urandom(16)]
        elif len(iv) != 16:
            raise ValueError
        else:
            iv = [GF(i) for i in iv]

        if size == 128:
            enc_func = encrypt_128
        elif size == 192:
            enc_func = encrypt_192
        elif size == 256:
            enc_func = encrypt_256
        else:
            raise ValueError

        blocks, *outputs = self._encrypt_(blocks, key, iv, enc_func)

        out = self.from_blocks(blocks, False)
        outputs.insert(0, salt)

        return (out, *outputs)

    def decrypt(self, ciphertext, password, size, salt=None, iv=None):

        blocks = self.to_blocks(ciphertext)

        if salt is None:
            salt = urandom(self.salt_size)

        key = iter_key([GF(i) for i in phash(self.hash_algo, password, salt, self.hash_iters, size / 8)], size, reverse=True)

        if iv is None:
            iv = [GF(i) for i in urandom(16)]
        elif len(iv) != 16:
            raise ValueError
        else:
            iv = [GF(i) for i in iv]

        if size == 128:
            dec_func = decrypt_128
        elif size == 192:
            dec_func = decrypt_192
        elif size == 256:
            dec_func = decrypt_256
        else:
            raise ValueError

        blocks = self._decrypt_(blocks, key, iv, dec_func)

        return self.from_blocks(blocks, True)


class ECB(BaseAES):

    def _encrypt_(self, blocks, key, _, func):
        """
        Method to handle encryption using ECB mode of operation.
        Should not be directly called

        :param blocks: list
        :param key: generator
        :param func: function
        :return: list
        """

        for index, block in enumerate(blocks):
            # encrypt each block with the key schedule
            blocks[index] = func(block, key)
        return blocks,

    def _decrypt_(self, blocks, key, _, func):
        """
        Method to handle decryption using ECB mode of operation.
        Should not be directly called

        :param blocks: list
        :param key: generator
        :param func: function
        :return: list
        """

        for index, block in enumerate(blocks):
            # decrypt each block with the key schedule
            blocks[index] = func(block, key)

        return blocks


class CBC(BaseAES):
    def _encrypt_(self, blocks, key, iv, enc_func):
        """
        Method to handle encryption using CBC mode of operation.
        Should not be directly called

        :param blocks: list
        :param key: generator
        :param iv: list
        :param func: function
        :return: list
        """


        xor_iv = iv.copy()

        for index, block in enumerate(blocks):
            block = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
            # Get the new iv ready and encrypt this block with the key schedule
            xor_iv = enc_func(block, key)
            # New iv is the encrypted block
            blocks[index] = xor_iv

        return blocks, iv


    def _decrypt_(self, blocks, key, xor_iv, dec_func):
        """
        Method to handle decryption using CBC mode of operation.
        Should not be directly called

        :param blocks: list
        :param key: generator
        :param iv: list
        :param func: function
        :return: list
        """

        for index, block in enumerate(blocks):
            # Get the new iv ready
            next_iv = block
            # Decrypt the block
            block = dec_func(block, key)
            # Save decrypted block by xor-ing with iv
            blocks[index] = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
            # Assign new iv
            xor_iv = next_iv

        return blocks


class PCBC(BaseAES):
    def _encrypt_(self, blocks, key, iv, enc_func):
        """
        Method to handle encryption using PCBC mode of operation.
        Should not be directly called

        :param blocks: list
        :param key: generator
        :param iv: list
        :param func: function
        :return: list
        """

        xor_iv = iv.copy()

        for index, block in enumerate(blocks):
            # Get the new iv ready
            new_iv = block

            for i in range(16):
                block[i] = block[i] ^ xor_iv[i]
            # Encrypt each block with the key schedule
            block = enc_func(block, key)

            # Save encrypted block
            blocks[index] = block

            for i in range(16):
                # xor each byte of the encrypted block with each byte of the unencrypted block
                # This creates the new iv for the next block
                xor_iv[i] = new_iv[i] ^ block[i]

        return blocks, iv


    def _decrypt_(self, blocks, key, xor_iv, dec_func):
        """
        Method to handle decryption using PCBC mode of operation.
        Should not be directly called

        :param blocks: list
        :param key: generator
        :param iv: list
        :param func: function
        :return: list
        """

        for index, block in enumerate(blocks):

            # Get the new iv ready
            new_iv = block

            # Encrypt each block with the key schedule
            block = dec_func(block, key)

            for i in range(16):
                block[i] = block[i] ^ xor_iv[i]

            # Save decrypted block
            blocks[index] = block

            for i in range(16):
                # xor each byte of the encrypted block with each byte of the unencrypted block
                # This creates the new iv for the next block
                xor_iv[i] = new_iv[i] ^ block[i]

        return blocks


class CFB(BaseAES):
    def _encrypt_(self, blocks, key, iv, func):
        """
        Method to handle encryption using CFB mode of operation.
        Should not be directly called

        :param blocks: list
        :param key: generator
        :param iv: list
        :param func: function
        :return: list
        """

        enc_iv = iv.copy()

        for index, block in enumerate(blocks):
            for i, p_item, c_item in zip(range(16), block, func(enc_iv, key)):
                block[i] = p_item ^ c_item

            enc_iv = block
            blocks[index] = block

        return blocks, iv

    def _decrypt_(self, blocks, key, iv, func):
        pass


class OFB(BaseAES):
    def _encrypt_(self, blocks, key, iv, func):
        """
        Method to handle encryption using OFB mode of operation.
        Should not be directly called

        :param blocks: list
        :param key: generator
        :param iv: list
        :param func: function
        :return: list
        """


        xor_iv = iv.copy()
        for index, block in enumerate(blocks):
            xor_iv = func(xor_iv, key)
            for i in range(16):
                block[i] = block[i] ^ xor_iv[i]
            blocks[index] = block

        return blocks, iv

    def _decrypt_(self, blocks, key, iv, func):
        pass


class CTR(BaseAES):
    def __init__(self, counter_func=None, salt_size=64, hash_algo='sha256', hash_iters=1_000_000):
        super().__init__(salt_size, hash_algo, hash_iters)

        if counter_func is None:
            self.counter = self.default_counter()
        else:
            self.counter = counter_func

    @staticmethod
    def default_counter(count=0, inc=1):
        while True:
            yield count
            count = count+inc

    def _encrypt_(self, blocks, key, iv, func):
        """
        Method to handle encryption using CTR mode of operation.
        Should not be directly called

        :param blocks: list
        :param key: generator
        :param iv: list
        :param func: function
        :return: list
        """

        xor_iv = iv.copy()

        for index, block in enumerate(blocks):
            ctr_iv = [GF(i) ^ x_item for i, x_item in zip(next(self.counter).to_bytes(16, 'big'), xor_iv)]
            blocks[index] = [b_item ^ ctr_item for b_item, ctr_item in zip(block, func(ctr_iv, key))]

        return blocks, iv

    def _decrypt_(self, blocks, key, iv, func):
        pass

if __name__ == '__main__':
    pass

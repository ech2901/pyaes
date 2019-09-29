# Import base encryption and decryption functions
# Import pbkdf2_hmac to generage passwords of a fixed size based on inputs
from hashlib import pbkdf2_hmac as phash
# Import urandom to get cryptographically secure random bytes
from os import urandom

from src.AESCore import encrypt_128, encrypt_192, encrypt_256, decrypt_128, decrypt_192, decrypt_256
# Import Finite(Galois) Field class
# This handles most of the math operated on values
from src.Field import GF
# Import key generation function
# Generates the key schedule for a given AES size (128, 192, 256) and loops over the schedule repeatedly
# So that the keys can be used for each block of plaintext
from src.Key import iter_key


# TODO finish commenting code
# TODO Create other block cipher operating modes

def parser(*, password, size, reverse=False,  **kwargs):
    """
    Helper function to reduce repeated code

    :param plaintext: bytes; keyword; adds a list of GF objects to the output
    :param ciphertext: string; keyword; adds a list of GF objects to the output
    :param password: bytes; keyword; adds a iter_key object to the output
    :param size: int; keyword; does not directly contribute to the output
    :param iv: bytes; keyword; adds a list of GF objects to the output
    :param salt: bytes; keyword; does not directly contribute to the output
    :param reverse: bool; keyword; True for most modes of decrypting


    :return: tuple
    """

    out = []

    if 'plaintext' in kwargs:
        plaintext = [GF(i) for i in kwargs['plaintext']]
        while len(plaintext) % 16 != 0:
            # Pad at end of plaintext to make sure it always has blocks with 16 bytes of data
            plaintext.append(GF(0))
        # Add a list of list objects that represent 16 byte blocks of data
        out.append([plaintext[i:i + 16] for i in range(0, len(plaintext), 16)])

    if 'ciphertext' in kwargs:
        ciphertext = bytes.fromhex(kwargs['ciphertext'])
        if len(ciphertext) % 16 != 0:
            # Ciphertext must always have blocks with 16 bytes of data
            raise ValueError
        ciphertext = [GF(i) for i in ciphertext]
        # Add a list of list objects that represent 16 byte blocks of data
        out.append([ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)])


    salt = kwargs.get('salt', urandom(64))
    if salt is None:
        salt = urandom(64)

    key = phash('sha256', password, salt, 1_000_000, size / 8)
    out.append(iter_key([GF(i) for i in key], size, reverse=reverse))





    if 'iv' in kwargs:
        iv = kwargs.get('iv', urandom(16))
        if iv is None:
            iv = urandom(16)
        elif len(iv) != 16:
            raise ValueError
        out.append([GF(i) for i in iv])

    out.append(salt)

    if size == 128:
        out.append(decrypt_128 if reverse else encrypt_128)
    elif size == 192:
        out.append(decrypt_192 if reverse else encrypt_192)
    elif size == 256:
        out.append(decrypt_256 if reverse else encrypt_256)
    else:
        raise ValueError

    return out


def ecb_encrypt(plaintext: bytes, password: bytes, size: int, *, salt: bytes = None):
    """
    Encrypt plaintext with the Electronic Code Book mode of operation

    :param plaintext: bytes
    :param password: bytes
    :param size: int (must be either 128, 192, or 256)
    :param salt:  bytes=None (not required)
    :return: ciphertext: string, salt: bytes
    :raise: ValueError: if size is not either 128, 192, or 256
    """

    blocks, key, salt, enc_func = parser(plaintext=plaintext, password=password, size=size, salt=salt)

    for index, block in enumerate(blocks):
        blocks[index] = enc_func(block, key)

    out = ''
    for block in blocks:
        for item in block:
            # Take each item of each block, convert to a string, and append to a string output
            out = out + str(item)

    return out, salt


def ecb_decrypt(ciphertext: str, password: bytes, size: int, salt: bytes):
    """
    Decrypt ciphertext with the Electronic Code Book mode of operation

    :param ciphertext: str
    :param password: bytes
    :param size: int (must be either 128, 192, or 256)
    :param salt: bytes
    :return: plaintext: bytes
    :raise: ValueError: if size is not either 128, 192, or 256
    """

    blocks, key, _, dec_func = parser(ciphertext=ciphertext, password=password, size=size, salt=salt, reverse=True)

    for index, block in enumerate(blocks):
        # Encrypt each block with the key schedule
        blocks[index] = dec_func(block, key)

    out = ''
    for block in blocks:
        for item in block:
            # For every item of every block convert to a string and append to an output string
            out = out + str(item)

    while out[-2:] == '00':
        # Remove trailing 0 bits added during encryption
        out = out[:-2]
    return bytes.fromhex(out)


def cbc_encrypt(plaintext: bytes, password: bytes, size: int, *, iv: bytes = None, salt: bytes = None):
    """
    Encrypt plaintext with the Cipher Block Chaining mode of operation

    :param plaintext: bytes
    :param password: bytes
    :param size: int (must be either 128, 192, or 256)
    :param iv: bytes (not required but if supplied must be 16 bytes)
    :param salt: bytes (not required
    :return: ciphertext: string, iv: bytes, salt: bytes
    :raise: ValueError: if size is not either 128, 192, or 256
    """

    blocks, key, iv, salt, enc_func = parser(plaintext=plaintext, password=password, size=size, iv=iv, salt=salt)

    xor_iv = iv.copy()

    for index, block in enumerate(blocks):
        block = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
        # Get the new iv ready and encrypt this block with the key schedule
        xor_iv = enc_func(block, key)
        # New iv is the encrypted block
        blocks[index] = xor_iv

    out = ''
    for block in blocks:
        for item in block:
            out = out + str(item)

    return out, iv, salt


def cbc_decrypt(ciphertext: str, password: bytes, size: int, iv: bytes, salt: bytes):
    """
    Decrypt ciphertext with the Cipher Block Chaining mode of operation

    :param ciphertext: str
    :param password: bytes
    :param size: int (must be either 128, 192, or 256)
    :param iv: bytes
    :param salt: bytes
    :return: plaintext: bytes
    :raise: ValueError: if size is not either 128, 192, or 256
    """

    blocks, key, xor_iv, _, dec_func = parser(ciphertext=ciphertext, password=password, size=size, iv=iv, salt=salt,
                                              reverse=True)
    for index, block in enumerate(blocks):
        # Get the new iv ready
        next_iv = block
        # Decrypt the block
        block = dec_func(block, key)
        # Save decrypted block by xor-ing with iv
        blocks[index] = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
        # Assign new iv
        xor_iv = next_iv

    out = ''
    for block in blocks:
        for item in block:
            out = out + str(item)
    while out[-2:] == '00':
        out = out[:-2]
    return bytes.fromhex(out)


def pcbc_encrypt(plaintext: bytes, password: bytes, size: int, *, iv: bytes = None, salt: bytes = None):
    """
    Encrypt plaintext using the Propagating Cipher Block Chaining
    mode of operation. Slightly more complex mode than CBC.

    :param plaintext: bytes
    :param password: bytes
    :param size: int (Must be either 128, 192, or 256)
    :param iv: bytes (not required but if supplied must be 16 bytes)
    :param salt: bytes (Can be omitted)
    :return: ciphertext: bytes, iv: bytes, salt: bytes
    """

    blocks, key, iv, salt, enc_func = parser(plaintext=plaintext, password=password, size=size, iv=iv, salt=salt)

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


    out = ''
    for block in blocks:
        for item in block:
            out = out + str(item)

    return out, iv, salt


def pcbc_decrypt(ciphertext: str, password: bytes, size: int, iv: bytes, salt: bytes):
    """
    Encrypt plaintext using the Propagating Cipher Block Chaining
    mode of operation.

    :param ciphertext: bytes
    :param password: bytes
    :param size: int (Must be either 128, 192, or 256)
    :param iv: bytes (Must be 16 bytes of data)
    :param salt: bytes
    :return: ciphertext: bytes, iv: bytes, salt: bytes
    """

    blocks, key, xor_iv, _, dec_func = parser(ciphertext=ciphertext, password=password, size=size, iv=iv, salt=salt,
                                              reverse=True)

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

    out = ''
    for block in blocks:
        for item in block:
            out = out + str(item)
    while out[-2:] == '00':
        out = out[:-2]
    return bytes.fromhex(out)


def cfb_encrypt(plaintext: bytes, password: bytes, size: int, *, iv: bytes = None, salt: bytes = None):
    """
    Encrypt plaintext with the Cipher Block Chaining mode of operation

    :param plaintext: bytes
    :param password: bytes
    :param size: int (must be either 128, 192, or 256)
    :param iv: bytes (not required but if supplied must be 16 bytes)
    :param salt: bytes (not required
    :return: ciphertext: string, iv: bytes, salt: bytes
    :raise: ValueError: if size is not either 128, 192, or 256
    """

    blocks, key, iv, salt, enc_func = parser(plaintext=plaintext, password=password, size=size, iv=iv, salt=salt)

    enc_iv = iv.copy()

    for index, block in enumerate(blocks):
        for i, p_item, c_item in zip(range(16), block, enc_func(enc_iv, key)):
            block[i] = p_item ^ c_item

        enc_iv = block
        blocks[index] = block

    out = ''
    for block in blocks:
        for item in block:
            out = out + str(item)

    return out, iv, salt


def cfb_decrypt(ciphertext: str, password: bytes, size: int, iv: bytes, salt: bytes):
    """
        Decrypt ciphertext with the Cipher Feedback mode of operation.
        Basically same as encrypting with this mode, just slightly different due to
        the types of parameters given.

        :param ciphertext: str
        :param password: bytes
        :param size: int (must be either 128, 192, or 256)
        :param iv: bytes
        :param salt: bytes
        :return: plaintext: bytes
        :raise: ValueError: if size is not either 128, 192, or 256
        """

    out, _, _ = cfb_encrypt(bytes.fromhex(ciphertext), password, size, iv=iv, salt=salt)

    while out[-2:] == '00':
        out = out[:-2]
    return out


def ofb_encrypt():
    pass


def ofb_decrypt():
    pass


def ctr_encrypt():
    pass


def ctr_decrypt():
    pass


if __name__ == '__main__':
    pass

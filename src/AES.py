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


def ecb_encrypt(plaintext: bytes, password: bytes, size: int, *, salt: bytes = None):
    """
    Encrypt plaintext with the Electronic Code Book mode of operation

    :param plaintext: bytes
    :param password: bytes
    :param size: int (must be either 128, 192, or 256)
    :param salt: None (not required)
    :return: ciphertext: string, salt: bytes
    :raise: ValueError: if size is not either 128, 192, or 256
    """
    if salt is None:
        # If the salt input is not given, generate a random salt of 64 bytes
        salt = urandom(64)

    # Convert the plaintext input into a list of GF instances
    plaintext = [GF(i) for i in plaintext]

    while len(plaintext) % 16 != 0:
        # Pads the size of the list to have blocks of length 16
        plaintext.append(GF(0))

    # Separate each GF instance into a block of size 16
    blocks = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]

    if size == 128:
        # For AES-128
        # Hash password with a salt to a given length of 16 bytes
        key = phash('sha256', password, salt, 1_000_000, 16)
        # Expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 128)

        for index, block in enumerate(blocks):
            # Encrypt each block with the key schedule
            blocks[index] = encrypt_128(block, key)

    elif size == 192:
        # For AES-192
        # Hach password with a salt to a given length of 24 bytes
        key = phash('sha256', password, salt, 1_000_000, 24)
        # expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 192)
        for index, block in enumerate(blocks):
            # Encrypt each block with the key schedule
            blocks[index] = encrypt_192(block, key)

    elif size == 256:
        # For AES-256
        # Hach password with a salt to a given length of 32 bytes
        key = phash('sha256', password, salt, 1_000_000, 32)
        # expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 256)
        for index, block in enumerate(blocks):
            # Encrypt each block with the key schedule
            blocks[index] = encrypt_256(block, key)

    else:
        raise ValueError(f'Expected size of either 128, 192, or 256 and recieved {size}')

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
    # Convert a string with hex values to a bytes object
    ciphertext = bytes.fromhex(ciphertext)
    # Convert the bytes object ciphertext to an array of GF instances
    ciphertext = [GF(i) for i in ciphertext]

    # Make sure the ciphertext can fit in blocks of size 16
    # This should never run for any valid given input
    while len(ciphertext) % 16 != 0:
        ciphertext.append(GF(0))

    # Break down the ciphertext into blocks of size 16
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]

    if size == 128:
        # For AES-128
        # Hash password with a salt to a given length of 16 bytes
        key = phash('sha256', password, salt, 1_000_000, 16)
        # Expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 128, reverse=True)

        for index, block in enumerate(blocks):
            # Encrypt each block with the key schedule
            blocks[index] = decrypt_128(block, key)

    elif size == 192:
        # For AES-192
        # Hash password with a salt to a given length of 24 bytes
        key = phash('sha256', password, salt, 1_000_000, 24)
        # Expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 192, reverse=True)

        for index, block in enumerate(blocks):
            # Encrypt each block with the key schedule
            blocks[index] = decrypt_192(block, key)

    elif size == 256:
        # For AES-256
        # Hash password with a salt to a given length of 32 bytes
        key = phash('sha256', password, salt, 1_000_000, 32)
        # Expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 256, reverse=True)

        for index, block in enumerate(blocks):
            # Encrypt each block with the key schedule
            blocks[index] = decrypt_256(block, key)

    else:
        raise ValueError(f'Expected size of either 128, 192, or 256 and recieved {size}')

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

    if salt is None:
        # If the salt input is not given, generate a random salt of 64 bytes
        salt = urandom(64)

    if iv is None:
        # If no supplied iv generate one
        iv = urandom(16)
    elif len(iv) != 16:
        # If a supplied iv is not of the correct size
        raise ValueError
    # create list of GF objects to represent the IV
    xor_iv = [GF(i) for i in iv]


    # Convert bytes object to an list of GF objects
    plaintext = [GF(i) for i in plaintext]
    # Pads the size of the list to have blocks of length 16
    while len(plaintext) % 16 != 0:
        plaintext.append(GF(0))

    # Break the plaintext into blocks with 16 elements each
    blocks = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]

    if size == 128:
        # For AES-128
        # Hash password with a salt to a given length of 16 bytes
        key = phash('sha256', password, salt, 1_000_000, 16)
        # Expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 128)

        for index, block in enumerate(blocks):
            block = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
            # Get the new iv ready and encrypt this block with the key schedule
            xor_iv = encrypt_128(block, key)
            # New iv is the encrypted block
            blocks[index] = xor_iv

    elif size == 192:
        key = phash('sha256', password, salt, 1_000_000, 24)
        # Expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 192)
        for index, block in enumerate(blocks):
            block = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
            # Get the new iv ready and encrypt this block with the key schedule
            xor_iv = encrypt_192(block, key)
            # New iv is the encrypted block
            blocks[index] = xor_iv

    elif size == 256:
        key = phash('sha256', password, salt, 1_000_000, 32)
        # Expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 256)
        for index, block in enumerate(blocks):
            block = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
            # Get the new iv ready and encrypt this block with the key schedule
            xor_iv = encrypt_256(block, key)
            # New iv is the encrypted block
            blocks[index] = xor_iv
    else:
        raise ValueError(f'Expected size of either 128, 192, or 256 and recieved {size}')

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
    # Convert str object with hex values into a bytes object
    ciphertext = bytes.fromhex(ciphertext)
    # Convert bytes object to an list of GF objects
    ciphertext = [GF(i) for i in ciphertext]


    while len(ciphertext) % 16 != 0:
        # Pads the size of the list to have blocks of length 16
        ciphertext.append(GF(0))

    if len(iv) != 16:
        # If a supplied iv is not of the correct size
        raise ValueError

    # create list of GF objects to represent the IV
    xor_iv = [GF(i) for i in iv]

    # Break the plaintext into blocks with 16 elements each
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]

    if size == 128:
        # For AES-128
        # Hash password with a salt to a given length of 16 bytes
        key = phash('sha256', password, salt, 1_000_000, 16)
        # Expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 128, reverse=True)

        for index, block in enumerate(blocks):
            # Get the new iv ready
            next_iv = block
            # Decrypt the block
            block = decrypt_128(block, key)
            # Save decrypted block by xor-ing with iv
            blocks[index] = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
            # Assign new iv
            xor_iv = next_iv

    elif size == 192:
        # For AES-192
        # Hash password with a salt to a given length of 24 bytes
        key = phash('sha256', password, salt, 1_000_000, 24)
        # Expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 192, reverse=True)

        for index, block in enumerate(blocks):
            # Get the new iv ready
            next_iv = block
            # Decrypt the block by xor-ing with iv
            block = decrypt_192(block, key)
            # Save decrypted block
            blocks[index] = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
            # Assign new iv
            xor_iv = next_iv

    elif size == 256:
        # For AES-256
        # Hash password with a salt to a given length of 32 bytes
        key = phash('sha256', password, salt, 1_000_000, 32)
        # Expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 256, reverse=True)

        for index, block in enumerate(blocks):
            # Get the new iv ready
            next_iv = block
            # Decrypt the block
            block = decrypt_256(block, key)
            # Save decrypted block by xor-ing with iv
            blocks[index] = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
            # Assign new iv
            xor_iv = next_iv

    else:
        raise ValueError(f'Expected size of either 128, 192, or 256 and recieved {size}')

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

    if salt is None:
        # If the salt input is not given, generate a random salt of 64 bytes
        salt = urandom(64)

    if iv is None:
        # If no supplied iv generate one
        iv = urandom(16)
    elif len(iv) != 16:
        # If a supplied iv is not of the correct size
        raise ValueError
    # create list of GF objects to represent the IV
    xor_iv = [GF(i) for i in iv]

    # Convert bytes object to an list of GF objects
    plaintext = [GF(i) for i in plaintext]


    while len(plaintext) % 16 != 0:
        # Pads the size of the list to have blocks of length 16
        plaintext.append(GF(0))

    # Break the plaintext into blocks with 16 elements each
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]


    if size == 128:
        # For AES-128
        # Hash password with a salt to a given length of 16 bytes
        key = phash('sha256', password, salt, 1_000_000, 16)
        # Expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 128)

        for index, block in enumerate(blocks):
            # Get the new iv ready
            new_iv = block

            for i in range(16):
                block[i] = block[i] ^ xor_iv[i]
            # Encrypt each block with the key schedule
            block = encrypt_128(block, key)

            # Save encrypted block
            blocks[index] = block

            for i in range(16):
                # xor each byte of the encrypted block with each byte of the unencrypted block
                # This creates the new iv for the next block
                xor_iv[i] = new_iv[i] ^ block[i]


    elif size == 192:
        # For AES-192
        # Hach password with a salt to a given length of 24 bytes
        key = phash('sha256', password, salt, 1_000_000, 24)
        # expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 192)
        for index, block in enumerate(blocks):
            # Get the new iv ready
            new_iv = block

            for i in range(16):
                block[i] = block[i] ^ xor_iv[i]
            # Encrypt each block with the key schedule
            block = encrypt_192(block, key)

            # Save encrypted block
            blocks[index] = block

            for i in range(16):
                # xor each byte of the encrypted block with each byte of the unencrypted block
                # This creates the new iv for the next block
                xor_iv[i] = new_iv[i] ^ block[i]

    elif size == 256:
        # For AES-256
        # Hach password with a salt to a given length of 32 bytes
        key = phash('sha256', password, salt, 1_000_000, 32)
        # expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 256)
        for index, block in enumerate(blocks):
            # Get the new iv ready
            new_iv = block

            for i in range(16):
                block[i] = block[i] ^ xor_iv[i]

            # Encrypt each block with the key schedule
            block = encrypt_256(block, key)

            # Save encrypted block
            blocks[index] = block

            for i in range(16):
                # xor each byte of the encrypted block with each byte of the unencrypted block
                # This creates the new iv for the next block
                xor_iv[i] = new_iv[i] ^ block[i]

    else:
        raise ValueError(f'Expected size of either 128, 192, or 256 and recieved {size}')

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

    if len(iv) != 16:
        # If a supplied iv is not of the correct size
        raise ValueError

    # create list of GF objects to represent the IV
    xor_iv = [GF(i) for i in iv]

    # Convert bytes object to an list of GF objects
    ciphertext = bytes.fromhex(ciphertext)
    ciphertext = [GF(i) for i in ciphertext]

    while len(ciphertext) % 16 != 0:
        # Pads the size of the list to have blocks of length 16
        ciphertext.append(GF(0))

    # Break the plaintext into blocks with 16 elements each
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]

    if size == 128:
        # For AES-128
        # Hash password with a salt to a given length of 16 bytes
        key = phash('sha256', password, salt, 1_000_000, 16)
        # Expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 128, reverse=True)

        for index, block in enumerate(blocks):

            # Get the new iv ready
            new_iv = block

            # Encrypt each block with the key schedule
            block = decrypt_128(block, key)

            for i in range(16):
                block[i] = block[i] ^ xor_iv[i]

            # Save decrypted block
            blocks[index] = block

            for i in range(16):
                # xor each byte of the encrypted block with each byte of the unencrypted block
                # This creates the new iv for the next block
                xor_iv[i] = new_iv[i] ^ block[i]


    elif size == 192:
        # For AES-192
        # Hach password with a salt to a given length of 24 bytes
        key = phash('sha256', password, salt, 1_000_000, 24)
        # expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 192, reverse=True)
        for index, block in enumerate(blocks):
            # Get the new iv ready
            new_iv = block

            # Encrypt each block with the key schedule
            block = decrypt_192(block, key)

            for i in range(16):
                block[i] = block[i] ^ xor_iv[i]

            # Save decrypted block
            blocks[index] = block

            for i in range(16):
                # xor each byte of the encrypted block with each byte of the unencrypted block
                # This creates the new iv for the next block
                xor_iv[i] = new_iv[i] ^ block[i]

    elif size == 256:
        # For AES-256
        # Hach password with a salt to a given length of 32 bytes
        key = phash('sha256', password, salt, 1_000_000, 32)
        # expand the key to the required size and set it as a repeating iterable
        key = iter_key([GF(i) for i in key], 256, reverse=True)
        for index, block in enumerate(blocks):
            # Get the new iv ready
            new_iv = block

            # Encrypt each block with the key schedule
            block = decrypt_256(block, key)

            for i in range(16):
                block[i] = block[i] ^ xor_iv[i]

            # Save decrypted block
            blocks[index] = block

            for i in range(16):
                # xor each byte of the encrypted block with each byte of the unencrypted block
                # This creates the new iv for the next block
                xor_iv[i] = new_iv[i] ^ block[i]

    else:
        raise ValueError(f'Expected size of either 128, 192, or 256 and recieved {size}')

    out = ''
    for block in blocks:
        for item in block:
            out = out + str(item)
    while out[-2:] == '00':
        out = out[:-2]
    return bytes.fromhex(out)


def cfb_encrypt(plaintext: bytes, password: bytes, size: int, *, iv: bytes = None, salt: bytes = None):
    """
    Close relative of CBC, Cipher Feedback mode turns AES into a
    self-synchronizing stream cipher

    :param plaintext: bytes
    :param password: bytes
    :param size: int (must be either 128, 192, or 256)
    :param iv: bytes (not required but if supplied must be 16 bytes)
    :param salt: bytes (Not required)
    :return: ciphertext: str, iv: bytes, salt: bytes
    """
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

    if salt is None:
        salt = urandom(64)

    if iv is None:
        iv = urandom(16)
    elif len(iv) != 16:
        raise ValueError

    enc_iv = [GF(i) for i in iv]

    plaintext = [GF(i) for i in plaintext]

    while len(plaintext) % 16 != 0:
        plaintext.append(GF(0))

    blocks = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]

    if size == 128:
        key = phash('sha256', password, salt, 1_000_000, 16)
        key = iter_key([GF(i) for i in key], 128)

        for index, block in enumerate(blocks):
            for i, p_item, c_item in zip(range(16), block, encrypt_128(enc_iv, key)):
                block[i] = p_item ^ c_item

            enc_iv = block
            blocks[index] = block




    elif size == 192:
        key = phash('sha256', password, salt, 1_000_000, 24)
        key = iter_key([GF(i) for i in key], 192)
        for index, block in enumerate(blocks):
            for i, p_item, c_item in zip(range(16), block, encrypt_192(enc_iv, key)):
                block[i] = p_item ^ c_item

            enc_iv = block
            blocks[index] = block

    elif size == 256:
        key = phash('sha256', password, salt, 1_000_000, 32)
        key = iter_key([GF(i) for i in key], 256)
        for index, block in enumerate(blocks):
            for i, p_item, c_item in zip(range(16), block, encrypt_256(enc_iv, key)):
                block[i] = p_item ^ c_item

            enc_iv = block
            blocks[index] = block
    else:
        raise ValueError(f'Expected size of either 128, 192, or 256 and recieved {size}')

    out = ''
    for block in blocks:
        for item in block:
            out = out + str(item)

    return out, iv, salt


def cfb_decrypt(ciphertext: str, password: bytes, size: int, iv: bytes, salt: bytes):
    """
        Decrypt ciphertext with the Cipher Feedback mode of operation

        :param ciphertext: str
        :param password: bytes
        :param size: int (must be either 128, 192, or 256)
        :param iv: bytes
        :param salt: bytes
        :return: plaintext: bytes
        :raise: ValueError: if size is not either 128, 192, or 256
        """

    ciphertext = bytes.fromhex(ciphertext)
    ciphertext = [GF(i) for i in ciphertext]
    while len(ciphertext) % 16 != 0:
        ciphertext.append(GF(0))

    while len(iv) < 16:
        iv = iv + b'\x00'
    enc_iv = [GF(i) for i in iv]

    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]

    if size == 128:
        key = phash('sha256', password, salt, 1_000_000, 16)
        key = iter_key([GF(i) for i in key], 128)

        for index, block in enumerate(blocks):

            for i, p_item, c_item in zip(range(16), block, encrypt_128(enc_iv, key)):
                block[i] = p_item ^ c_item

            enc_iv = blocks[index]
            blocks[index] = block



    elif size == 192:
        key = phash('sha256', password, salt, 1_000_000, 24)
        key = iter_key([GF(i) for i in key], 192)

        for index, block in enumerate(blocks):
            for i, p_item, c_item in zip(range(16), block, encrypt_192(enc_iv, key)):
                block[i] = p_item ^ c_item

            enc_iv = blocks[index]
            blocks[index] = block

    elif size == 256:
        key = phash('sha256', password, salt, 1_000_000, 32)
        key = iter_key([GF(i) for i in key], 256)

        for index, block in enumerate(blocks):
            for i, p_item, c_item in zip(range(16), block, encrypt_256(enc_iv, key)):
                block[i] = p_item ^ c_item

            enc_iv = blocks[index]
            blocks[index] = block

    else:
        raise ValueError(f'Expected size of either 128, 192, or 256 and recieved {size}')

    out = ''
    for block in blocks:
        for item in block:
            out = out + str(item)
    while out[-2:] == '00':
        out = out[:-2]
    return bytes.fromhex(out)


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

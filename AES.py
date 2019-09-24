# Import base encryption and decryption functions
# Import pbkdf2_hmac to generage passwords of a fixed size based on inputs
from hashlib import pbkdf2_hmac as phash
# Import urandom to get cryptographically secure random bytes
from os import urandom

from AESCore import encrypt_128, encrypt_192, encrypt_256, decrypt_128, decrypt_192, decrypt_256
# Import Finite(Galois) Field class
# This handles most of the math operated on values
from Field import GF
# Import key generation function
# Generates the key schedule for a given AES size (128, 192, 256) and loops over the schedule repeatedly
# So that the keys can be used for each block of plaintext
from Key import iter_key


# TODO finish commenting code
# TODO Create other block cipher operating modes


def ecb_encrypt(plaintext: bytes, password: bytes, size: int, *, salt: bytes = None):
    '''
    Encrypt plaintext with the Electronic Code Book mode of operation

    :param plaintext: bytes
    :param password: bytes
    :param size: int (must be either 128, 192, or 256)
    :param salt: None (not required)
    :return: ciphertext: string, salt: bytes
    :raise: ValueError: if size is not either 128, 192, or 256
    '''
    if salt is None:
        # If the salt input is not given, generate a random salt of 64 bytes
        salt = urandom(64)

    # Convert the plaintext input into a list of GF instances
    plaintext = [GF(i) for i in plaintext]

    while len(plaintext) % 16 != 0:
        # Pads the size of the list to have blocks of length 16
        plaintext.append(GF(0))

    # Separate each GF instance into a block of size 16
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]

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


def ecb_decrypt(ciphertext: str, password: bytes, salt: bytes, size: int):
    '''
    Decrypt ciphertext with the Electronic Code Book mode of operation

    :param ciphertext: str
    :param password: bytes
    :param salt: bytes
    :param size: int (must be either 128, 192, or 256)
    :return: plaintext: bytes
    :raise: ValueError: if size is not either 128, 192, or 256
    '''
    # Convert a string with hex values to a bytes object
    ciphertext = bytes.fromhex(ciphertext)
    # Convert the bytes object ciphertext to an array of GF instances
    ciphertext = [GF(i) for i in ciphertext]

    # Make sure the ciphertext can fit in blocks of size 16
    # This should never run for any valid given input
    while len(ciphertext) % 16 != 0:
        ciphertext.append(GF(0))

    # Break down the ciphertext into blocks of size 16
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

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


def cbc_encrypt(plaintext: bytes, password: bytes, size: int, *, iv: bytes=None, salt: bytes=None):
    '''
    Encrypt plaintext with the Cipher Block Chaining mode of operation

    :param plaintext: bytes
    :param password: bytes
    :param size: int (must be either 128, 192, or 256)
    :param iv: None (not required)
    :param salt: None (not required
    :return: ciphertext: string, iv: bytes, salt: bytes
    :raise: ValueError: if size is not either 128, 192, or 256
    '''

    if salt is None:
        salt = urandom(64)

    if iv is None:
        iv = urandom(16)
    else:
        iv = iv + urandom(16-len(iv))

    xor_iv = [GF(i) for i in iv]

    plaintext = [GF(i) for i in plaintext]

    while len(plaintext) % 16 != 0:
        plaintext.append(GF(0))

    blocks = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]

    if size == 128:
        key = phash('sha256', password, salt, 1_000_000, 16)
        key = iter_key([GF(i) for i in key], 128)

        for index, block in enumerate(blocks):
            block = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
            xor_iv = encrypt_128(block, key)
            blocks[index] = xor_iv

    elif size == 192:
        key = phash('sha256', password, salt, 1_000_000, 24)
        key = iter_key([GF(i) for i in key], 192)
        for index, block in enumerate(blocks):
            block = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
            xor_iv = encrypt_192(block, key)
            blocks[index] = xor_iv

    elif size == 256:
        key = phash('sha256', password, salt, 1_000_000, 32)
        key = iter_key([GF(i) for i in key], 256)
        for index, block in enumerate(blocks):
            block = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
            xor_iv = encrypt_256(block, key)
            blocks[index] = xor_iv
    else:
        raise ValueError(f'Expected size of either 128, 192, or 256 and recieved {size}')

    out = ''
    for block in blocks:
        for item in block:
            out = out + str(item)

    return out, iv, salt


def cbc_decrypt(ciphertext: str, password: bytes, iv: bytes, salt: bytes, size: int):
    '''
    Decrypt ciphertext with the Cipher Block Chaining mode of operation

    :param ciphertext: str
    :param password: bytes
    :param iv: bytes
    :param salt: bytes
    :param size: int (must be either 128, 192, or 256)
    :return: plaintext: bytes
    :raise: ValueError: if size is not either 128, 192, or 256
    '''
    ciphertext = bytes.fromhex(ciphertext)
    ciphertext = [GF(i) for i in ciphertext]
    while len(ciphertext) % 16 != 0:
        ciphertext.append(GF(0))

    while len(iv) < 16:
        iv = iv + b'\x00'
    xor_iv = [GF(i) for i in iv]

    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    if size == 128:
        key = phash('sha256', password, salt, 1_000_000, 16)
        key = iter_key([GF(i) for i in key], 128, reverse=True)

        for index, block in enumerate(blocks):
            next_iv = block
            block = decrypt_128(block, key)
            blocks[index] = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
            xor_iv = next_iv

    elif size == 192:
        key = phash('sha256', password, salt, 1_000_000, 24)
        key = iter_key([GF(i) for i in key], 192, reverse=True)

        for index, block in enumerate(blocks):
            next_iv = block
            block = decrypt_192(block, key)
            blocks[index] = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
            xor_iv = next_iv

    elif size == 256:
        key = phash('sha256', password, salt, 1_000_000, 32)
        key = iter_key([GF(i) for i in key], 256, reverse=True)

        for index, block in enumerate(blocks):
            next_iv = block
            block = decrypt_256(block, key)
            blocks[index] = [b_item ^ iv_item for b_item, iv_item in zip(block, xor_iv)]
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



if __name__ == '__main__':
    plain = b'test'
    pwd = b'password'
    size = 128
    salt = None
    iv = None

    ciphertext, iv, salt = cbc_encrypt(plain, pwd, size, iv=iv, salt=salt)



    print(f'Plaintext:   {plain}')
    print(f'Password:    {pwd}')
    print(f'Size:        {size}')
    print(f'IV:          {iv}')
    print(f'Salt:        {salt}')
    print(f'Ciphertext:  {ciphertext}')

    new_plain = cbc_decrypt(ciphertext, pwd, iv, salt, size)

    print(f'Decrypted:   {new_plain}')












from Field import GF, sbox, modulus

# TODO comment code
# TODO create docstrings
# TODO format according to PEP 8

def expand_128(key):
    i = 1

    while len(key) < 176:
        temp = key[-4:]
        if len(key) % 16 == 0:
            schedule_core(temp, i)
            i = i + 1
        for item in temp:
            key.append(item ^ key[-16])
    return key

def expand_192(key):
    i = 1
    while len(key) < 208:
        temp = key[-4:]
        if len(key) % 24 == 0:
            schedule_core(temp, i)
            i = i + 1
        for item in temp:
            key.append(item ^ key[-24])

    return key

def expand_256(key):
    i = 1
    while len(key) < 240:
        temp = key[-4:]

        if len(key) % 32 == 0:
            schedule_core(temp, i)
            i = i + 1

        if len(key) % 32 == 16:
            for index, item in enumerate(temp):
                temp[index] = sbox(item)

        for item in temp:
            key.append(item ^ key[-32])

    return key

def schedule_core(temp, i):
    def rotate(arr):
        arr.append(arr.pop(0))
        return arr
    def rcon():
        return GF(1 << (i-1)) % modulus

    temp = rotate(temp)
    for index, item in enumerate(temp):
        temp[index] = sbox(item)
    temp[0] = temp[0] ^ rcon()
    return temp

def iter_key(key, size, *, reverse=False):
    if size == 128:
        key = expand_128(key)
    elif size == 192:
        key = expand_192(key)
    elif size == 256:
        key = expand_256(key)
    else:
        return
    keys = list()
    for i in range(0, len(key), 16):
        keys.append(key[i:i+16])

    if reverse:
        keys.reverse()

    while True:
        for key in keys:
            yield key

